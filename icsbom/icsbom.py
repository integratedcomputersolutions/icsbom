# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Ics inc.
# SPDX-FileContributor: Chris Rizzitello <crizzitello@ics.com>
# SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>
# SPDX-FileContributor: Qin Zhang <qzhang@ics.com>
# SPDX-FileContributor: Gerardo Stola <gstola@ics.com>

import logging
import argparse
import time
import json
import rlcompleter
import readline

import rich.console
from rich.style import Style
from rich.color import Color
from rich.text import Text
from rich import print, print_json
from rich_argparse import RawTextRichHelpFormatter

from decimal import Decimal
from pathlib import Path

from spdx_tools.spdx.model import Document as SPDXDocument

from ics_sbom_libs.common import logging_setup, console_output
from ics_sbom_libs.common.vulnerability import vulnerability_styles
from ics_sbom_libs.cve_fetch.vulnerabilitydatabase import VulnerabilityDatabase
from ics_sbom_libs.sbom_import.parse_anything import FilteredParser
from ics_sbom_libs.cve_match.matchresult import MatchResult
from ics_sbom_libs.cve_match.cvematcher import CveMatcher, MatchTableOutput
from spdx_tools.spdx.model.actor import Actor as SpdxActor
from license_expression import LicenseExpression

from packageurl import PackageURL
from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import XsUri

try:
    # support for cyclonedx 7.x
    from cyclonedx.model.contact import OrganizationalEntity
except ImportError:
    # drop back to cyclonedx 6.x
    from cyclonedx.model import OrganizationalEntity

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityRating,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyclonedx.output.json import Json as JsonOutputter

script_name = Path(__file__).stem

# Setup Args
parser = argparse.ArgumentParser(
    prog=script_name, description="process spdx sbom files", formatter_class=RawTextRichHelpFormatter
)
logging_setup.setup_log_arg(parser)
VulnerabilityDatabase.setup_args(parser)
parser.add_argument("--update-db-only", action="store_true", help="Updates the local NVD database cache only.")
parser.add_argument("-f", "--file", type=Path, help="Input File")
parser.add_argument("-o", metavar="OutFile", type=str, help="Output File, [*.txt, *.csv, *.html, *.json.vex]")
parser.add_argument(
    "-i", "--interactive", action="store_true", help="run interactively after matching to view cve data"
)
parser.add_argument("-s", "--skip-db-update", action="store_true", help="Skip database update")
parser.add_argument(
    "-l",
    "--lookup",
    action="append",
    help="""Lookup packages using key/value pair descriptions with the following keys: 'vendor',\
'product', 'version'. Each lookup description must have 'product' key/value pair.
Examples:
\t-l 'product=libcurl'
\t-l 'vendor=curl,product=libcurl'
\t-l 'product=libcurl,version=8.11'
\t-l 'vendor=curl,product=libcurl,version=8.11'""",
)

FilteredParser.setup_args(parser)
args = parser.parse_args()

logging.basicConfig(level=logging_setup.handle_log_arg(args), force=True)
log = logging.getLogger(script_name)


def create_results_overview(input_sbom_file: Path, cve_matcher: CveMatcher, processing_time: float):
    overview = [console_output.format_string("{:<25}".format("SBoM File Scanned"), f"{input_sbom_file}")]
    overview += [console_output.format_string("{:<25}".format("Time of last scan"), f"{cve_matcher.scanTime}")]
    overview += [console_output.format_string("{:<25}".format("Scanning Time"), f"{processing_time:.3f} Seconds")]
    overview += [
        console_output.format_string("{:<25}".format("Packages Scanned"), f"{cve_matcher.total_package_count}")
    ]
    overview += [
        console_output.format_string("{:<25}".format("Packages With Issues"), f"{cve_matcher.dirty_package_count}")
    ]
    overview += [
        console_output.format_string("{:<25}".format("Packages Without Issues"), f"{cve_matcher.clean_package_count}")
    ]
    overview += [console_output.format_string("{:<25}".format("CVEs"), "")]
    overview += [console_output.format_string("Total", f"{cve_matcher.total_cve_count}", left_justify=False)]

    vuln_info = cve_matcher.get_severity_info()
    for severity in list(vuln_info.keys())[1:]:
        overview += [
            console_output.format_string(
                f"{severity}", vuln_info[severity], vulnerability_styles[severity].style, left_justify=False
            )
        ]

    return Text("\n").join(overview)


def print_results(input_sbom_file: Path, cve_matcher: CveMatcher, processing_time: float):
    print(cve_matcher.create_match_table(table_output=MatchTableOutput.CvesOnly))

    print(create_results_overview(input_sbom_file, cve_matcher, processing_time))


def write_text(output_file: Path, input_sbom_file: Path, cve_matcher: CveMatcher, processing_time: float):
    with open(output_file, "w") as f:
        output = rich.console.Console(file=f, width=120)
        output.print("# IcsBom Results\n")
        output.print(create_results_overview(input_sbom_file, cve_matcher, processing_time))
        output.print("\n## Packages With Issues\n")
        output.print(cve_matcher.create_match_table(table_output=MatchTableOutput.CvesOnly))
        output.print("\n## Packages Without Issues\n")
        output.print(cve_matcher.create_match_table(table_output=MatchTableOutput.WithoutCvesOnly))

    print(f"Wrote To file {output_file}")


def write_html(output_file: Path, input_sbom_file: Path, cve_matcher: CveMatcher, processing_time: float):
    null_output = open("/dev/null", "w")

    captured_str = ""
    with rich.console.Console(file=null_output, width=120, force_terminal=True) as capture_console:
        with capture_console.capture() as capture:
            capture_console.print("[b][u]IcsBom Results[/]\n")
            capture_console.print(create_results_overview(input_sbom_file, cve_matcher, processing_time))
            capture_console.print("\n[b]Packages With Issues[/]\n")
            capture_console.print(cve_matcher.create_match_table(table_output=MatchTableOutput.CvesOnly))
            capture_console.print("\n[b]Packages Without Issues[/]\n")
            capture_console.print(cve_matcher.create_match_table(table_output=MatchTableOutput.WithoutCvesOnly))

        captured_str = capture.get()

    record_console = rich.console.Console(file=null_output, width=120, record=True)
    record_console.print(Text().from_ansi(captured_str))
    html_str = record_console.export_html(inline_styles=True)

    with open(output_file, "w") as f:
        f.write(html_str)

    print(f"Wrote To file {output_file}")


def write_csv(output_file: Path, cve_matcher: CveMatcher):
    f = open(output_file, "w")
    for result in cve_matcher.result_list:
        f.write(f"{result.csvify}\n")
    f.close()
    print(f"Wrote To file {output_file}")


def write_results(input_sbom_file: Path, cve_matcher: CveMatcher, processing_time: float, sbom: Bom):
    output_file = Path(args.o)
    if not output_file.parent.exists():
        Path.mkdir(output_file.parent)

    if output_file.name.endswith(".txt"):
        write_text(output_file, input_sbom_file, cve_matcher, processing_time)
    elif output_file.name.endswith(".csv"):
        write_csv(output_file, cve_matcher)
    elif output_file.name.endswith(".htm") or output_file.name.endswith(".html"):
        write_html(output_file, input_sbom_file, cve_matcher, processing_time)
    elif output_file.name.endswith(".json.vex"):
        write_vex(output_file, sbom)
    else:
        print("Can't write type output must be *.txt, *.csv, *.html, or *.json.vex")


def make_vex(sbom, matcher):
    """
    Derived from https://cyclonedx-python-library.readthedocs.io/en/latest/examples.html
    """
    lc_factory = LicenseFactory()
    db = VulnerabilityDatabase()
    db.process_args(args)

    # region build the BOM
    bom = Bom()
    bom.metadata.component = root_component = Component(
        name=sbom.creation_info.name if sbom else "simplified-bom",
        type=ComponentType.APPLICATION,
        licenses=[lc_factory.make_from_string("MIT")],
        bom_ref=sbom.creation_info.name if sbom else "simplified-bom",
    )

    for result in matcher.result_list:
        # Need both results with and without CVEs
        component_name = result.name
        component_version = result.version

        component: Component
        if sbom:
            package = [sbom_package for sbom_package in sbom.packages if sbom_package.name == component_name][0]

            component = Component(
                type=ComponentType.LIBRARY,
                name=package.name,
                version=package.version,
                bom_ref=component_name + ("@" + component_version if component_version else ""),
                purl=PackageURL("generic", "ics", component_name, component_version),
            )

            if package.license_declared is not None and isinstance(package.license_declared, LicenseExpression):
                component.licenses = [lc_factory.make_from_string(package.license_declared.get_literals()[0].key)]

            if isinstance(package.supplier, SpdxActor):
                component.supplier = OrganizationalEntity(
                    name=package.supplier.name, contacts=[package.supplier.email] if package.supplier.email else []
                )
            if isinstance(package.copyright_text, str):
                component.copyright = package.copyright_text

            if len(result.cpe_list):
                component.cpe = result.cpe_list[0]

        else:
            component = Component(
                type=ComponentType.LIBRARY,
                name=component_name,
                group="ics",
                version=component_version,
                licenses=[lc_factory.make_from_string("(c) 2024 ICS inc.")],
                supplier=OrganizationalEntity(name="ICS Inc", urls=[XsUri("https://www.ics.com")]),
                bom_ref=component_name + ("@" + component_version if component_version else ""),
                purl=PackageURL("generic", "ics", component_name, component_version),
            )
        bom.components.add(component)
        bom.register_dependency(root_component, [component])

        if not result.cve_list:
            continue

        # print(f"component: {result.name} ({result.version}), Open Cve's {result.cve_list}")
        for cve in result.cve_list:

            vul = Vulnerability()
            vul.id = cve.cve_number
            vul.source = VulnerabilitySource(name=cve.source)
            vul.cwes = [int(cwe.split("-")[1]) for cwe in cve.cwes if isinstance(cwe, str) and cwe.startswith("CWE")]
            vul.description = cve.description
            vul.updated = cve.last_modified
            vul.ratings = [
                VulnerabilityRating(
                    vector=cve.cvss_vector,
                    score=Decimal.from_float(cve.score),
                    severity=VulnerabilitySeverity(cve.severity.lower()),
                    method=VulnerabilityScoreSource.get_from_vector(cve.cvss_vector),
                )
            ]

            vul.affects.add(BomTarget(ref=component.bom_ref.value, versions=None))
            bom.vulnerabilities.add(vul)

    return bom


def write_vex(output_filename: Path, sbom: Bom):
    # endregion build the BOM
    my_json_outputter: "JsonOutputter" = JsonV1Dot5(sbom)
    serialized_json = my_json_outputter.output_as_string(indent=2)
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_5)
    try:
        validation_errors = my_json_validator.validate_str(serialized_json)
        if validation_errors:
            log.error(f"JSON invalid -- ValidationError: {repr(validation_errors)}")
            return
        # print(serialized_json)
        with open(output_filename, "w") as f:
            f.write(serialized_json)
    except MissingOptionalDependencyException as error:
        log.error(f"JSON-validation was skipped due to {error}")


class ReviewCompleter(rlcompleter.Completer):
    def __init__(self, keywords: list, secondary_lists: dict | None = None):
        super(ReviewCompleter, self).__init__()
        self._text = ""
        self._completions: list = []

        if not keywords:
            raise ValueError("No keyword list given")

        self._completion_list = keywords
        self._secondary_completion_list: dict | None = secondary_lists

    def _check_completions(self, text):
        if text != self._text:
            self._text = text

            text_split = self._text.split(" ")

            first_check = text_split[0].strip()
            self._completions = [item for item in self._completion_list if item.startswith(first_check)]

            if self._completions and self._secondary_completion_list and self._completions[0] == first_check:
                if first_check in self._secondary_completion_list.keys():
                    self._completions = [
                        f"{first_check} {item}"
                        for item in self._secondary_completion_list[first_check]
                        if item.startswith(text_split[1]) or text_split[1] == ""
                    ]

    def complete(self, text, state):
        self._check_completions(text)

        if self._completions and len(self._completions) > state:
            return self._completions[state]

        return None


def review(input_sbom_file: Path, input_sbom, match_results, output_sbom, parse_time):

    def help_mode_str(mode: str, arg: str = "", brief: str = ""):
        help_str = Text.assemble((mode, "bold cyan"))
        help_str.pad_left(2, " ")

        if arg:
            arg_str = Text.assemble((arg, "i green"))
            arg_str = Text.assemble((" [", "green"), arg_str, ("] ", "green"))
            help_str += arg_str

        help_str.pad_right(35 - help_str.cell_len, " ")
        help_str += Text.assemble(("  --  ", "yellow"), f"{brief}\n")

        return help_str

    def help_sub_mode_str(mode: str, brief: str = ""):
        help_str = Text.assemble((mode, "bold red"))
        help_str.pad_left(4, " ")
        help_str.pad_right(37 - help_str.cell_len, " ")
        help_str += Text.assemble(("  --  ", "yellow"), f"{brief}\n")
        return help_str

    db = VulnerabilityDatabase()
    db.process_args(args)

    help_string = Text.assemble(("Interactive Mode - options are\n", Style(color=Color.from_rgb(255.0, 165.0, 0.0))))
    help_string += help_mode_str("view", "package name", "Shows brief information on package if available")
    help_string += help_mode_str("review", "vuln package name", "Prints each cve for a the package")

    help_sub_string = help_sub_mode_str("n", "Next cve")
    help_sub_string += help_sub_mode_str("p", "Previous cve")
    help_sub_string += help_sub_mode_str("q", "Quit the review")
    help_sub_string += help_sub_mode_str("c", "Retrieve the full CVE information from the NVD database")
    help_sub_string += help_sub_mode_str("e", "Export the full CVE information from the NVD database")
    help_sub_string += help_sub_mode_str("h/?", "Reshow this help")

    help_string += help_sub_string
    help_string += help_mode_str("search_cpes", "package name", brief="Queries all the CPEs for the given package.")
    help_string += help_mode_str("write_csv", "output filename", brief="Writes the match data to a CSV file.")
    help_string += help_mode_str("write_txt", "output filename", brief="Writes the match data to a TXT file.")
    help_string += help_mode_str("write_html", "output filename", brief="Writes the match data to a HTML file.")
    help_string += help_mode_str("write_vex", "vex filename", brief="Writes the match data to a HTML file.")
    help_string += help_mode_str("list", brief="Reprints the results")
    help_string += help_mode_str("help", brief="Reprints this help")
    help_string += help_mode_str("exit", brief="Exits the application")

    def print_cve(cve):
        if not cve:
            return

        print(cve.rich())

    def print_match_result(package: MatchResult):
        print(console_output.format_string("Name", f"{package.name}"))
        print(console_output.format_string("Version", f"{package.version}"))
        console_output.print_list("CPEs", package.cpe_list)
        print(console_output.format_string("CVE Counts"))
        print(console_output.format_string("Total", f"{len(package.cve_list)}", left_justify=False))
        vuln_info = package.get_severity_info()

        for severity in vuln_info.keys():
            print(
                console_output.format_string(
                    f"{severity}", vuln_info[severity], vulnerability_styles[severity].style, left_justify=False
                )
            )

    def print_cpe_search_result(package_name: str):
        print(console_output.format_string("Name", f"{package_name}"))
        cpe_names = db.query_cpe_dictionary(package_name)
        if cpe_names:
            console_output.print_list("CPEs", cpe_names, with_wrap=(len(cpe_names) > 12))
        else:
            print(console_output.format_string("CPEs:", "Package couldn't be found."))

    def quit_review():
        main.reviewing = -1
        main.previous = -1
        main.ignore = False
        main.process_stack.pop()

    print(help_string)
    package_list = [pkg.name for pkg in match_results.result_list]
    vulnerable_package_list = [pkg.name for pkg in match_results.result_list if pkg.cve_list]

    package_completions = ReviewCompleter(
        ["view", "review", "search_cpes", "write_csv", "write_txt", "write_html", "write_vex", "list", "exit"],
        {"view": package_list, "review": vulnerable_package_list},
    )

    readline.set_completer(package_completions.complete)
    readline.set_completer_delims("")
    readline.parse_and_bind("tab: complete")

    review_package = None
    main.reviewing = -1
    main.ignore = False
    main.previous = -1
    main.process_stack = [script_name, input_sbom_file.stem]
    while True:
        command = input("/".join(main.process_stack) + " > ")
        command.strip()

        if command.lower().startswith("review"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2:
                if main.reviewing >= 0:
                    print(f"Already reviewing [bold cyan]{review_package.name}[/]")
                    continue
                else:
                    print(
                        "[bold red]Invalid command usage[/]: "
                        "[lightblue]review[/] [green][[i]vuln package name[/i]][/green]"
                    )
                    continue

            elif cmd_args[1] in vulnerable_package_list:
                pkg_index = package_list.index(cmd_args[1])
                review_package = match_results.result_list[pkg_index]
                if main.reviewing >= 0:
                    main.process_stack.pop()

                main.reviewing = 0
                main.process_stack.append(f"{review_package.name} ({review_package.version})")
                main.ignore = False

        elif command.lower().startswith("view"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2 and main.reviewing == -1:
                print("[red][b]Invalid command usage[/]: [lightblue]view[/] [green][[i]package name[/i]][/green]")
                continue

            elif len(cmd_args) == 1 and main.reviewing >= 0:
                print_match_result(review_package)
                continue

            elif cmd_args[1] in package_list:
                pkg_index = package_list.index(cmd_args[1])
                print_match_result(match_results.result_list[pkg_index])
                continue

        elif command.lower().startswith("search_cpes"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2 and main.reviewing == -1:
                print(
                    "[red][b]Invalid command usage[/b][/red]: "
                    "[lightblue]search_cpes[/lightblue] [green][[i]package name[/i]][/green]"
                )
                continue

            elif len(cmd_args) == 1 and main.reviewing >= 0:
                print_cpe_search_result(review_package.name)
                continue

            elif len(cmd_args) == 2:
                print_cpe_search_result(cmd_args[1])
                continue

        elif command.lower().startswith("write_csv"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2:
                print(
                    "[red][b]Invalid command usage[/]: "
                    "[lightblue]write_csv[/] [green]/[[i]output filename[/i]][/green]"
                )
                continue

            else:
                try:
                    write_csv(Path(cmd_args[1]), match_results)
                except OSError as e:
                    print(f"[red][b]ERROR:[/b] Couldn't write the file.[/]\n{e.strerror}")
                continue

        elif command.lower().startswith("write_txt"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2:
                print(
                    "[red][b]Invalid command usage[/]: "
                    "[lightblue]write_txt[/] [green]/[[i]output filename[/i]][/green]"
                )
                continue

            else:
                try:
                    write_text(
                        Path(cmd_args[1]),
                        input_sbom_file=input_sbom_file,
                        cve_matcher=match_results,
                        processing_time=parse_time,
                    )
                except OSError as e:
                    print(f"[red][b]ERROR:[/b] Couldn't write the file.[/]\n{e.strerror}")
                continue

        elif command.lower().startswith("write_html"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2:
                print(
                    "[red][b]Invalid command usage[/]: "
                    "[lightblue]write_html[/] [green]/[[i]output filename[/i]][/green]"
                )
                continue

            else:
                try:
                    write_html(
                        Path(cmd_args[1]),
                        input_sbom_file=input_sbom_file,
                        cve_matcher=match_results,
                        processing_time=parse_time,
                    )
                except OSError as e:
                    print(f"[red][b]ERROR:[/b] Couldn't write the file.[/]\n{e.strerror}")
                continue

        elif command.lower().startswith("write_vex"):
            cmd_args = command.split(" ")
            if len(cmd_args) != 2:
                print(
                    "[red][b]Invalid command usage[/]: "
                    "[lightblue]write_vex[/] [green]/[[i]output filename[/i]][/green]"
                )
                continue

            else:
                try:
                    write_vex(Path(cmd_args[1]), output_sbom)
                except OSError as e:
                    print(f"[red][b]ERROR:[/b] Couldn't write the file.[/]\n{e.strerror}")
                continue

        elif command.lower() == "list":
            print_results(input_sbom_file, match_results, parse_time)
            continue

        elif command.lower() == "help":
            print(help_string)

        elif command.lower() == "exit":
            print("Goodbye")
            break

        if main.reviewing >= 0:
            if command.lower() == "n":
                main.previous = main.reviewing
                main.reviewing = min(main.reviewing + 1, len(review_package.cve_list) - 1)
                main.ignore = main.previous == main.reviewing

            elif command.lower() == "p":
                main.previous = main.reviewing
                main.reviewing = max(main.reviewing - 1, 0)
                main.ignore = main.previous == main.reviewing

            elif command.lower() == "q":
                quit_review()
                continue

            elif command.lower() == "c":
                retrieval = db.query_cve_from_nvd(review_package.cve_list[main.reviewing].cve_number)
                print_json(retrieval)
                continue

            elif command.lower() == "e":
                retrieval = db.query_cve_from_nvd(review_package.cve_list[main.reviewing].cve_number)
                with open(
                    Path().absolute() / f"{review_package.name}-{review_package.cve_list[main.reviewing]}.json",
                    "w",
                    encoding="utf-8",
                ) as f:
                    print(f"Exporting {review_package.cve_list[main.reviewing].cve_number} to {f.name}.")

                    json.dump(json.loads(retrieval), f, indent=2)
                continue

            elif command.lower() == "?" or command.lower() == "h":
                print(help_sub_string)
                main.ignore = True

            if not main.ignore:
                print_cve(review_package.cve_list[main.reviewing])

            if main.previous == -1:
                main.ignore = True


def main():
    print("IcsBom", flush=True)
    db = VulnerabilityDatabase()
    db.process_args(args)
    if not args.skip_db_update:
        db.create_database()

    if args.update_db_only:
        return

    if not args.file and len(args.lookup) == 0:
        print("[red][b]ERROR:[/b] missing the input file `-f` or lookups `-l`.[/]", flush=True)
        parser.print_help()
        return -1

    start_time = time.time()
    filtered_parser = FilteredParser()
    filtered_parser.process_args(args)

    imported_sbom: SPDXDocument
    matcher = CveMatcher(db_path=db.db_path)
    if args.file:
        print(f"Parsing File {args.file}", flush=True)
        imported_sbom = filtered_parser.parse(args.file)
        matcher.spdx_document = imported_sbom

    elif len(args.lookup) > 0:
        print("Looking up packages:")
        for package_description in args.lookup:
            package_description_parts = {"product": None, "version": None, "vendor": None}
            package_description = package_description.strip("'").strip('"')
            package_parts = package_description.split(",")
            for part in package_parts:
                key_value = part.split("=")
                if key_value[0].lower() in package_description_parts:
                    package_description_parts[key_value[0].lower()] = key_value[1]

            matcher.add_package(
                package_description_parts["product"],
                package_description_parts["version"],
                package_description_parts["vendor"],
            )

        imported_sbom = matcher.spdx_document

    else:
        print("[red][b]ERROR:[/b] Really missing any inputs.[/]", flush=True)

    try:
        matcher.process()
    except RuntimeError as err:
        print(f"[red][b]ERROR:[/b]{err.args[0]}[/red]")
        exit(1)

    finish_time = time.time()
    parse_time = finish_time - start_time

    vex_sbom = make_vex(imported_sbom, matcher)

    if not args.o:
        print_results(args.file, matcher, parse_time)
    else:
        write_results(args.file, matcher, parse_time, vex_sbom)

    if args.interactive:
        review(
            input_sbom_file=args.file,
            input_sbom=imported_sbom,
            match_results=matcher,
            output_sbom=vex_sbom,
            parse_time=parse_time,
        )


if __name__ == "__main__":
    main()
