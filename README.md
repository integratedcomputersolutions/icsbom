<!--
   SPDX-FileCopyrightText: 2024 ICS inc.
   SPDX-License-Identifier: CC-BY-SA-4.0
-->

ICSbom ![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/integratedcomputersolutions/icsbom/build.yml) [![REUSE status](https://api.reuse.software/badge/github.com/integratedcomputersolutions/icsbom)](https://api.reuse.software/info/github.com/integratedcomputersolutions/icsbom) [![PyPI - Version](https://img.shields.io/pypi/v/icsbom)](https://pypi.org/project/icsbom/) ![PyPI - Downloads](https://img.shields.io/pypi/dm/icsbom)
===
This application downloads data from the nvd api and creates a local `Vulnerability Database`.
If the database already exists it will be updated with changes since your last update.
It then uses that data to check the provided sbom file and give you a Vulnerability report. This tool is used by [SBOMGuard](https://sbomguard.com) ICS' open source, web-based cloud service.

## Usage
 icsbom [OPTIONS] INPUTFILE

### Options
`-h` Help
 - Shows the Application Help

`--log` set the log level of the application 
 - Valid levels: `NOTSET`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
 - Default value: `WARNING`

`--cache_dir` the path where the application will write 
 - Any path you can Read and Write to is valid 
 - Default: `$HOME/.cache/icsbom`

`--api_key` API_KEY
 - Use the API_KEY to access the NVD Api
 - A Key is NOT required, providing one allows more api queries per second
 - If the file `$CACHE_DIR/api_key.txt` exists its contents will be used as the api key

`--save_key`Save the api key used by the `api_key` option
   - Writes the used api key to `api_key.txt` in the Cache Directory

`--db_file` filename for the database
 - The filename used will be written into the cache directory
 - Default: `nvd_v#.db` Where # is the revision of the database format.

`-o` Output file to write
   - File format depending on extention of the output file
   - Valid extentions are *.txt, *.csv, *.html, *.json.vex

`-i`, `--interactive` Enter interactive mode after matching

`-s`, `--skip-db-update`
 - This option will skip the database update and go right to scanning the file using the existing database.

`--filter_file` `FILTER_FILE`
 - Override the builtin filters with the contents of `FILTER_FILE`
 - `FILTER_FILE` must be a json file

 `--write_filters` `FILTER_OUT`
 - Write the default filters to a file
 - `FILTER_OUT` should end in .json
 - Useful to adjust the filters for your projects needs.

`-t` TAR_DIR_PATTERN
 - Used when the input file is a tarball crated by a yocto build process
 - process the contents of the subdir matching the TAR_DIR_PATTERN
 - Valid Patterns: recipies, packages
 - Default: packages

`INPUTFILE` The input file
 - File can be a sbom or tarball

# Requirements
 requires [ics_sbom_libs](https://github.com/integratedcomputersolutions/ics-sbom-libs)
