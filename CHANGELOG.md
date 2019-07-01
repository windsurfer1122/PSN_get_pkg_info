# PSN_get_pkg_info.py - Changelog

## 2019.06.30.post1
* FIX: Still display determined data if reading/decryption of items fail

## 2019.06.30
* NEW: Added support for PS3/PSX/PSP/PSV/PSM debug packages
* NEW: Added dependency to Python module fastxor for debug packages
* NEW: Added region/language check to `--unknown` option
* FIX: Avoid execution stall by adding timeout of 60 seconds to all network calls
* FIX: Avoid writing out of extraction directory, e.g. special homebrew packages
* FIX: Use ISO date format
* FIX: Updated PS4 firmware version for http headers

## 2019.06.09
* NEW: Enhanced analysis output for PS4 packages (key index, name table offset if name for meta entry came from name table)
* NEW: PS4 Update URL

## 2019.05.28
* FIX: Correctly list PS4 meta table entries

## 2019.05.26
* NEW: Added `--pathpattern` filter via regex to `--content` extraction and also `--nosubdirs` to extract all files directly to the content dir
* NEW: Enhanced PARAM.SFO display to display hex values in their correct length
* FIX: Correctly use quiet setting when extracting files

## 2019.04.30
* NEW: Detect PS3 Unlock DLC without titles and give technical title
* NEW: Allow fake package source "dummy". Can be used if only handling zrifs.
* FIX: Update firmware versions for http headers

## 2019.03.10.post2
* NEW: Handle HTTP errors much better

## 2019.03.10.post1
* FIX: Allow redirections when accessing HTTP headers, otherwise causes error of mismatching sizes
* FIX: Formatting issue on error message of mismatching sizes

## 2019.03.10
* NEW: Support for multi-part packages (PS3 via XML, PS4 via JSON)
* NEW: Parse PARAM.SFO item inside package, even if a PARAM.SFO is available in the unencrypted part
* NEW: Parse PBP inside package
* NEW: Determine required firmware versions for all platforms referenced inside the package and/or PBP
* NEW: Added PS3 content type detection of 0x12 (PS2 Classics), 0x13, 0x14
* NEW: Added some PS4 content type detection
* NEW: Display hex values in their correct length
* NEW: Updated PS4 HTTP headers to 6.50
* NEW: Parse PKG3 meta data 0x0A
* NEW: Read first 128 KiB of each package to reduce HTTP/S request while keeping download time short (size fits 99% of known PKG3 package headers)
* NEW: Added item flags to output format 99 for detailed analysis
* NEW: Extraction: create all directories before extracting any file, added item index to extraction messages
* FIX: Content ID in header fields is 48 bytes long and not 36 (derived from PSM extraction)
* FIX: Correctly distinguish between PSP DLCs and updates
* FIX: Determine PSP game versions and required firmware version from PBP PARAM.SFO
* FIX: Return source from arguments in JSON output (e.g. XML/JSON URL)
* FIX: Corrected extraction messages for PSM additional special files
* FIX: Updated and corrected some content id recognition
* FIX: Fine-tuned messages for remaining data and unaligned access
* FIX: avoid leading spaces on metadata output (-f 99)
* INTERNAL: Calculate tail size and do not use and support negative sizes for package read
* INTERNAL: Functionality to get only the beginning of an item, which can be later re-used for extractions (data only read once)
* INTERNAL: Use bytes for magic
* INTERNAL: Pass-through SEP to sub-structure output
* INTERNAL: Use more constants to avoid typos
* INTERNAL: Rename several variables to better fit their usage
* INTERNAL: Items Info changes: rename function and variables, handle encrypted offset > 0 correctly, single bytearray for Items Info (entries plus names), use Items Info size from meta data if available, moved existing checks into function, added new checks, placed data about Items Info in own results dictionary, removed unneccesary internal data from JSON output
* INTERNAL: Adopted code further to coding style
* PRELIMINARY: Added pkg_dec's "makedir=id" `--content` extraction functionality for PS3/PSX/PSP/PSV/PSM packages
* PRELIMINARY: Added pkg2zip's `--ux0` extraction functionality for PSX/PSV/PSM packages (PSP still missing)
* PRELIMINARY: First part of PSP extraction, EBOOT.PBP recognition and analysis for PSP/PSX packages.
* PRELIMINARY: Added zrif support to extraction functionality for PSV/PSM packages
* PRELIMINARY: Output format 50 for displaying all RIF data, so that multiple zrifs for the same content id are all displayed
* PRELIMINARY: Option `--quiet` to suppress extraction messages
* PRELIMINARY: Moved all extraction code in one block after data determination and output, so that analysis output is present even if any extraction fails
* PRELIMINARY: Added checks for extraction targets to avoid issues before reading packages

## 2018.12.31
* NEW: dependency on aenum module
* NEW: Rearranged format codes: 2/3 for results only; 99/98 for analysis output
* NEW: Added meta data size to header fields
* NEW: Added tool version
* NEW: Added offsets, sizes and SHA-256 of items info to results
* NEW: Added separate platform and package type values to results
* NEW: Added linux shell scripts to automate creation of analysis data and to quickly analyze them
* FIX: Fixed item info size calculation for some corner cases in parsing ItemEntries (did not affect any further processing)
* FIX: Analysis output (-f 99) does not dump anymore on PS4 packages (added meta data check)
* FIX: Analysis output (-f 99) shows correct file table index on PS4 packages
* FIX: Removed structure definitions from JSON output
* INTERNAL: Changed extended header size detection plus added ext header magic check
* INTERNAL: Use meta data 0xD for item entries offset
* INTERNAL: Added checks for items info offsets and sizes

## 2018.12.26
* NEW: pkg_dec's `--raw` extraction functionality to create a decrypted package file of PS3/PSX/PSP/PSV/PSM package
* NEW: JSON output of analysis data
* NEW: Added detection of meta data ID 13/0x0D
* NEW: Show unaligned access, as this is not common
* NEW: Added version and changelog
* FIX: Use UTF-8 encoding on Windows if stdout/stderr are redirected
* FIX: Correct size alignment calculation if offset alignment was calculated before
* FIX: Align access to item entries and item names too
* INTERNAL: Got rid of global variables in functions
* INTERNAL: Use int.from_bytes() instead of custom function. Python 2 provides it via future module
* INTERNAL: Switched to argparse for command line parsing
* INTERNAL: Enhanced dprint() and eprint() with prefix support
* INTERNAL: Read huge items from package in blocks to reduce memory usage and swapping
* INTERNAL: Adopted source code further to coding style
