# PSN_get_pkg_info.py - Changelog

## 2019.01.00 alpha 4
* FIX: avoid leading spaces on metadata output (-f 99)
* FIX: Read only first 128 KiB to reduce download time (size fits unecrypted header size of all known packages)
* FIX: Fine-tuned messages for remaining data and unaligned access
* FIX: Corrected extraction messages for PSM additional special files
* INTERNAL: Items Info changes: rename function and variables, handle encrypted offset > 0 correctly, single bytearray for Items Info (entries plus names), use Items Info size from meta data if available, moved existing checks into function, added new checks, placed data about Items Info in own results dictionary, removed unneccesary internal data from JSON output
* INTERNAL: Extraction: create all directories before extracting any file, added item index to extraction messages

(alpha 3)
* NEW: Added zrif support to extraction functionality for PSV/PSM packages
* NEW: Added pkg2zip's `--ux0` extraction functionality for PSX/PSV/PSM packages (PSP still missing)
* NEW: Added pkg_dec's "makedir=id" `--content` extraction functionality for PS3/PSX/PSP/PSV/PSM packages
* NEW: Read first 1 MiB of each package to reduce HTTP/S request while keeping download time short (size fits 99% of known packages)
* FIX: Updated and corrected content id recognition

(alpha 2)
* NEW: (preliminary) Added pkg2zip's `--ux0` extraction functionality for PSV/PSM packages
* NEW: (preliminary) Added pkg_dec's "makedir=id" `--content` extraction functionality for PSV/PSM packages
* NEW: Added option `--quiet` to suppress extraction messages
* FIX: Content ID in header fields is 48 bytes long and not 36 (derived from PSM extraction)
* INTERNAL: Used dictionary for all extractions and adopted code to generic extraction routines
* INTERNAL: output format code 50 for debugging extractions

(alpha 1)
* NEW: Added item flags to output format 99 for detailed analysis
* NEW: Added checks for extraction targets to avoid issues before reading packages
* INTERNAL: Moved all extraction code in one block after data determination and output, so that analysis output is present even if any extraction fails
* INTERNAL: Adopted code further to coding style

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
