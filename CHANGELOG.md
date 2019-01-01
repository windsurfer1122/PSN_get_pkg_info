# PSN_get_pkg_info.py - Changelog

## 2018-12-31
* NEW: dependency on aenum module
* NEW: Rearranged format codes: 2/3 for results only; 99/98 for analysis output
* NEW: Added meta data size to header fields
* NEW: Added tool version
* NEW: Added offsets, sizes and SHA-256 of items info to results
* NEW: Added separate platform and package type values to results
* NEW: Added linux shell scripts to automate creation of analysis data and to quickly analyze them
* FIX: Off by 1 issue in parsing ItemEntries (did not affect any further processing)
* FIX: Analysis output (-f 99) does not dump anymore on PS4 packages (added meta data check)
* FIX: Analysis output (-f 99) shows correct file table index on PS4 packages
* FIX: Removed structure definitions from JSON output
* INTERNAL: Changed extended header size detection plus added ext header magic check
* INTERNAL: Use meta data 0xD for item entries offset
* INTERNAL: Added checks for items info offsets and sizes

## 2018-12-26
* NEW: pkg_dec's "--raw" functionality to create a decrypted package file of PS3/PSX/PSP/PSV/PSM package
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
