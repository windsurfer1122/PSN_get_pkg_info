# PSN_get_pkg_info.py - Changelog

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
