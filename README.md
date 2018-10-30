# PSN_get_pkg_info.py (c) 2018 by "windsurfer1122"
Extract package information from header and PARAM.SFO of PS3/PSX/PSP/PSV/PSM and PS4 packages.

<u>Goals:</u>
* One-for-all solution to retrieve all header data and PARAM.SFO data from PSN packages
* Decryption of PS3 encrypted data to get all data
* Support of all known package types: PS3/PSX/PSP, PSV/PSM, PS4
* Easy enhancement of interpreting data (=done at the very end with all data at hand)
* Support multiple output formats
* Support multiple debug verbosity levels
* Easy to maintain and no compiler necessary (=interpreter language)
* Cross platform support
  * Decision: Python 3
    * Compatible with Python 2 (target version 2.7)
      * Identical output
      * Forward-compatible solutions preferred
* Modular and flexible code for easy enhancement and/or extensions (of course there's always something hard-coded left)

For options execute: PSN_get_pkg_info -h<br>
Use at your own risk!
If you state URLs then only the necessary bytes are downloaded into memory.


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


git master repository at https://github.com/windsurfer1122
