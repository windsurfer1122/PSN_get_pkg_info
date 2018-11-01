#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PSN_get_pky_info.py (c) 2018 by "windsurfer1122"
### Extract package information from header and PARAM.SFO of PS3/PSX/PSP/PSV/PSM and PS4 packages.
###
### Primary Goals:
### * One-for-all solution to retrieve all header data and PARAM.SFO data from PSN packages
### * Decryption of encrypted data to get all data
### * Support of all known package types: PS3/PSX/PSP, PSV/PSM, PS4
### * Easy enhancement of interpreting data (=done at the very end with all data at hand)
### * Support multiple output formats
### * Support multiple debug verbosity levels
###
### Secondary Goals:
### * Easy to maintain and no compiler necessary (=interpreter language)
### * Cross platform support
###   * Decision: Python 3
###
### Other Goals:
### * Modular and flexible code for easy enhancement and/or extensions (of course there's always something hard-coded left)
### * Compatible with Python 2 (target version 2.7)
###   * Identical output
###   * Forward-compatible solutions preferred
###
### For options execute: PSN_get_pkg_info.py -h and read the README.md
### Use at your own risk!
###
###
### This program is free software: you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, either version 3 of the License, or
### (at your option) any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program.  If not, see <https://www.gnu.org/licenses/>.
###
###
### git master repository at https://github.com/windsurfer1122
###
###
### Credits:
### * AnalogMan
### * https://playstationdev.wiki/ (previously https://vitadevwiki.com/ & https://www.pspdevwiki.com/)
### * http://www.psdevwiki.com/
### * mmozeiko
### * st4rk
### * qwikrazor87
###

###
### Python Related Information
###
### Using a HTTP Proxy: export HTTP_PROXY="http://192.168.0.1:3128"; export HTTPS_PROXY="http://192.168.0.1:1080";
###
### Python 3 on Debian:
### May need to install apt packages python3-requests python3-crypto, as Python 2 is default on Debian as of version 8
###
### Workarounds for Python 2 (see: http://python-future.org/compatible_idioms.html)
### - use of struct.unpack() instead of int.from_bytes()
### - convert byte string of struct.pack() to bytes
### - use future print function
### - use future unicode literals
###
### Python 2 on Debian:
### May need to install apt package python-future python-crypto, as Python 2 is default on Debian as of version 8
###
### Adopted PEP8 Coding Style:
### * [joined_]lower for attributes, variables
### * ALL_CAPS for constants
### * StudlyCaps for classes
### * (differs to PEP8) mixedCase for functions, methods
### * (differs to PEP8) StudlyCaps global variables
###

### Python 2 workarounds:
## a) prevent interpreting print(a,b) as a tuple plus support print(a, file=sys.stderr)
from __future__ import print_function
## b) interpret all literals as unicode
from __future__ import unicode_literals
## c) same division handling ( / = float, // = integer)
from __future__ import division
## d) interpret long as int
from builtins import int
## e) support bytes()
from builtins import bytes

import sys
import struct
import io
import requests
import collections
import locale
import os
import getopt
import re
import json
import binascii
import traceback

from Crypto.Cipher import AES
from Crypto.Util import Counter

from math import log
from datetime import datetime


## Debug level for Python initializations (will be reset in "main" code)
DebugLevel = 0


## Error and Debug print to stderr
## https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):  ## error print
    print(*args, file=sys.stderr, **kwargs)

def dprint(*args, **kwargs):  ## debug print
    if DebugLevel:
        print("[debug]", *args, file=sys.stderr, **kwargs)


## Enhanced TraceBack
## http://code.activestate.com/recipes/52215-get-more-information-from-tracebacks/
## https://stackoverflow.com/questions/27674602/hide-traceback-unless-a-debug-flag-is-set
def print_exc_plus():
    """
    Print the usual traceback information, followed by a listing of all the
    local variables in each frame.
    """
    tb = sys.exc_info()[2]
    stack = []

    while tb:
        stack.append(tb.tb_frame)
        tb = tb.tb_next

    for frame in stack:
        for key, value in frame.f_locals.items():
            if key != "Source":
                continue
            eprint(">>> PKG Source:", end=" ")
            #We have to be careful not to cause a new error in our error
            #printer! Calling str() on an unknown object could cause an
            #error we don't want.
            try:
                eprint(value)
            except:
                eprint("<ERROR WHILE PRINTING VALUE>")

    traceback.print_exc()


## Python 2 workaround: set system default encoding to UTF-8 like in Python 3
## All results will be Unicode and we want all output to be UTF-8
if sys.getdefaultencoding().lower() != "utf-8":
    if DebugLevel >= 1:
        dprint("Default Encoding set from {} to UTF-8".format(sys.getdefaultencoding()))
    reload(sys)
    sys.setdefaultencoding("utf-8")

## General debug information related to Python and Unicode
if DebugLevel >= 1:
    ## List encodings
    dprint("Python Version {}".format(sys.version))
    dprint("DEFAULT Encoding {}".format(sys.getdefaultencoding()))
    dprint("LOCALE Encoding {}".format(locale.getpreferredencoding()))
    dprint("STDOUT Encoding {} Terminal {}".format(sys.stdout.encoding, sys.stdout.isatty()))
    dprint("STDERR Encoding {} Terminal {}".format(sys.stderr.encoding, sys.stderr.isatty()))
    dprint("FILESYS Encoding {}".format(sys.getfilesystemencoding()))
    value = ""
    if "PYTHONIOENCODING" in os.environ:
        value = os.environ["PYTHONIOENCODING"]
    dprint("PYTHONIOENCODING={}".format(value))
    ## Check Unicode
    dprint("ö ☺ ☻")

## Python 2/3 workaround: define unicode for Python 3 like in Python 2
## Unfortunately a backward-compatible workaround, as I couldn't find a forward-compatible one :(
## Every string is Unicode
## https://stackoverflow.com/questions/34803467/unexpected-exception-name-basestring-is-not-defined-when-invoking-ansible2
try:
    unicode
except:
    if DebugLevel >= 1:
        dprint("Define \"unicode = str\" for Python 3 :(")
    unicode = str


## Generic definitions
CONST_FMT_BIG_ENDIAN = ">"
CONST_FMT_LITTLE_ENDIAN = "<"
CONST_FMT_UINT64, CONST_FMT_UINT32, CONST_FMT_UINT16, CONST_FMT_UINT8 = 'Q', 'L', 'H', 'B'
CONST_FMT_INT64, CONST_FMT_INT32, CONST_FMT_INT16, CONST_FMT_INT8 = 'q', 'l', 'h', 'b'

## Generic PKG definitions
CONST_CONTENT_ID_SIZE = 0x24
CONST_SHA256_HASH_SIZE = 0x20

##
## PKG3 Definitions
##
#
## --> Header
CONST_PKG3_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PKG3_MAGIC = 0x7f504b47  ## "\x7FPKG"
CONST_PKG3_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",     { "FORMAT": "L", "DEBUG": 1, "DESC": "Magic", }, ),
    ( "REV",       { "FORMAT": "H", "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",      { "FORMAT": "H", "DEBUG": 1, "DESC": "Type", }, ),
    ( "MDOFS",     { "FORMAT": "L", "DEBUG": 1, "DESC": "Meta Data Offset", }, ),
    ( "MDCNT",     { "FORMAT": "L", "DEBUG": 1, "DESC": "Meta Data Count", }, ),
    ( "HDRSIZE",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Header [Additional] Size incl. PS3 0x40 Digest [and Extensions]", }, ),
    ( "ITEMCNT",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Item Count", }, ),
    ( "TOTALSIZE", { "FORMAT": "Q", "DEBUG": 1, "DESC": "Total Size", }, ),
    ( "DATAOFS",   { "FORMAT": "Q", "DEBUG": 1, "DESC": "Data Offset", }, ),
    ( "DATASIZE",  { "FORMAT": "Q", "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "CID",       { "FORMAT": "s", "SIZE": CONST_CONTENT_ID_SIZE, "CONV": 0x0204, "DEBUG": 1, "DESC": "Content ID", }, ),
    ( "PADDING1",  { "FORMAT": "s", "SIZE": 12, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "DIGEST",    { "FORMAT": "s", "SIZE": 16, "DEBUG": 1, "DESC": "Digest", }, ),
    ( "DATARIV",   { "FORMAT": "s", "SIZE": 16, "DEBUG": 1, "DESC": "Data RIV", }, ),
    #
    ( "KEYINDEX",  { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Key Index for Decryption of Item Entries Table", }, ),
    ( "PARAM.SFO", { "VIRTUAL": -1, "DEBUG": 1, "DESC": "PARAM.SFO Item Name", }, ),
])
## --> PS3 0x40 Digest
CONST_PKG3_PS3_DIGEST_FIELDS = collections.OrderedDict([ \
    ( "CMACHASH",     { "FORMAT": "s", "SIZE": 16, "DEBUG": 1, "DESC": "CMAC Hash", }, ),
    ( "NPDRMSIG",     { "FORMAT": "s", "SIZE": 40, "DEBUG": 1, "DESC": "NpDrm Signature", }, ),
    ( "SHA1HASH",     { "FORMAT": "s", "SIZE": 8, "DEBUG": 1, "DESC": "SHA1 Hash", }, ),
])
## --> Extended Header
CONST_PKG3_EXT_MAGIC = 0x7f657874
CONST_PKG3_EXT_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": "L", "DEBUG": 1, "DESC": "Magic", }, ),
    ( "UNKNOWN",      { "FORMAT": "L", "DEBUG": 1, "DESC": "Unknown (likely version/type)", }, ),
    ( "HDRSIZE",      { "FORMAT": "L", "DEBUG": 1, "DESC": "Ext Header Size", }, ),
    ( "DATASIZE",     { "FORMAT": "L", "DEBUG": 1, "DESC": "RSA Size", }, ),
    ( "HDRRSAOFS",    { "FORMAT": "L", "DEBUG": 1, "DESC": "Header RSA Offset", }, ),
    ( "METARSAOFS",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Meta Data RSA Offset", }, ),
    ( "DATARSAOFS",   { "FORMAT": "Q", "DEBUG": 1, "DESC": "Data RSA Offset", }, ),
    ( "PADDING1",     { "FORMAT": "s", "SIZE": 4, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "KEYID",        { "FORMAT": "L", "DEBUG": 1, "DESC": "PKG Key Index", }, ),
    ( "ALLHDRRSAOFS", { "FORMAT": "L", "DEBUG": 1, "DESC": "All Header RSA Offset", }, ),
    ( "PADDING2",     { "FORMAT": "s", "SIZE": 20, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
])
## --> Item Entry
CONST_PKG3_ITEM_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "ITEMNAMEOFS",  { "FORMAT": "L", "DEBUG": 1, "DESC": "Item Name Offset", }, ),
    ( "ITEMNAMESIZE", { "FORMAT": "L", "DEBUG": 1, "DESC": "Item Name Size", }, ),
    ( "DATAOFS",      { "FORMAT": "Q", "DEBUG": 1, "DESC": "Data Offset", }, ),
    ( "DATASIZE",     { "FORMAT": "Q", "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "FLAGS",        { "FORMAT": "L", "DEBUG": 1, "DESC": "Flags", }, ),
    ( "PADDING1",     { "FORMAT": "s", "SIZE": 4, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    #
    ( "NAME",         { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Item Name", }, ),
])
## --> Content PKG Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_CONTENT_KEYS = {
   0: { "KEY": bytes.fromhex("2e7b71d7c9c9a14ea3221f188828b8f8"), "DESC": "PS3",     },
   1: { "KEY": bytes.fromhex("07f2c68290b50d2c33818d709b60e62b"), "DESC": "PSX/PSP", },
   2: { "KEY": bytes.fromhex("e31a70c9ce1dd72bf3c0622963f2eccb"), "DESC": "PSV",     "DERIVE": True, },
   3: { "KEY": bytes.fromhex("423aca3a2bd5649f9686abad6fd8801f"), "DESC": "Unknown", "DERIVE": True, },
   4: { "KEY": bytes.fromhex("af07fd59652527baf13389668b17d9ea"), "DESC": "PSM",     "DERIVE": True, },
}

##
## PKG4 Definitions
##
#
## --> Header
CONST_PKG4_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PKG4_MAGIC = 0x7f434e54
CONST_PKG4_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": "L", "DEBUG": 1, "DESC": "Magic", }, ),
    ( "REV",          { "FORMAT": "H", "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",         { "FORMAT": "H", "DEBUG": 1, "DESC": "Type", }, ),
    ( "UNKNOWN1",     { "FORMAT": "s", "SIZE": 4, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
    ( "FILECNT",      { "FORMAT": "L", "DEBUG": 1, "DESC": "File Count", }, ),
    ( "ENTCNT",       { "FORMAT": "L", "DEBUG": 1, "DESC": "Entry Count", }, ),
    ( "SCENTCNT",     { "FORMAT": "H", "DEBUG": 1, "DESC": "SC Entry Count", }, ),
    ( "ENTCNT2",      { "FORMAT": "H", "DEBUG": 1, "DESC": "Entry Count 2", }, ),
    ( "FILETBLOFS",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Table Offset", }, ),
    ( "ENTSIZE",      { "FORMAT": "L", "DEBUG": 1, "DESC": "Ent Data Size", }, ),
    ( "BODYOFS",      { "FORMAT": "Q", "DEBUG": 1, "DESC": "Body Offset", }, ),
    ( "BODYSIZE",     { "FORMAT": "Q", "DEBUG": 1, "DESC": "Body Size", }, ),
    ( "PADDING1",     { "FORMAT": "s", "SIZE": 16, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "CID",          { "FORMAT": "s", "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", }, ),
    ( "PADDING2",     { "FORMAT": "s", "SIZE": 12, "DEBUG": 3, "DESC": "Padding", }, ),
    ( "DRMTYPE",      { "FORMAT": "L", "DEBUG": 1, "DESC": "DRM Type", }, ),
    ( "CONTTYPE",     { "FORMAT": "L", "DEBUG": 1, "DESC": "Content Type", }, ),
    ( "CONTFLAGS",    { "FORMAT": "L", "DEBUG": 1, "DESC": "Content Flags", }, ),
    ( "PROMOTSIZE",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Promote Size", }, ),
    ( "VERSIONDAT",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Version Date", }, ),
    ( "VERSIONHAS",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Version Hash", }, ),
    ( "UNKNOWN2",     { "FORMAT": "s", "SIZE": -0x098, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
    ( "IROTAG",       { "FORMAT": "L", "DEBUG": 1, "DESC": "IRO Tag", }, ),
    ( "EKCVERSION",   { "FORMAT": "L", "DEBUG": 1, "DESC": "EKC Version", }, ),
    ( "UNKNOWN3",     { "FORMAT": "s", "SIZE": -0x100, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),

    ( "DIGESTTABL",   { "FORMAT": "s", "SUBCOUNT": 24, "SUBSIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 2, "DESC": "Digest Table", }, ),
      ## [0] = main_  entries1_digest
      ## [1] = main_  entries2_digest
      ## [2] = diges  t_table_digest
      ## [3] = body_  digest
      ## [4]-[23] =   unused
    ( "UNKNOWN4",     { "FORMAT": "s", "SIZE": 4, "DEBUG": 1, "DESC": "Unknown (Maybe count)", }, ),
    ( "PFSIMGCNT",    { "FORMAT": "L", "DEBUG": 1, "DESC": "PFS Image Count", }, ),
## >>> Could be a 136 bytes structure, that may be repeated up to 3 times (or even more? 22x up to 0xfd9)
##     While the 2 integers before may define the count and number of each pfs container
    ( "PFSFLAGS",     { "FORMAT": "Q", "DEBUG": 1, "DESC": "PFS Flags", }, ),
    ( "PFSIMGOFS",    { "FORMAT": "Q", "DEBUG": 1, "DESC": "PFS Image Offset", }, ),
    ( "PFSIMGSIZE",   { "FORMAT": "Q", "DEBUG": 1, "DESC": "PFS Image Size", }, ),
    ( "MNTIMGOFS",    { "FORMAT": "Q", "DEBUG": 1, "DESC": "Mount Image Offset", }, ),
    ( "MNTIMGSIZE",   { "FORMAT": "Q", "DEBUG": 1, "DESC": "Mount Image Size", }, ),
    ( "PKGSIZE",      { "FORMAT": "Q", "DEBUG": 1, "DESC": "Package Size", }, ),
    ( "PFSSIGNSIZE",  { "FORMAT": "L", "DEBUG": 1, "DESC": "PFS Signed Size", }, ),
    ( "PFSCACHESIZE", { "FORMAT": "L", "DEBUG": 1, "DESC": "PFS Cache Size", }, ),
    ( "PFSIMGDIG",    { "FORMAT": "s", "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Image Digest", }, ),
    ( "PFSSIGNDIG",   { "FORMAT": "s", "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Signed Digest", }, ),
    ( "PFSSPLITNTH0", { "FORMAT": "Q", "DEBUG": 1, "DESC": "PFS Split NTH 0", }, ),
    ( "PFSSPLITNTH1", { "FORMAT": "Q", "DEBUG": 1, "DESC": "PFS Split NTH 1", }, ),
## <<< Could be 136 bytes structure
## >>> Could be 2x 136 bytes structure from before
    ( "UNKNOWN5",     { "FORMAT": "s", "SIZE": -0x5a0, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
## <<< Could be 2x 136 bytes structure from before
## real size looks like it is 0x2000
])
#
## --> File Entry Table
CONST_PKG4_FILE_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "FILEID",       { "FORMAT": "L", "DEBUG": 1, "DESC": "File ID", }, ),
    ( "NAMERELOFS",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Name Table Offset", }, ),
    ( "FLAGS1",       { "FORMAT": "L", "DEBUG": 1, "DESC": "Flags 1", }, ),
    ( "FLAGS2",       { "FORMAT": "L", "DEBUG": 1, "DESC": "Flags 2", }, ),
    ( "DATAOFS",      { "FORMAT": "L", "DEBUG": 1, "DESC": "PKG Offset", }, ),
    ( "DATASIZE",     { "FORMAT": "L", "DEBUG": 1, "DESC": "File Size", }, ),
    ( "PADDING1",     { "FORMAT": "s", "SIZE": 8, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    #
    ( "NAME",         { "VIRTUAL": -1, "DEBUG": 1, "DESC": "File Name", }, ),
])
#
## --> Name Table
##     Name Table is 0-indexed, index 0 is an empty name
CONST_PKG4_FILE_ENTRY_ID_DIGEST_TABLE = 0x0001
CONST_PKG4_FILE_ENTRY_ID_ENTRY_KEYS   = 0x0010
CONST_PKG4_FILE_ENTRY_ID_IMAGE_KEY    = 0x0020
CONST_PKG4_FILE_ENTRY_ID_GENERAL_DIGESTS = 0x0080
CONST_PKG4_FILE_ENTRY_ID_META_TABLE   = 0x0100
CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE   = 0x0200
CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO    = 0x1000
#
CONST_PKG4_FILE_ENTRY_NAME_MAP = {
	CONST_PKG4_FILE_ENTRY_ID_DIGEST_TABLE: ".digests",
	CONST_PKG4_FILE_ENTRY_ID_ENTRY_KEYS: ".entry_keys",
	CONST_PKG4_FILE_ENTRY_ID_IMAGE_KEY: ".image_key",
	CONST_PKG4_FILE_ENTRY_ID_GENERAL_DIGESTS: ".general_digests",
	CONST_PKG4_FILE_ENTRY_ID_META_TABLE: ".metatable",
	CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE: ".nametable",

	0x0400: "license.dat",
	0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat",
    0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat",

  	CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO: "param.sfo",
	0x1001: "playgo-chunk.dat",
	0x1002: "playgo-chunk.sha",
	0x1003: "playgo-manifest.xml",
	0x1004: "pronunciation.xml",
	0x1005: "pronunciation.sig",
	0x1006: "pic1.png",
    0x1007: "pubtoolinfo.dat",
	0x1008: "app/playgo-chunk.dat",
    0x1009: "app/playgo-chunk.sha",
    0x100a: "app/playgo-manifest.xml",
    0x100b: "shareparam.json",
    0x100c: "shareoverlayimage.png",
    0x100d: "save_data.png",
    0x100e: "shareprivacyguardimage.png",

    0x1200: "icon0.png",
    0x1220: "pic0.png",
    0x1240: "snd0.at9",
    0x1260: "changeinfo/changeinfo.xml",
    0x1280: "icon0.dds",
    0x12a0: "pic0.dds",
    0x12c0: "pic1.dds",
}
#
## 0x1201-0x121f: icon0_<nn>.png
for count in range(0x1f):
    key = 0x1201 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "icon0_{:02}.png".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1241-0x125f: pic1_<nn>.png
for count in range(0x1f):
    key = 0x1241 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "pic1_{:02}.png".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1261-0x127f: pic1_<nn>.png
for count in range(0x1f):
    key = 0x1261 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "changeinfo/changeinfo_{:02}.xml".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1281-0x129f: icon0_<nn>.dds
for count in range(0x1f):
    key = 0x1281 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "icon0_{:02}.dds".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x12c1-0x12df: pic1_<nn>.dds
for count in range(0x1f):
    key = 0x12c1 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "pic1_{:02}.dds".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1400-0x1463: trophy/trophy<nn>.dds
for count in range(0x64):
    key = 0x1400 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "trophy/trophy{:02}.trp".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1600-0x1609: keymap_rp/<nn>.png
for count in range(0x0a):
    key = 0x1600 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "keymap_rp/{:03}.png".format(count)
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))
#
## 0x1610-0x17f9: keymap_rp/<nn>/<nnn>.png
for count in range(0x01ea):
    key = 0x1610 + count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[key] = "keymap_rp/{:02}/{:03}.png".format(count >> 4, count & 0xf )
    if DebugLevel >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(key, CONST_PKG4_FILE_ENTRY_NAME_MAP[key]))

##
## PARAM.SFO Definitions
##
CONST_PARAM_SFO_ENDIAN = CONST_FMT_LITTLE_ENDIAN
## --> Header
CONST_PARAM_SFO_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": "L", "DEBUG": 1, "DESC": "Magic", }, ),
    ( "VERSION",      { "FORMAT": "L", "DEBUG": 1, "DESC": "Version", }, ),
    ( "KEYTBLOFS",    { "FORMAT": "L", "DEBUG": 1, "DESC": "Key Table Offset", }, ),
    ( "DATATBLOFS",   { "FORMAT": "L", "DEBUG": 1, "DESC": "Data Table Offset", }, ),
    ( "COUNT",        { "FORMAT": "L", "DEBUG": 1, "DESC": "Entry Count", }, ),
])
#
## --> File Entry Table
CONST_PARAM_SFO_INDEX_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "KEYOFS",       { "FORMAT": "H", "DEBUG": 1, "DESC": "Key Offset", }, ),
    ( "DATAFORMAT",   { "FORMAT": "H", "DEBUG": 1, "DESC": "Data Format", }, ),
    ( "DATAUSEDSIZE", { "FORMAT": "L", "DEBUG": 1, "DESC": "Data Used Size", }, ),
    ( "DATAMAXSIZE",  { "FORMAT": "L", "DEBUG": 1, "DESC": "Data Maximum Size", }, ),
    ( "DATAOFS",      { "FORMAT": "L", "DEBUG": 1, "DESC": "Data Offset", }, ),
])


def prettySize(n, pow=0, b=1024, u="B", pre=[""]+[p+"i"for p in "KMGTPEZY"]):
    pow, n = min(int(log(max(n*b**pow, 1), b)), len(pre)-1), n*b**pow
    return "%%.%if %%s%%s" % abs(pow % (-pow-1)) % (n/b**float(pow), pre[pow], u)


def getInteger16BitLE(data, offset):
    return struct.unpack("<H", data[offset:offset+2])[0]

def getInteger32BitLE(data, offset):
    return struct.unpack("<L", data[offset:offset+4])[0]

def getInteger64BitLE(data, offset):
    return struct.unpack("<Q", data[offset:offset+8])[0]

def getInteger16BitBE(data, offset):
    return struct.unpack(">H", data[offset:offset+2])[0]

def getInteger32BitBE(data, offset):
    return struct.unpack(">L", data[offset:offset+4])[0]

def getInteger64BitBE(data, offset):
    return struct.unpack(">Q", data[offset:offset+8])[0]


def convertBytesToHexString(data, format=""):
    if isinstance(data, int):
        data = struct.pack(format, data)
    ## Python 2 workaround: convert str to bytes
    if isinstance(data, str):
        data = bytes(data)
    #
    return " ".join(["%02x" % b for b in data])


def convertBytesToIntegerValue(data):
    return int(binascii.hexlify(data), 16)

def calculateAesAlignedOffsetAndSize(offset, size):
    aligned_offset_delta = offset & ( AES.block_size - 1 )
    aligned_offset = offset - aligned_offset_delta

    aligned_size_delta = size & ( AES.block_size - 1 )
    if aligned_size_delta > 0:
        aligned_size_delta = AES.block_size - aligned_size_delta
    aligned_size_delta += aligned_offset_delta
    aligned_size = size + aligned_size_delta

    return aligned_offset, aligned_size, aligned_offset_delta, aligned_size_delta


class PkgReader():
    def __init__(self, source, debug_level=0):
        self._source = source
        self._size = None

        if self._source.startswith("http:") \
        or self._source.startswith("https:"):
            if debug_level >= 2:
                dprint("Opening source as URL data stream")
            self._stream_type = "requests"
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            try:
                self._data_stream = requests.Session()
            except:
                eprint("\nERROR: {}: Could not create HTTP/S session for PKG URL".format(sys.argv[0]))
                sys.exit(2)
            self._data_stream.headers = {"User-Agent": "libhttp/3.69 (PS Vita)"}
            ##TODO: PS4: "Download/1.00 libhttp/6.00 (PlayStation 4)"
            response = self._data_stream.head(self._source)
            if debug_level >= 2:
                dprint(response)
                dprint("Response headers:", response.headers)
            if "content-length" in response.headers:
                self._size = int(response.headers["content-length"])
        else:
            if debug_level >= 2:
                dprint("Opening source as FILE data stream")
            self._stream_type = "file"
            try:
                self._data_stream = io.open(self._source, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("\nERROR: {}: Could not open PKG FILE {}".format(sys.argv[0], self._source))
                sys.exit(2)
            #
            self._data_stream.seek(0, os.SEEK_END)
            self._size = self._data_stream.tell()

        if debug_level >= 3:
            dprint("Data stream is of class {}".format(self._data_stream.__class__.__name__))

    def getSize(self, debug_level=0):
        return self._size

    def read(self, offset, size, debug_level=0):
        if self._stream_type == "file":
            self._data_stream.seek(offset, os.SEEK_SET)
            return self._data_stream.read(size)
        elif self._stream_type == "requests":
            ## Send request in persistent session
            ## http://docs.python-requests.org/en/master/api/#requests.Session.get
            ## http://docs.python-requests.org/en/master/api/#requests.request
            reqheaders={"Range": "bytes={}-{}".format(offset, offset + size - 1)}
            response = self._data_stream.get(self._source, headers=reqheaders)
            return response.content

    def close(self, debug_level=0):
        return self._data_stream.close()


class PkgAesCtrCounter():
    def __init__(self, key, iv):
        self._key = key
        if isinstance(iv, int):
            self._iv = iv
        elif isinstance(iv, bytes) \
        or isinstance(iv, bytearray):
            self._iv = convertBytesToIntegerValue(iv)
        self._reset()
    def _reset(self):
        if hasattr(self, "_ctr"):
            del self._ctr
        if hasattr(self, "_aes"):
            del self._aes
        self._ctr = Counter.new(AES.key_size[0] * 8, initial_value=self._iv)  ## Key length 16 bytes = 128 bits
        self._aes = AES.new(self._key, AES.MODE_CTR, counter=self._ctr)
        self._block_offset = 0
    def _setOffset(self, offset):
        if offset < self._block_offset:
            self._reset()
        if offset > self._block_offset:
            for _i in range((offset - self._block_offset) // AES.block_size):
                self._ctr()
                self._block_offset += AES.block_size
    def decrypt(self, offset, data):
        self._setOffset(offset)
        self._block_offset += len(data)
        decrypted_data = self._aes.decrypt(data)
        ## Python 2 workaround: convert str to bytes
        if isinstance(decrypted_data, str):
            decrypted_data = bytes(decrypted_data)
        return decrypted_data


def getRegion(id):
    ## For definition see http://www.psdevwiki.com/ps3/Productcode
    ##                    http://www.psdevwiki.com/ps3/PARAM.SFO#TITLE_ID
    ##                    http://www.psdevwiki.com/ps4/Regioning
    ##
    ##                    https://playstationdev.wiki/psvitadevwiki/index.php?title=Languages
    ##                    http://www.psdevwiki.com/ps3/Languages
    ##                    http://www.psdevwiki.com/ps3/PARAM.SFO#TITLE
    ##                    http://www.psdevwiki.com/ps4/Languages
    if id == "A":
        return "ASIA", [ "09", "11", "10", "00" ]
    elif id == "E":
        return "EU", [ "01", "18" ]
    elif id == "H":
        return "ASIA(HKG)", [ "11", "10" ]
    elif id == "I":
        return "INT", [ "01", "18" ]
    elif id == "J":
        return "JP", [ "00" ]
    elif id == "K":
        return "ASIA(KOR)", [ "09" ]
    elif id == "U":
        return "US", [ "01" ]
    else:
        return "???", []


def convertUtf8BytesToString(data, conversion, length = 0):
    result = ""
    ## Python 2 workaround: convert str to bytes
    if isinstance(data, str):
        data = bytes(data)
    #
    if length == 0:
        length = len(data)
    _i = length
    #
    if conversion == 0x0204:  ## UTF-8 NUL-terminated
        for _i in range(length):  ## 0 to <length - 1>
            if data[_i] == 0:
                data = data[:_i]
                break
    #
    if _i > 0:
        result = data.decode("utf-8", errors="ignore")
    #
    return result


def dprintBytesStructure(CONST_STRUCTURE_FIELDS, CONST_STRUCTURE_ENDIAN, tempfields, formatstring, parent_debug_level):
    for key in CONST_STRUCTURE_FIELDS:
        if key == "STRUCTURE_SIZE" \
        or key == "STRUCTURE_UNPACK":
            continue
        #
        fielddef = CONST_STRUCTURE_FIELDS[key]
        #
        if "VIRTUAL" in fielddef \
        and fielddef["VIRTUAL"]:
            continue
        #
        field_debug_level = 1
        if "DEBUG" in fielddef:
            field_debug_level = fielddef["DEBUG"]
        #
        if parent_debug_level >= field_debug_level:
            fieldformat = fielddef["FORMAT"]
            output = formatstring.format(fielddef["INDEX"], fielddef["OFFSET"], fielddef["SIZE"], fielddef["DESC"], convertBytesToHexString(tempfields[fielddef["INDEX"]], "".join((CONST_STRUCTURE_ENDIAN, fieldformat))))
            #
            if "CONV" in fielddef:
                if fielddef["CONV"] == 0x0004 \
                or fielddef["CONV"] == 0x0204:  ## UTF-8 not and NUL-terminated
                    value = convertUtf8BytesToString(tempfields[fielddef["INDEX"]], fielddef["CONV"])
                    output = "".join((output, " => ", value))
            elif CONST_STRUCTURE_ENDIAN == CONST_FMT_LITTLE_ENDIAN \
            and ( fieldformat == "L" \
                  or fieldformat == "H" \
                  or fieldformat == "Q" ) :
                output = "".join((output, " => ", convertBytesToHexString(tempfields[fielddef["INDEX"]], "".join((CONST_FMT_BIG_ENDIAN, fieldformat)))))
            #
            dprint(output)


def dprintField(key, field, fielddef, formatstring, parent_debug_level, parent_prefix, print_func=dprint):
    if isinstance(key, unicode):
        key = "".join(("\"", key, "\"" ))
    if parent_prefix is None:
        formatvalues = {}
        formatvalues["KEY"] = key
        if fielddef:
            formatvalues["INDEX"] = fielddef["INDEX"]
            formatvalues["DESC"] = fielddef["DESC"]
        prefix = formatstring.format(**formatvalues)
    else:
        prefix = "".join((parent_prefix, "[", formatstring.format(key), "]"))
    #
    if isinstance(field, list) \
    or isinstance(field, tuple):  ## indexed list
        dprintFieldsList(field, formatstring, parent_debug_level, prefix, print_func)
    elif isinstance(field, dict):  ## dictionary
        dprintFieldsDict(field, formatstring, parent_debug_level, prefix, print_func)
    else:
        if isinstance(field, int):
            value = "{0} = {0:#x}".format(field)
        elif isinstance(field, bytes) \
        or isinstance(field, bytearray):
            value = convertBytesToHexString(field)
        else:
            value = field
        #
        print_func("".join((prefix, ":")), value)

def dprintFieldsList(fields, formatstring, parent_debug_level, parent_prefix, print_func=dprint):
    length = len(fields)
    #
    if parent_prefix:
        formatstring = "".join(("{:", unicode(len(unicode(length))), "}"))
    #
    for key in range(length):
        field = fields[key]
        #
        dprintField(key, field, None, formatstring, parent_debug_level, parent_prefix, print_func)

def dprintFieldsDict(fields, formatstring, parent_debug_level, parent_prefix, print_func=dprint):
    if parent_prefix:
        formatstring = "{}"
    #
    fields_structure = None
    if "STRUCTURE_DEF" in fields:
        fields_structure = fields["STRUCTURE_DEF"]
    #
    for key in fields:
        if fields_structure \
        and not key in fields_structure:
            continue
        #
        field = fields[key]
        #
        fielddef = None
        field_debug_level = 1
        if fields_structure \
        and key in fields_structure:
            fielddef = fields_structure[key]
            if "DEBUG" in fielddef:
                field_debug_level = fielddef["DEBUG"]
        #
        if parent_debug_level >= field_debug_level:
            dprintField(key, field, fielddef, formatstring, parent_debug_level, parent_prefix, print_func)


def finalizeBytesStructure(CONST_STRUCTURE_FIELDS, CONST_STRUCTURE_ENDIAN, structure_name, formatstring, parent_debug_level):
    unpack_format = CONST_STRUCTURE_ENDIAN
    offset = 0
    index = 0
    for key in CONST_STRUCTURE_FIELDS:
        fielddef = CONST_STRUCTURE_FIELDS[key]
        #
        if "VIRTUAL" in fielddef \
        and fielddef["VIRTUAL"]:
            fielddef["INDEX"] = -1
            fielddef["OFFSET"] = -1
            continue
        #
        fielddef["INDEX"] = index
        fielddef["OFFSET"] = offset
        if "FORMAT" in fielddef:
            fieldformat = fielddef["FORMAT"]
            if fieldformat == "s":
                if "SUBSIZE" in fielddef:
                    fielddef["SIZE"] = fielddef["SUBSIZE"] * fielddef["SUBCOUNT"]
                elif fielddef["SIZE"] < 0:
                    fielddef["SIZE"] = abs(fielddef["SIZE"]) - fielddef["OFFSET"]
                fieldformat = "".join((unicode(fielddef["SIZE"]), fieldformat))
            elif fieldformat == "L" \
            or fieldformat == "H" \
            or fieldformat == "Q":
                fielddef["SIZE"] = struct.calcsize("".join((CONST_STRUCTURE_ENDIAN, fieldformat)))
            unpack_format = "".join((unpack_format, fieldformat))
        if parent_debug_level >= 3:
            dprint(formatstring.format(structure_name, fielddef["INDEX"], fielddef["OFFSET"], fielddef["SIZE"], key, fielddef["DESC"]))
        offset += fielddef["SIZE"]
        index += 1
    structure_size = struct.calcsize(unpack_format)
    if parent_debug_level >= 2:
        dprint("{}: Size {} Format {}".format(structure_name, structure_size, unpack_format))

    CONST_STRUCTURE_FIELDS["STRUCTURE_SIZE"] = structure_size
    CONST_STRUCTURE_FIELDS["STRUCTURE_UNPACK"] = unpack_format


def convertFieldsToOrdDict(CONST_STRUCTURE_FIELDS, tempfields):
    fields = collections.OrderedDict()
    #
    for key in CONST_STRUCTURE_FIELDS:
        if key == "STRUCTURE_SIZE" \
        or key == "STRUCTURE_UNPACK":
            continue
        #
        fielddef = CONST_STRUCTURE_FIELDS[key]
        #
        if "SKIP" in fielddef \
        and fielddef["SKIP"]:
            continue
        #
        if "VIRTUAL" in fielddef \
        and fielddef["VIRTUAL"]:
            if fielddef["VIRTUAL"] > 0:
                fields[key] = None
            continue
        #
        fields[key] = tempfields[fielddef["INDEX"]]
        if "CONV" in fielddef:
            if fielddef["CONV"] == 0x0004 \
            or fielddef["CONV"] == 0x0204:  ## UTF-8 not and NUL-terminated
                fields[key] = convertUtf8BytesToString(fields[key], fielddef["CONV"])
        elif "FORMAT" in fielddef:
            ## Python 2 workaround: convert str to bytes
            if fielddef["FORMAT"] == "s" \
            and isinstance(fields[key], str):
                fields[key] = bytes(fields[key])
    #
    fields["STRUCTURE_DEF"] = CONST_STRUCTURE_FIELDS
    #
    return fields


def parsePkg4Header(headerbytes):
    ## local debug level for fine-tuned analysis
    function_debug_level = 0  ## hard-coded minimum local debug level
    if function_debug_level < DebugLevel:
        function_debug_level = DebugLevel

    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps4/PKG_files#File_Header

    ## Extract fields from PKG4 Main Header
    tempfields = struct.unpack(CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], headerbytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PKG4_MAIN_HEADER_FIELDS, CONST_PKG4_HEADER_ENDIAN, tempfields, "PKG4 Main Header[{:2}]: [{:#05x}|{:3}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    headerfields = convertFieldsToOrdDict(CONST_PKG4_MAIN_HEADER_FIELDS, tempfields)
    del tempfields

    ## Process sub structures
    for key in headerfields:
        if not key in CONST_PKG4_MAIN_HEADER_FIELDS:
            continue
        #
        fielddef = CONST_PKG4_MAIN_HEADER_FIELDS[key]
        if "SUBCOUNT" in fielddef:
            unpack_format = CONST_PKG4_HEADER_ENDIAN
            fieldformat = "".join((unicode(fielddef["SUBSIZE"]), fielddef["FORMAT"]))
            for _i in range(fielddef["SUBCOUNT"]):
                unpack_format = "".join((unpack_format, fieldformat))
            headerfields[key] = struct.unpack(unpack_format, headerfields[key])
            ## Python 2 workaround: convert str to bytes
            if fielddef["FORMAT"] == "s" \
            and isinstance(headerfields[key][0], str):
                tempfields = []
                for _i in range(len(headerfields[key])):
                    tempfields.append(bytes(headerfields[key][_i]))
                headerfields[key] = tempfields
                del tempfields

    ## Prepare format strings
    filecntlen = unicode(len(unicode(headerfields["FILECNT"])))
    filecntformatstring = "".join(("{:", filecntlen, "}"))

    ## Retrieve PKG4 File Entry Table from data stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 File Entry Table:")
    pkg_file_table_size = headerfields["FILECNT"] * CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG4 file entry table from offset {:#x} with count {} and size {}".format(headerfields["FILETBLOFS"], headerfields["FILECNT"], pkg_file_table_size))
    tempbytes = bytearray()
    try:
        tempbytes.extend(DataStream.read(headerfields["FILETBLOFS"], pkg_file_table_size, function_debug_level))
    except:
        DataStream.close(function_debug_level)
        eprint("\nERROR: {}: Could not get PKG4 file entry table at offset {:#x} with size {} from {}".format(sys.argv[0], headerfields["FILETBLOFS"], pkg_file_table_size, Source))
        sys.exit(2)

    ## Parse PKG4 File Entry Table Data
    filetable = []
    filetablemap = collections.OrderedDict()
    offset = 0
    #
    for _i in range(headerfields["FILECNT"]):  ## 0 to <file count - 1>
        tempfields = struct.unpack(CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_UNPACK"], tempbytes[offset:offset+CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG4_FILE_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, tempfields, "".join(("PKG4 File Entry[", filecntformatstring.format(_i), "][{:2}]: [{:#04x}|{:2}] {} = {}")), function_debug_level)
        tempfields = convertFieldsToOrdDict(CONST_PKG4_FILE_ENTRY_FIELDS, tempfields)
        tempfields["INDEX"] = _i
        tempfields["KEYINDEX"] = (tempfields["FLAGS2"] & 0xf000) >> 12  # TODO: correct?
        filetable.append(tempfields)
        #
        filetablemap[tempfields["FILEID"]] = _i
        #
        del tempfields
        #
        offset += CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del tempbytes

    ## Retrieve PKG4 Name Table from data stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Name Table:")
    nametable = None
    if not CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE in filetablemap:
        dprint("Not present!")
    else:
        fileentry = filetable[filetablemap[CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE]]
        if function_debug_level >= 2:
                dprint("Get PKG4 name table from offset {:#x} with size {}".format(fileentry["DATAOFS"], fileentry["DATASIZE"]))
        nametable = bytearray()
        try:
            nametable.extend(DataStream.read(fileentry["DATAOFS"], fileentry["DATASIZE"], function_debug_level))
        except:
            DataStream.close(function_debug_level)
            eprint("\nERROR: {}: Could not get PKG4 name table at offset {:#x} with size {} from {}".format(sys.argv[0], fileentry["DATAOFS"], fileentry["DATASIZE"], Source))
            sys.exit(2)
        nametable = bytes(nametable)

    ## Parse PKG4 Name Table Data for File Entries
    if function_debug_level >= 2:
        dprint("Parse PKG4 Name Table for File Names")
    for _i in range(headerfields["FILECNT"]):  ## 0 to <file count - 1>
        fileentry = filetable[_i]
        #
        if nametable \
        and fileentry["NAMERELOFS"] > 0:
            fileentry["NAME"] = convertUtf8BytesToString(nametable[fileentry["NAMERELOFS"]:], 0x0204)
        elif fileentry["FILEID"] in CONST_PKG4_FILE_ENTRY_NAME_MAP:
            fileentry["NAME"] = CONST_PKG4_FILE_ENTRY_NAME_MAP[fileentry["FILEID"]]
        #
        if "NAME" in fileentry \
        and function_debug_level >= 2:
            dprint("".join(("PKG4 File Entry[", filecntformatstring, "]: ID {:#06x} Name Offset {:#03x} =")).format(_i, fileentry["FILEID"], fileentry["NAMERELOFS"]), fileentry["NAME"])
        #
        if ExtractUnknown \
        and not fileentry["FILEID"] in CONST_PKG4_FILE_ENTRY_NAME_MAP:
            eprint("!!! PKG4 File ID {:#x} {}".format(fileentry["FILEID"], fileentry["NAME"] if "NAME" in fileentry else ""))

    ## Debug print results
    dprint(">>>>> parsePkg4Header results:")
    dprintFieldsDict(headerfields, "headerfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsList(filetable, "".join(("filetable[{KEY:", filecntlen, "}]")), function_debug_level, None)
    if function_debug_level >= 2:
        dprintFieldsDict(filetablemap, "filetablemap[{KEY:#06x}]", function_debug_level, None)
        dprint("nametable: {}".format(nametable))

    return headerfields, filetable, filetablemap


def parsePkg3Header(headerbytes):
    ## local debug level for fine-tuned analysis
    function_debug_level = 0  ## hard-coded minimum local debug level
    if function_debug_level < DebugLevel:
        function_debug_level = DebugLevel

    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2

    ## Extract fields from PKG3 Main Header
    tempfields = struct.unpack(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], headerbytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PKG3_MAIN_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, tempfields, "PKG3 Main Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    headerfields = convertFieldsToOrdDict(CONST_PKG3_MAIN_HEADER_FIELDS, tempfields)
    del tempfields

    ## Process sub structures
    for key in headerfields:
        if not key in CONST_PKG3_MAIN_HEADER_FIELDS:
            continue
        #
        fielddef = CONST_PKG3_MAIN_HEADER_FIELDS[key]
        if "SUBCOUNT" in fielddef:
            unpack_format = CONST_PKG3_HEADER_ENDIAN
            fieldformat = "".join((unicode(fielddef["SUBSIZE"]), fielddef["FORMAT"]))
            for _i in range(fielddef["SUBCOUNT"]):
                unpack_format = "".join((unpack_format, fieldformat))
            headerfields[key] = struct.unpack(unpack_format, headerfields[key])
            ## Python 2 workaround: convert str to bytes
            if fielddef["FORMAT"] == "s" \
            and isinstance(headerfields[key][0], str):
                tempfields = []
                for _i in range(len(headerfields[key])):
                    tempfields.append(bytes(headerfields[key][_i]))
                headerfields[key] = tempfields
                del tempfields

    ## Retrieve PKG3 Unencrypted Data from data stream
    if function_debug_level >= 2:
        dprint("Get PKG3 remaining unencrypted data with size {}".format(headerfields["DATAOFS"]))
    unencrypted = headerbytes
    try:
        unencrypted.extend(DataStream.read(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], headerfields["DATAOFS"] - CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], function_debug_level))
    except:
        DataStream.close(function_debug_level)
        eprint("\nERROR: {}: Could not get PKG3 unencrypted data at offset {:#x} with size {} from {}".format(sys.argv[0], CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], headerfields["DATAOFS"] - CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], Source))
        sys.exit(2)

    ## Extract fields from PKG3 Extended Header
    extheaderfields = None
    mainhdrsize = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"] + CONST_PKG3_PS3_DIGEST_FIELDS["STRUCTURE_SIZE"]
    if "HDRSIZE" in headerfields \
    and headerfields["HDRSIZE"] > mainhdrsize:
        if function_debug_level >= 2:
            dprint(">>>>> PKG3 Extended Main Header:")
        tempfields = struct.unpack(CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_UNPACK"], headerbytes[mainhdrsize:mainhdrsize+CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_SIZE"]])
        ## --> Debug print all
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, tempfields, "PKG3 Extended Main Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

        ## Convert to dictionary (associative array)
        extheaderfields = convertFieldsToOrdDict(CONST_PKG3_EXT_HEADER_FIELDS, tempfields)
        del tempfields

    ## Determine key index for item entries plus path of PARAM.SFO
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Package Keys:")
    if headerfields["TYPE"] == 0x1:  ## PS3
        headerfields["KEYINDEX"] = 0
        headerfields["PARAM.SFO"] = "PARAM.SFO"
    elif headerfields["TYPE"] == 0x2:  ## PSX/PSP/PSV/PSM
        if extheaderfields:  ## PSV/PSM
            headerfields["KEYINDEX"] = extheaderfields["KEYID"] & 0xf
            if headerfields["KEYINDEX"] == 2:  ## PSV
                headerfields["PARAM.SFO"] = "sce_sys/param.sfo"
            elif headerfields["KEYINDEX"] == 3:  ## Unknown
                eprint("!!! PKG3 Key Index {}".format(headerfields["KEYINDEX"]))
        else:  ## PSX/PSP
            headerfields["KEYINDEX"] = 1
            headerfields["PARAM.SFO"] = "PARAM.SFO"
    else:
        eprint("!!! PKG3 Package Type {}".format(headerfields["TYPE"]))
    #
    headerfields["AES_CTR"] = {}
    for key in CONST_PKG3_CONTENT_KEYS:
        if function_debug_level >= 2:
            dprint("Content Key #{}: {}".format(key, convertBytesToHexString(CONST_PKG3_CONTENT_KEYS[key]["KEY"])))
        if "DERIVE" in CONST_PKG3_CONTENT_KEYS[key] \
        and CONST_PKG3_CONTENT_KEYS[key]["DERIVE"]:
            aes = AES.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], AES.MODE_ECB)
            pkg_key = aes.encrypt(headerfields["DATARIV"])
            ## Python 2 workaround: convert str to bytes
            if isinstance(pkg_key, str):
                pkg_key = bytes(pkg_key)
            headerfields["AES_CTR"][key] = PkgAesCtrCounter(pkg_key, headerfields["DATARIV"])
            del aes
            if function_debug_level >= 2:
                dprint("Derived Key #{} from IV encrypted with Content Key: {}".format(key, convertBytesToHexString(pkg_key)))
            del pkg_key
        else:
            headerfields["AES_CTR"][key] = PkgAesCtrCounter(CONST_PKG3_CONTENT_KEYS[key]["KEY"], headerfields["DATARIV"])

    ## Extract fields from PKG3 Main Header Meta Data
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Meta Data:")
    metadata = collections.OrderedDict()
    #
    md_type = -1
    md_size = -1
    md_offset = headerfields["MDOFS"]
    mdformatstring = "".join(("Metadata[{:", unicode(len(unicode(headerfields["MDCNT"]))), "}]: [{:#05x}|{:2}] ID {:#04x} ="))
    for _i in range(headerfields["MDCNT"]):  ## 0 to <meta data count - 1>
        md_type = getInteger32BitBE(unencrypted, md_offset)
        md_offset += 0x04
        #
        md_size = getInteger32BitBE(unencrypted, md_offset)
        md_offset += 0x04
        #
        tempbytes = unencrypted[md_offset:md_offset + md_size]
        if function_debug_level >= 2:
            dprint(mdformatstring.format(_i, md_offset, md_size, md_type), \
                   convertBytesToHexString(tempbytes))
        #
        metadata[md_type] = collections.OrderedDict()
        ## DRM Type (0x1), Content Type (0x2)
        if md_type == 0x01 \
        or md_type == 0x02:
            if md_type == 0x01:
                metadata[md_type]["DESC"] = "DRM Type"
            elif md_type == 0x02:
                metadata[md_type]["DESC"] = "Content Type"
            metadata[md_type]["VALUE"] = getInteger32BitBE(tempbytes, 0)
        ## TitleID (when size 0xc) (otherwise Version + App Version)
        elif md_type == 0x06 \
        and md_size == 0x0C:
            metadata[md_type]["DESC"] = "Title ID"
            metadata[md_type]["VALUE"] = convertUtf8BytesToString(tempbytes, 0x0204)
        ## (14) PARAM.SFO Info (PS Vita)
        ## (15) Unknown Info (PS Vita)
        ## (16) Entirety Info (PS Vita)
        elif md_type == 0x0E \
        or md_type == 0x0F \
        or md_type == 0x10 \
        or md_type == 0x12:
            if md_type == 0x0E:
                metadata[md_type]["DESC"] = "PARAM.SFO Info"
            elif md_type == 0x10:
                metadata[md_type]["DESC"] = "Entirety Info"
            elif md_type == 0x12:
                metadata[md_type]["DESC"] = "Self Info"
            metadata[md_type]["OFS"] = getInteger32BitBE(tempbytes, 0)
            metadata[md_type]["SIZE"] = getInteger32BitBE(tempbytes, 0x04)
            metadata[md_type]["UNKNOWN"] = bytes(tempbytes[0x08:md_size - 0x20])
            metadata[md_type]["SHA256"] = bytes(tempbytes[md_size - 0x20:])
        else:
            if md_type == 0x03:
                metadata[md_type]["DESC"] = "Package Type/Flags"
            elif md_type == 0x04:
                metadata[md_type]["DESC"] = "Package Size"
            elif md_type == 0x06:
                metadata[md_type]["DESC"] = "Version + App Version"
            elif md_type == 0x07:
                metadata[md_type]["DESC"] = "QA Digest"
            elif md_type == 0x0A:
                metadata[md_type]["DESC"] = "Install Directory"
            metadata[md_type]["VALUE"] = bytes(tempbytes)
        #
        md_offset += md_size
    #
    del tempbytes

    ## Debug print results
    dprint(">>>>> parsePkg3Header results:")
    dprintFieldsDict(headerfields, "headerfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    if extheaderfields:
        dprintFieldsDict(extheaderfields, "extheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsDict(metadata, "metadata[{KEY:#04x}]", function_debug_level, None)

    return headerfields, extheaderfields, metadata


def parsePkg3ItemEntries(headerfields):
    ## local debug level for fine-tuned analysis
    function_debug_level = 0  ## hard-coded minimum local debug level
    if function_debug_level < DebugLevel:
        function_debug_level = DebugLevel

    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entries:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Body

    ## Prepare format strings
    itemcntlen = unicode(len(unicode(headerfields["ITEMCNT"])))
    itemcntformatstring = "".join(("{:", itemcntlen, "}"))

    ## Retrieve PKG3 Item Entries from data stream
    item_entries_size = headerfields["ITEMCNT"] * CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG3 item entries from encrypted data with offset {:#x} with count {} and size {}".format(headerfields["DATAOFS"], headerfields["ITEMCNT"], item_entries_size))
    encrypted_bytes = bytearray()
    try:
        encrypted_bytes.extend(DataStream.read(headerfields["DATAOFS"], item_entries_size, function_debug_level))
    except:
        DataStream.close(function_debug_level)
        eprint("\nERROR: {}: Could not get PKG3 encrypted data at offset {:#x} with size {} from {}".format(sys.argv[0], headerfields["DATAOFS"], item_entries_size, Source))
        sys.exit(2)

    ## Decrypt PKG3 Item Entries
    tempbytes = headerfields["AES_CTR"][headerfields["KEYINDEX"]].decrypt(0, bytes(encrypted_bytes))
    del encrypted_bytes

    ## Parse PKG3 Item Entries
    itementries = []
    offset = 0
    name_offset_start = -1
    name_offset_end = -1
    #
    for _i in range(headerfields["ITEMCNT"]):  ## 0 to <item count - 1>
        tempfields = struct.unpack(CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_UNPACK"], tempbytes[offset:offset+CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, tempfields, "".join(("PKG3 Body Item Entry[", itemcntformatstring.format(_i),"][{:1}]: [", "{:#06x}+".format(headerfields["DATAOFS"] + offset), "{:#04x}|{:1}] {} = {}")), function_debug_level)
        tempfields = convertFieldsToOrdDict(CONST_PKG3_ITEM_ENTRY_FIELDS, tempfields)
        tempfields["INDEX"] = _i
        tempfields["KEYINDEX"] = ( tempfields["FLAGS"] >> 28 ) & 0x7
        itementries.append(tempfields)
        #
        if tempfields["ITEMNAMESIZE"] > 0:
            if name_offset_start == -1 \
            or tempfields["ITEMNAMEOFS"] < name_offset_start:
                name_offset_start = tempfields["ITEMNAMEOFS"]
            #
            if name_offset_end == -1 \
            or tempfields["ITEMNAMEOFS"] > name_offset_end:
                name_offset_end = tempfields["ITEMNAMEOFS"] + tempfields["ITEMNAMESIZE"]
        #
        del tempfields
        #
        offset += CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del tempbytes
    name_size = name_offset_end - name_offset_start + 1

    ## Retrieve PKG3 Item Names from data stream
    aligned_offset, aligned_size, aligned_offset_delta, aligned_size_delta = calculateAesAlignedOffsetAndSize(name_offset_start, name_offset_end - name_offset_start + 1)
    if function_debug_level >= 2:
        dprint("Get PKG3 item names from encrypted data with offset {:#x}(-{:#x}) and size {}(+{})".format(headerfields["DATAOFS"] + name_offset_start, aligned_offset_delta, name_size, aligned_size_delta))
    encrypted_bytes = bytearray()
    try:
        encrypted_bytes.extend(DataStream.read(headerfields["DATAOFS"] + aligned_offset, aligned_size, function_debug_level))
    except:
        DataStream.close(function_debug_level)
        eprint("\nERROR: {}: Could not get PKG3 encrypted data at offset {:#x} with size {} from {}".format(sys.argv[0], aligned_offset, aligned_size, Source))
        sys.exit(2)

    ## Decrypt and Parse PKG3 Item Names
    for _i in range(len(itementries)):  ## 0 to <item count - 1>
        item = itementries[_i]
        if item["ITEMNAMESIZE"] <= 0:
            continue
        #
        key_index = item["KEYINDEX"]
        aligned_offset, aligned_size, aligned_offset_delta, aligned_size_delta = calculateAesAlignedOffsetAndSize(item["ITEMNAMEOFS"], item["ITEMNAMESIZE"])
        offset = aligned_offset - name_offset_start
        #
        decrypted_bytes = headerfields["AES_CTR"][key_index].decrypt(aligned_offset, bytes(encrypted_bytes[offset:offset+aligned_size]))
        tempbytes = decrypted_bytes[aligned_offset_delta:aligned_offset_delta+item["ITEMNAMESIZE"]]
        del decrypted_bytes
        #if function_debug_level >= 3:
        #    dprint("".join(("PKG3 Body Item Name[", itemcntformatstring, "]: key {:#} with offset {:#x} {:#} {}")).format(_i, key_index, item["ITEMNAMEOFS"], item["ITEMNAMESIZE"], tempbytes))
        item["NAME"] = convertUtf8BytesToString(tempbytes, 0x0204)
        #
        del tempbytes
    #
    del encrypted_bytes

    ## Debug print results
    dprint(">>>>> parsePkg3ItemEntries results:")
    dprintFieldsList(itementries, "".join(("itementries[{KEY:", itemcntlen, "}]")), function_debug_level, None)

    return itementries


def retrievePkg3Item(headerfields, item):
    ## local debug level for fine-tuned analysis
    function_debug_level = 0  ## hard-coded minimum local debug level
    if function_debug_level < DebugLevel:
        function_debug_level = DebugLevel

    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entry #{} {}:".format(item["INDEX"], item["NAME"]))

    ## Retrieve PKG3 Item Data from data stream
    aligned_offset, aligned_size, aligned_offset_delta, aligned_size_delta = calculateAesAlignedOffsetAndSize(item["DATAOFS"], item["DATASIZE"])
    if function_debug_level >= 2:
        dprint("Get PKG3 item data from encrypted data with offset {:#x}(-{:#x}) and size {}(+{})".format(headerfields["DATAOFS"] + item["DATAOFS"], aligned_offset_delta, item["DATASIZE"], aligned_size_delta))
    encrypted_bytes = bytearray()
    try:
        encrypted_bytes.extend(DataStream.read(headerfields["DATAOFS"] + aligned_offset, aligned_size, function_debug_level))
    except:
        DataStream.close(function_debug_level)
        eprint("\nERROR: {}: Could not get PKG3 encrypted data at offset {:#x} with size {} from {}".format(sys.argv[0], aligned_offset, aligned_size, Source))
        sys.exit(2)

    ## Decrypt PKG3 Item Data
    decrypted_bytes = headerfields["AES_CTR"][item["KEYINDEX"]].decrypt(aligned_offset, bytes(encrypted_bytes))
    data_bytes = decrypted_bytes[aligned_offset_delta:aligned_offset_delta+item["DATASIZE"]]
    del encrypted_bytes
    del decrypted_bytes
    del aligned_offset, aligned_size, aligned_offset_delta, aligned_size_delta

    return data_bytes


def parseSfo(sfobytes):
    ## local debug level for fine-tuned analysis
    function_debug_level = 0  ## hard-coded minimum local debug level
    if function_debug_level < DebugLevel:
        function_debug_level = DebugLevel

    if function_debug_level >= 2:
        dprint(">>>>> SFO Header:")

    ## For definition see https://playstationdev.wiki/psvitadevwiki/index.php?title=System_File_Object_(SFO)_(PSF)

    ## Extract fields from SFO Header
    tempfields = struct.unpack(CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_UNPACK"], sfobytes[0:CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]])
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PARAM_SFO_HEADER_FIELDS, CONST_PARAM_SFO_ENDIAN, tempfields, "SFO Header[{:1}]: [{:#04x}|{:1}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    headerfields = convertFieldsToOrdDict(CONST_PARAM_SFO_HEADER_FIELDS, tempfields)
    del tempfields

    ## Retrieve SFO Index Table from sfo bytes
    if function_debug_level >= 2:
        dprint(">>>>> SFO Index Table:")
    sfo_index_table_size = headerfields["COUNT"] * CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get SFO index table from offset {:#x} with count {} and size {}".format(CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"], headerfields["COUNT"], sfo_index_table_size))
    tempbytes = sfobytes[CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]:CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]+sfo_index_table_size]
    sfovalues = collections.OrderedDict()

    ## Parse SFO Index Table Data
    cntformatstring = "".join(("{:", unicode(len(unicode(headerfields["COUNT"]))), "}"))
    formatstring = ""
    if function_debug_level >= 2:
        if function_debug_level >= 3:
            formatstring = "".join(("SFO Index Entry[", cntformatstring, "][^]: [^^^|^] {} = {}"))
        elif function_debug_level >= 2:
            formatstring = "".join(("SFO Index Entry[", cntformatstring, "]: {} = {}"))
    #
    offset = 0
    #
    for _i in range(headerfields["COUNT"]):  ## 0 to <count - 1>
        tempfields = struct.unpack(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_UNPACK"], tempbytes[offset:offset+CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 3:
            dprintBytesStructure(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, CONST_PARAM_SFO_ENDIAN, tempfields, "".join(("SFO Index Entry[", cntformatstring.format(_i),"][{:1}]: [{:#03x}|{:1}] {} = {}")), function_debug_level)
        tempfields = convertFieldsToOrdDict(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, tempfields)
        keyname = convertUtf8BytesToString(sfobytes[headerfields["KEYTBLOFS"]+tempfields["KEYOFS"]:], 0x0204)
        data = bytes(sfobytes[headerfields["DATATBLOFS"]+tempfields["DATAOFS"]:headerfields["DATATBLOFS"]+tempfields["DATAOFS"]+tempfields["DATAUSEDSIZE"]])
        if function_debug_level >= 2:
            dprint(formatstring.format(_i, "Key Name", keyname))
            datadesc = "Data Used (Fmt {:#0x})".format(tempfields["DATAFORMAT"])
            dprint(formatstring.format(_i, datadesc, convertBytesToHexString(data)))
        format = tempfields["DATAFORMAT"]
        if format == 0x0004 \
        or format == 0x0204:  ## UTF-8 not and NUL-terminated
            data = convertUtf8BytesToString(data, format)
            #
            if function_debug_level >= 2:
                datadesc = "UTF-8 String"
                dprint(formatstring.format(_i, datadesc, data))
            #
            if keyname == "STITLE" \
            or keyname[:7] == "STITLE_" \
            or keyname == "TITLE" \
            or ( keyname[:6] == "TITLE_" \
                 and keyname != "TITLE_ID" ):
                data = data.replace("\r\n", " ").replace("\n\r", " ")
                data = re.sub(r"\s", " ", data, 0, re.UNICODE).strip()  ## also replaces \u3000
        elif format == 0x0404:
            data = getInteger32BitLE(data, 0x00)
            #
            if function_debug_level >= 2:
                datadesc = "Integer"
                datadisplay = "{0} = {0:#x}".format(data)
                dprint(formatstring.format(_i, datadesc, datadisplay))
        #
        sfovalues[keyname] = data
        #
        del tempfields
        #
        offset += CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del tempbytes

    ## Debug print results
    dprint(">>>>> parseSfo results:")
    dprintFieldsDict(sfovalues, "sfovalues[{KEY:20}]", function_debug_level, None)

    return sfovalues


def showUsage():
    eprint("Usage: {} [options] <URL or path to PKG file> [<URL|PATH> ...]".format(sys.argv[0]))
    eprint("  -h/--help       Show this help")
    eprint("  -f/--format=<n> Format of output via code")
    eprint("                    0 = Generic output [default]")
    eprint("                    1 = sh env vars")
    eprint("  -d/--debug=<n>  Debug verbosity level")
    eprint("                    0 = No debug info [default]")
    eprint("                    1 = Show parsed results only")
    eprint("                    2 = Additionally show raw PKG and SFO data plus read actions")
    eprint("                    3 = Additionally show interim PKG and SFO data to get results")
    eprint("  -u/--unclean    Do not clean up international/english tile, except for condensing")
    eprint("                  multiple white spaces incl. new line to a single space.")
    eprint("                  Default is to clean up by replacing {}".format(ReplaceList))
    eprint("                  and condensing demo information to just \"(DEMO)\".")


## Global code
if __name__ == "__main__":
    try:
        ## Initialize (global) variables changeable by command line parameters
        ## Global Debug [Verbosity] Level: can be set via '-d'/'--debug='
        DebugLevel = 0
        ## Output Format: can be set via '-f'/'--format='
        OutputFormat = 0
        ReplaceList = [ ["™®☆◆", " "], ["—–", "-"], ]
        UncleanedTitle = False
        ExtractUnknown = False
        ExtractItemEntries = False
        ShowUsage = False
        ExitCode = 0

        ## Check parameters from command line
        try:
            Options, Arguments = getopt.gnu_getopt(sys.argv[1:], "hf:d:ux", ["help", "format=", "debug=", "unclean", "unknown", "itementries"])
        except getopt.GetoptError as err:
            ## Print help information and exit
            eprint(unicode(err))  ## will print something like "option -X not recognized"
            showUsage()
            sys.exit(2)
        #
        for Option, OptionValue in Options:
            if Option in ("-h", "--help"):
                ShowUsage = True
            elif Option in ("-u", "--unclean"):
                UncleanedTitle = True
            elif Option in ("--unknown"):
                ExtractUnknown = True
            elif Option in ("--itementries"):
                ExtractItemEntries = True
            elif Option in ("-f", "--format"):
                try:
                    OutputFormat = int(OptionValue)
                    if OutputFormat < 0:
                        eprint("Option {}: value {} is not valid".format(Option, OptionValue))
                        ExitCode = 2
                except:
                    eprint("Option {}: value {} is not a number".format(Option, OptionValue))
                    ExitCode = 2
            elif Option in ("-d", "--debug"):
                try:
                    DebugLevel = int(OptionValue)
                    if DebugLevel < 0:
                        eprint("Option {}: value {} is not valid".format(Option, OptionValue))
                        ExitCode = 2
                except:
                    eprint("Option {}: value {} is not a number".format(Option, OptionValue))
                    ExitCode = 2
            else:
                eprint("Option {} is unhandled in program".format(Option, OptionValue))
                ExitCode = 2
        #
        if not ShowUsage \
        and not Arguments:
            eprint("No paths or URLs stated")
            ExitCode = 2
        #
        if ShowUsage \
        or ExitCode:
            showUsage()
            sys.exit(ExitCode)

        ## Enrich structure format arrays
        ## --> PKG3 Main Header
        finalizeBytesStructure(CONST_PKG3_MAIN_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Main Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:12} = {}", DebugLevel)
        ## --> PKG3 PS3 0x40 Digest
        finalizeBytesStructure(CONST_PKG3_PS3_DIGEST_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 PS3 0x40 Digest", "{}[{:1}]: ofs {:#04x} size {:2} key {:12} = {}", DebugLevel)
        ## --> PKG3 Extended Header
        finalizeBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Ext Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:12} = {}", DebugLevel)
        ## --> PKG3 Item Entry
        finalizeBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Item Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", DebugLevel)
        ## --> PKG4 Main Header
        finalizeBytesStructure(CONST_PKG4_MAIN_HEADER_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 Main Header", "{}[{:2}]: ofs {:#05x} size {:3} key {:12} = {}", DebugLevel)
        ## --> PKG4 File Entry
        finalizeBytesStructure(CONST_PKG4_FILE_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 File Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", DebugLevel)
        ## --> PARAM.SFO Header
        finalizeBytesStructure(CONST_PARAM_SFO_HEADER_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Header", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", DebugLevel)
        ## --> PARAM.SFO Index Entry
        finalizeBytesStructure(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Index Entry", "{}[{:1}]: ofs {:#03x} size {:1} key {:12} = {}", DebugLevel)

        ## Process paths and URLs
        for Source in Arguments:
            ## Initialize per-file variables
            HeaderFields = None
            ExtHeaderFields = None
            MetaData = None
            RetrieveEncryptedParamSfo = False
            ItemEntries = None
            FileTable = None
            FileTableMap = None
            SfoBytes = None
            SfoValues = None
            #
            PkgContentId = ""
            PkgDrmType = -1
            PkgContentType = -1
            PkgTitleId = ""
            PkgSfoOffset = -1
            PkgSfoSize = -1
            PkgTotalSize = -1
            PkgMdType0A = False
            PkgMdType0B = False
            #
            SfoContentId = ""
            SfoTitleId = ""
            SfoMinVer = 0.00
            SfoCategory = ""
            SfoVersion = 0.00
            SfoAppVer = 0.00
            SfoSdkVer = 0.00
            SfoCreationDate = ""
            #
            SfoTitle = ""
            SfoTitleRegional = ""
            #
            NpsType = "UNKNOWN"
            #
            PsxTitleId = ""
            #
            ContentId = ""
            TitleId = ""
            Region = ""
            Languages = []

            ## If source is a JSON file then determine the first package url from it
            if Source.endswith(".json"):
                dprint(">>>>> JSON Source:", Source)
                if Source.startswith("http:") \
                or Source.startswith("https:"):
                    if DebugLevel >= 2:
                        dprint("Opening source as URL data stream")
                    try:
                        DataStream = requests.get(Source, headers={"User-Agent": "Download/1.00 libhttp/6.00 (PlayStation 4)"})
                    except:
                        eprint("\nERROR: {}: Could not open URL (1) {}".format(sys.argv[0], Source))
                        sys.exit(2)
                    StreamData = DataStream.json()
                else:
                    if DebugLevel >= 2:
                        dprint("Opening source as FILE data stream")
                    try:
                        DataStream = io.open(Source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    except:
                        eprint("\nERROR: {}: Could not open FILE {}".format(sys.argv[0], Source))
                        sys.exit(2)
                    StreamData = json.load(DataStream)
                    DataStream.close()

                ## Get PKG source from JSON data
                if not 'pieces' in StreamData \
                or not StreamData['pieces'][0] \
                or not 'url' in StreamData['pieces'][0]:
                    eprint("\nERROR: {}: JSON source does not look like PKG meta data (missing [pieces][0]) {}".format(sys.argv[0], Source))
                    sys.exit(2)

                Source = StreamData['pieces'][0]['url']

            ## Open PKG source
            if DebugLevel >= 1:
                dprint(">>>>>>>>>> PKG Source:", Source)
            DataStream = PkgReader(Source, DebugLevel)
            FileSize = DataStream.getSize(DebugLevel)
            if DebugLevel >= 2:
                dprint("File Size:", FileSize)

            ## Initialize headerbytes array
            dprint(">>>>> PKG Main Header:")
            HeaderBytes = bytearray()

            ## Get file magic code/string and check for GAME PKG file
            ## see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2
            ## see http://www.psdevwiki.com/ps4/PKG_files#File_Header
            HeaderBytes.extend(DataStream.read(0, 4, DebugLevel))
            PkgMagic = getInteger32BitBE(HeaderBytes, 0x00)
            #
            if PkgMagic == CONST_PKG3_MAGIC:
                HeaderSize = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                NpsType = "".join((NpsType, " (PS3/PSV/PSP/PSX/PSM)"))
                dprint("Detected PS3/PSV/PSP/PSX/PSM game package")
            elif PkgMagic == CONST_PKG4_MAGIC:
                HeaderSize = CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                NpsType = "".join((NpsType, " (PS4)"))
                dprint("Detected PS4 game package")
            else:
                DataStream.close(DebugLevel)
                eprint("\nERROR: {}: Not a known GAME PKG file ({:#x} <> {:#x}|{:#x}) {}".format(sys.argv[0], PkgMagic, CONST_PKG3_MAGIC, CONST_PKG4_MAGIC, Source))
                sys.exit(2)

            ## Get rest of PKG main header from data stream
            if DebugLevel >= 2:
                dprint("Get PKG main header from offset {:#x} with size {}".format(0, HeaderSize))
            HeaderBytes.extend(DataStream.read(4, HeaderSize - 4, DebugLevel))

            ## Process GAME PKG main header data
            ## --> PKG3
            if PkgMagic == CONST_PKG3_MAGIC:
                HeaderFields, ExtHeaderFields, MetaData = parsePkg3Header(HeaderBytes)
                ## --> Size of package (=file size)
                if "TOTALSIZE" in HeaderFields:
                    PkgTotalSize = HeaderFields["TOTALSIZE"]
                ## --> Package content id
                if "CID" in HeaderFields:
                    PkgContentId = HeaderFields["CID"]
                ## --> param.sfo offset + size
                if 0xE in MetaData:
                    PkgSfoOffset = MetaData[0xE]["OFS"]
                    PkgSfoSize = MetaData[0xE]["SIZE"]
                ## --> DRM Type
                if 0x1 in MetaData:
                    PkgDrmType = MetaData[0x1]["VALUE"]
                ## --> Content Type
                if 0x2 in MetaData:
                    PkgContentType = MetaData[0x2]["VALUE"]
                ## --> Title ID
                if 0x6 in MetaData:  ## Version + App Version / TitleID (on size 0xC)
                    PkgTitleId = MetaData[0x6]["VALUE"]
                ## --> Other flags for NPS Package Type
                if 0xA in MetaData:
                    PkgMdType0A = True
                if 0xB in MetaData:
                    PkgMdType0B = True
                ## If PARAM.SFO not present in unencrypted data, then search in encrypted item entries
                if PkgSfoOffset <= 0 \
                and "PARAM.SFO" in HeaderFields \
                and HeaderFields["PARAM.SFO"]:
                    RetrieveEncryptedParamSfo = True
                ## Process PKG3 encrypted item entries
                if not HeaderFields["KEYINDEX"] is None \
                and ( ExtractItemEntries \
                      or RetrieveEncryptedParamSfo ):
                    ItemEntries = parsePkg3ItemEntries(HeaderFields)
                    #
                    if RetrieveEncryptedParamSfo:
                        ## Find PARAM.SFO in encrypted item entries
                        for _i in range(len(ItemEntries)):
                            Item = ItemEntries[_i]
                            if "NAME" in Item \
                            and Item["NAME"] \
                            and Item["NAME"] == HeaderFields["PARAM.SFO"] \
                            and Item["DATASIZE"] > 0:
                                SfoBytes = retrievePkg3Item(HeaderFields, Item)
                                break
                        del Item
            ## --> PKG4
            elif PkgMagic == CONST_PKG4_MAGIC:
                HeaderFields, FileTable, FileTableMap = parsePkg4Header(HeaderBytes)
                ## --> Size of package (=file size)
                if "PKGSIZE" in HeaderFields:
                    PkgTotalSize = HeaderFields["PKGSIZE"]
                ## --> Package content id
                if "CID" in HeaderFields:
                    PkgContentId = HeaderFields["CID"]
                ## --> param.sfo offset + size
                if CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO in FileTableMap:
                    FileEntry = FileTable[FileTableMap[CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO]]
                    PkgSfoOffset = FileEntry["DATAOFS"]
                    PkgSfoSize = FileEntry["DATASIZE"]
                ## --> DRM Type
                if "DRMTYPE" in HeaderFields:
                    PkgDrmType = HeaderFields["DRMTYPE"]
                ## --> Content Type
                if "CONTTYPE" in HeaderFields:
                    PkgContentType = HeaderFields["CONTTYPE"]
            #
            if PkgTitleId and PkgTitleId.strip():
                TitleId = PkgTitleId.strip()
            #
            if PkgContentId and PkgContentId.strip():
                ContentId = PkgContentId.strip()
                if not (PkgTitleId and PkgTitleId.strip()):
                    TitleId = ContentId[7:16]

            ## Retrieve PARAM.SFO from unencrypted data if present
            if PkgSfoOffset > 0 \
            and not SfoBytes:
                if DebugLevel >= 2:
                    dprint(">>>>> PARAM.SFO:")
                ## Get PARAM.SFO from data stream
                if DebugLevel >= 2:
                    dprint("Get PARAM.SFO from offset {:#x} with size {}".format(PkgSfoOffset, PkgSfoSize))
                SfoBytes = bytearray()
                try:
                    SfoBytes.extend(DataStream.read(PkgSfoOffset, PkgSfoSize, DebugLevel))
                except:
                    DataStream.close(DebugLevel)
                    eprint("\nERROR: {}: Could not get PARAM.SFO at offset {:#x} with size {} from {}".format(sys.argv[0], PkgSfoOffset, PkgSfoSize, Source))
                    sys.exit(2)

            ## Process PARAM.SFO if present
            if SfoBytes:
                ## Check for known PARAM.SFO data
                SfoMagic = getInteger32BitLE(SfoBytes, 0)
                if SfoMagic != 0x46535000:
                    DataStream.close(DebugLevel)
                    eprint("\nERROR: {}: Not a known PARAM.SFO structure ({:#x} <> 0x46535000) {}".format(sys.argv[0], SfoMagic, Source))
                    sys.exit(2)

                ## Process PARAM.SFO data
                SfoValues = parseSfo(SfoBytes)
                ## -->
                if "TITLE_ID" in SfoValues:
                    SfoTitleId = SfoValues["TITLE_ID"]
                ## -->
                if "CONTENT_ID" in SfoValues:
                    SfoContentId = SfoValues["CONTENT_ID"]
                ## -->
                if "PS3_SYSTEM_VER" in SfoValues:
                    SfoMinVer = float(SfoValues["PS3_SYSTEM_VER"])
                ## -->
                if "PSP2_DISP_VER" in SfoValues:
                    SfoMinVer = float(SfoValues["PSP2_DISP_VER"])
                ## -->
                if "CATEGORY" in SfoValues:
                    SfoCategory = SfoValues["CATEGORY"]
                ## -->
                if "VERSION" in SfoValues:
                    SfoVersion = float(SfoValues["VERSION"])
                ## -->
                if "APP_VER" in SfoValues:
                    SfoAppVer = float(SfoValues["APP_VER"])
                ## -->
                if "PUBTOOLINFO" in SfoValues:
                    try:
                        SfoSdkVer = int(SfoValues["PUBTOOLINFO"][24:32]) / 1000000
                        SfoCreationDate = SfoValues["PUBTOOLINFO"][7:15]
                    except:
                        pass
                #
                if SfoTitleId and SfoTitleId.strip():
                    TitleId = SfoTitleId.strip()
                #
                if SfoContentId and SfoContentId.strip():
                    ContentId = SfoContentId.strip()
                    if not (SfoTitleId and SfoTitleId.strip()):
                        TitleId = ContentId[7:16]

            ## Close data stream
            DataStream.close(DebugLevel)

            ## Determine some derived variables
            ## a) Region and related languages
            if ContentId and ContentId.strip():
                Region, Languages = getRegion(ContentId[0])
            ## b) International/English title
            SfoTitle = ""
            for Language in [ "01", "18" ]:
                Key = "TITLE_" + Language
                if SfoValues \
                and Key in SfoValues:
                   if DebugLevel >= 2:
                       dprint("Set international name to", Key)
                   SfoTitle = SfoValues[Key].strip()
                   break
            if not SfoTitle \
            and SfoValues \
            and "TITLE" in SfoValues \
            and SfoValues["TITLE"] \
            and SfoValues["TITLE"].strip():
                if DebugLevel >= 2:
                    dprint("Set international title to TITLE")
                SfoTitle = SfoValues["TITLE"].strip()
            ## --> Clean international/english title
            if SfoTitle \
            and not UncleanedTitle:
                if ReplaceList:
                    for ReplaceChars in ReplaceList:
                        if DebugLevel >= 2:
                            dprint("Clean international title from", ReplaceChars[0])
                        for _i in range(len(ReplaceChars[0])):
                            ReplaceChar = ReplaceChars[0][_i]
                            if ReplaceChars[1] == " ":
                                SfoTitle = SfoTitle.replace(ReplaceChar + ":", ":")
                            SfoTitle = SfoTitle.replace(ReplaceChar, ReplaceChars[1])
                SfoTitle = re.sub(r"\s+", " ", SfoTitle, 0, re.UNICODE).strip()  ## also replaces \u3000
                ## Condense demo information in title to "(DEMO)"
                SfoTitle = SfoTitle.replace("demo ver.", "(DEMO)").replace("Demo Version", "(DEMO)").replace("Demo version", "(DEMO)").replace("DEMO Version", "(DEMO)").replace("DEMO version", "(DEMO)").replace("【体験版】", "(DEMO)").replace("(体験版)", "(DEMO)").replace("体験版", "(DEMO)").strip()
                SfoTitle = re.sub(r"\(demo\)", r"(DEMO)", SfoTitle, 0, re.IGNORECASE|re.UNICODE)
                SfoTitle = re.sub(r"(^|[^a-z(]{1})demo([^a-z)]{1}|$)", r"\1(DEMO)\2", SfoTitle, 0, re.IGNORECASE|re.UNICODE)
            ## c) Regional title
            SfoTitleRegional = ""
            for Language in Languages:
                Key = "TITLE_" + Language
                if SfoValues \
                and Key in SfoValues:
                   if DebugLevel >= 2:
                       dprint("Set regional title to", Key)
                   SfoTitleRegional = SfoValues[Key].strip()
                   break
            if not SfoTitleRegional \
            and SfoValues \
            and "TITLE" in SfoValues \
            and SfoValues["TITLE"] \
            and SfoValues["TITLE"].strip():
                if DebugLevel >= 2:
                    dprint("Set regional title to TITLE")
                SfoTitleRegional = SfoValues["TITLE"].strip()
            ## --> Clean regional title
            if SfoTitleRegional \
            and not UncleanedTitle:
                if ReplaceList:
                    for ReplaceChars in ReplaceList:
                        if DebugLevel >= 2:
                            dprint("Clean regional title from", ReplaceChars[0])
                        for _i in range(len(ReplaceChars[0])):
                            ReplaceChar = ReplaceChars[0][_i]
                            if ReplaceChars[1] == " ":
                                SfoTitleRegional = SfoTitleRegional.replace(ReplaceChar + ":", ":")
                            SfoTitleRegional = SfoTitleRegional.replace(ReplaceChar, ReplaceChars[1])
                SfoTitleRegional = re.sub(r"\s+", " ", SfoTitleRegional, 0, re.UNICODE).strip()  ## also replaces \u3000

            ## Determine NPS package type from data
            if PkgContentType == 0x1 \
            or PkgContentType == 0x6:
                NpsType = "PSX GAME"  #md_type = 9
                if PkgContentType == 0x6:
                    PsxTitleId = HeaderBytes[712:721].decode("utf-8", errors="ignore")
            elif PkgContentType == 0x4 \
            or PkgContentType == 0xB:
                if PkgMdType0B == True:
                    NpsType = "PS3 UPDATE"
                else:
                    NpsType = "PS3 DLC"  #md_type = 9 | Also PS3 updates : md_type = 11
            elif PkgContentType == 0x5:
                NpsType = "PS3 GAME"  #md_type = 5
            elif PkgContentType == 0x7:
                if PkgMdType0B == True:
                    NpsType = "PSP DLC"
                else:
                    NpsType = "PSP GAME"  #md_type = 9 | Also PSP DLCS : md_type = 10
            elif PkgContentType == 0x9:
                NpsType = "PSP or PS3 THEME"  #md_type = 9 | Also PS3 THEMES : md_type = 9
            elif PkgContentType == 0xD:
                NpsType = "PS3 AVATAR"  #md_type = 9
            elif PkgContentType == 0x15:
                NpsType = "VITA APP"  #md_type = 18
                if SfoCategory == "gp":
                    NpsType = "VITA UPDATE"
            elif PkgContentType == 0x16:
                NpsType = "VITA DLC"  #md_type = 17
            elif PkgContentType == 0x1F:
                NpsType = "VITA THEME"  #md_type = 17
            elif PkgContentType == 0x18:
        	    NpsType = "PSM GAME"  #md_type = 16
            else:
                eprint("\nERROR: PKG content type {0}/{0:#0x} not supported. {1}".format(PkgContentType, Source))

            if OutputFormat == 1:  ## Shell Variable Output
                print("PSN_PKG_SIZE='{}'".format(PkgTotalSize))
                print("PSN_PKG_NPS_TYPE='{}'".format(NpsType))
                if TitleId and TitleId.strip():
                    print("PSN_PKG_TITLEID='{}'".format(TitleId))
                else:
                    print("unset PSN_PKG_TITLEID")
                if ContentId and ContentId.strip():
                    print("PSN_PKG_CONTENTID='{}'".format(ContentId))
                    print("PSN_PKG_REGION='{}'".format(Region.replace("(HKG)","").replace("(KOR)","")))
                else:
                    print("unset PSN_PKG_CONTENTID")
                    print("unset PSN_PKG_REGION")
                if SfoTitle:
                    print("PSN_PKG_SFO_TITLE=\"\\\"{}\\\"\"".format(SfoTitle.replace("\"", "\\\"\\\"")))
                else:
                    print("unset PSN_PKG_SFO_TITLE")
                if SfoTitleRegional:
                    print("PSN_PKG_SFO_TITLE_REGION=\"\\\"{}\\\"\"".format(SfoTitleRegional.replace("\"", "\\\"\\\"")))
                else:
                    print("unset PSN_PKG_SFO_TITLE_REGION")
                if SfoMinVer >= 0:
                    print("PSN_PKG_SFO_FW_VER='{:.2f}'".format(SfoMinVer))
                else:
                    print("unset PSN_PKG_SFO_FW_VER")
                if SfoVersion >= 0:
                    print("PSN_PKG_SFO_VERSION='{:.2f}'".format(SfoVersion))
                else:
                    print("unset PSN_PKG_SFO_VERSION")
                if SfoAppVer >= 0:
                    print("PSN_PKG_SFO_APP_VER='{:.2f}'".format(SfoAppVer))
                else:
                    print("unset PSN_PKG_SFO_APP_VER")
                if SfoSdkVer >= 0:
                    print("PSN_PKG_SFO_SDK_VER='{:.2f}'".format(SfoSdkVer))
                else:
                    print("unset PSN_PKG_SFO_SDK_VER")
                if SfoCategory and SfoCategory.strip():
                    print("PSN_PKG_SFO_CATEGORY='{}'".format(SfoCategory))
                else:
                    print("unset PSN_PKG_SFO_CATEGORY")
                if SfoCreationDate and SfoCreationDate.strip():
                    print("PSN_PKG_SFO_CREATION='{}'".format(SfoCreationDate))
                else:
                    print("unset PSN_PKG_SFO_CREATION")
                if PsxTitleId and PsxTitleId.strip():
                    print("PSN_PKG_PSXTITLEID='{}'".format(PsxTitleId))
                else:
                    print("unset PSN_PKG_PSXTITLEID")
                if FileSize:
                    print("PSN_PKG_FILESIZE='{}'".format(FileSize))
                else:
                    print("unset PSN_PKG_FILESIZE")
            elif OutputFormat == 99:  ## Analysis Output
                print(">>> PKG Source:", Source)
                print("File Size:", FileSize)
                if PkgMagic == CONST_PKG3_MAGIC:
                    dprintFieldsDict(HeaderFields, "headerfields[{KEY:14}|{INDEX:2}]", 2, None, print)
                    if ExtHeaderFields:
                        dprintFieldsDict(ExtHeaderFields, "extheaderfields[{KEY:14}|{INDEX:2}]", 2, None, print)
                    dprintFieldsDict(MetaData, "metadata[{KEY:#04x}]", 2, None, print)
                    if ItemEntries:
                        FormatString = "".join(("{:", unicode(len(unicode(HeaderFields["ITEMCNT"]))), "}"))
                        for _i in range(len(ItemEntries)):
                            print("".join(("itementries[", FormatString, "]: Ofs {:#012x} Size {:12} Key Index {} {}")).format(_i, ItemEntries[_i]["DATAOFS"], ItemEntries[_i]["DATASIZE"], ItemEntries[_i]["KEYINDEX"],"".join(("Name \"", ItemEntries[_i]["NAME"], "\"")) if "NAME" in ItemEntries[_i] else ""))
                elif PkgMagic == CONST_PKG4_MAGIC:
                    dprintFieldsDict(HeaderFields, "headerfields[{KEY:14}|{INDEX:2}]", 2, None, print)
                    FormatString = "".join(("{:", unicode(len(unicode(HeaderFields["FILECNT"]))), "}"))
                    for _i in range(len(FileTable)):
                        print("".join(("filetable[", FormatString, "]: ID {:#06x} Ofs {:#012x} Size {:12} {}")).format(_i, FileTable[_i]["FILEID"], FileTable[_i]["DATAOFS"], FileTable[_i]["DATASIZE"], "".join(("Name \"", FileTable[_i]["NAME"], "\"")) if "NAME" in FileTable[_i] else ""))
                    dprintFieldsDict(FileTableMap, "filetablemap[{KEY:#06x}]", 2, None, print)
                if SfoValues:
                    dprintFieldsDict(SfoValues, "sfovalues[{KEY:20}]", 2, None, print)
            else:  ## Generic Human Output
                print("\n")
                print("{:13} {}".format("NPS Type:", NpsType))
                if TitleId and TitleId.strip():
                    print("{:13} {}".format("Title ID:", TitleId))
                if SfoTitle:
                    print("{:13} {}".format("Title:", SfoTitle))
                if SfoTitleRegional:
                    print("{:13} {}".format("Title Region:", SfoTitleRegional))
                if ContentId and ContentId.strip():
                    print("{:13} {}".format("Region:", Region))
                if SfoMinVer >= 0:
                    print("{:13} {:.2f}".format("Min FW:", SfoMinVer))
                if SfoSdkVer >= 0:
                    print("{:13} {:.2f}".format("SDK Ver:", SfoSdkVer))
                if SfoCreationDate and SfoCreationDate.strip():
                    print("{:13} {}".format("c_date:", datetime.strptime(SfoCreationDate, "%Y%m%d").strftime("%Y.%m.%d")))
                if SfoVersion >= 0:
                    print("{:13} {:.2f}".format("Version:", SfoVersion))
                if SfoAppVer >= 0:
                    print("{:13} {:.2f}".format("App Ver:", SfoAppVer))
                if PsxTitleId and PsxTitleId.strip():
                    print("{:13} {}".format("PSX Title ID:", PsxTitleId))
                if ContentId and ContentId.strip():
                    print("{:13} {}".format("Content ID:", ContentId))
                    if SfoContentId and SfoContentId.strip() \
                    and PkgContentId.strip() != SfoContentId.strip():
                        print("{:13} {}".format("PKG Hdr CID:", PkgContentId))
                print("{:13} {}".format("Size:", PkgTotalSize))
                print("{:13} {}".format("Pretty Size:", prettySize(PkgTotalSize)))
                if FileSize:
                    print("{:13} {}".format("File Size:", FileSize))
                print("\n")
    except:
        print_exc_plus()
