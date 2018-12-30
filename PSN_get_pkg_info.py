#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PSN_get_pky_info.py (c) 2018 by "windsurfer1122"
### Extract package information from header and PARAM.SFO of PS3/PSX/PSP/PSV/PSM and PS4 packages.
### Use at your own risk!
###
### For options execute: PSN_get_pkg_info.py -h
###
### git master repository at https://github.com/windsurfer1122
### Read README.md for more information including Python requirements and more
###
### Python 2 backward-compatible workarounds:
### - handle prefix in kwargs manually
### - set system default encoding to UTF-8
### - define unicode() for Python 3 like in Python 2 (ugly)
### - convert byte string of struct.pack() to bytes
###
### Adopted PEP8 Coding Style: (see https://www.python.org/dev/peps/pep-0008/)
### * (differs to PEP8) Studly_Caps_With_Underscores for global variables
### * (differs to PEP8) mixedCase for functions, methods
### * lower_case_with_underscores for attributes, variables
### * UPPER_CASE_WITH_UNDERSCORES for constants
### * StudlyCaps for classes
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

### Python 2 future-compatible workarounds: (see: http://python-future.org/compatible_idioms.html)
## a) prevent interpreting print(a,b) as a tuple plus support print(a, file=sys.stderr)
from __future__ import print_function
## b) interpret all literals as unicode
from __future__ import unicode_literals
## c) same division handling ( / = float, // = integer)
from __future__ import division
## d) interpret long as int, support int.from_bytes()
from builtins import int
## e) support bytes()
from builtins import bytes


## Version definition
__version__ = "2018.12.31a3"
__author__ = "https://github.com/windsurfer1122/PSN_get_pkg_info"
__license__ = "GPL"
__copyright__ = "Copyright 2018, windsurfer1122"


## Imports
import sys
import struct
import io
import requests
import collections
import locale
import os
import argparse
import re
import traceback
import json
import random
import aenum
import copy

import Cryptodome.Cipher.AES
import Cryptodome.Util.Counter
import Cryptodome.Hash

from math import log
from datetime import datetime


## Debug level for Python initializations (will be reset in "main" code)
Debug_Level = 0


## Error and Debug print to stderr
## https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):  ## error print
    ## Python 2 workaround: handle prefix in kwargs manually
    #def eprint(*args, prefix="[ERROR] ", **kwargs):  ## Python 3 only
    if "prefix" in kwargs:
        prefix = kwargs["prefix"]
        del kwargs["prefix"]
    else:
        prefix="[ERROR] "
    #
    if not prefix is None \
    and prefix != "":
        print(prefix, file=sys.stderr, end="")
    print(*args, file=sys.stderr, **kwargs)

def dprint(*args, **kwargs):  ## debug print
    if Debug_Level:
        ## Python 2 workaround: handle prefix in kwargs manually
        #def dprint(*args, prefix="[debug] ", **kwargs):  ## Python 3 only
        if "prefix" in kwargs:
            prefix = kwargs["prefix"]
            del kwargs["prefix"]
        else:
            prefix="[debug] "
        #
        if not prefix is None \
        and prefix != "":
            print(prefix, file=sys.stderr, end="")
        print(*args, file=sys.stderr, **kwargs)


## Enhanced TraceBack
## http://code.activestate.com/recipes/52215-get-more-information-from-tracebacks/
## https://stackoverflow.com/questions/27674602/hide-traceback-unless-a-debug-flag-is-set
def print_exc_plus():
    """
    Print the usual traceback information, followed by a listing of
    important variables in each frame.
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
                eprint(value, prefix=None)
            except:
                eprint("<ERROR WHILE PRINTING VALUE>", prefix=None)

    traceback.print_exc()


## General debug information related to Python
if Debug_Level >= 1:
    dprint("Python Version", sys.version)

## Python 2/Windows workaround: set system default encoding to UTF-8 like in Python 3
## All results will be Unicode and we want all output to be UTF-8
try:
    reload
except NameError:
    ## Python 3.4+
    from importlib import reload
reload(sys)
if sys.getdefaultencoding().lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("Default Encoding setting from {} to UTF-8".format(sys.getdefaultencoding()))
    sys.setdefaultencoding("utf-8")
if sys.stdout.encoding \
and sys.stdout.encoding.lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("STDOUT Encoding setting from {} to UTF-8".format(sys.stdout.encoding))
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding \
and sys.stderr.encoding.lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("STDERR Encoding setting from {} to UTF-8".format(sys.stderr.encoding))
    sys.stderr.reconfigure(encoding='utf-8')

## General debug information related to Unicode
if Debug_Level >= 1:
    ## List encodings
    dprint("DEFAULT Encoding", sys.getdefaultencoding())
    dprint("LOCALE Encoding", locale.getpreferredencoding())
    dprint("STDOUT Encoding {} Terminal {}".format(sys.stdout.encoding, sys.stdout.isatty()))
    dprint("STDERR Encoding {} Terminal {}".format(sys.stderr.encoding, sys.stderr.isatty()))
    dprint("FILESYS Encoding", sys.getfilesystemencoding())
    value = ""
    if "PYTHONIOENCODING" in os.environ:
        value = os.environ["PYTHONIOENCODING"]
    dprint("PYTHONIOENCODING=", value, sep="")
    ## Check Unicode
    dprint("ö ☺ ☻")

## Python 2/3 workaround: define unicode for Python 3 like in Python 2
## Unfortunately a backward-compatible workaround, as I couldn't find a forward-compatible one :(
## Every string is Unicode
## https://stackoverflow.com/questions/34803467/unexpected-exception-name-basestring-is-not-defined-when-invoking-ansible2
try:
    unicode
except:
    if Debug_Level >= 1:
        dprint("Define \"unicode = str\" for Python 3 :(")
    unicode = str


## Generic definitions
OUTPUT_FORMATS = collections.OrderedDict([ \
   ( 0, "Human-readable reduced Output [default]" ),
   ( 1, "Linux Shell Variable Output" ),
   ( 2, "Results Output" ),
   ( 3, "Results Output in JSON format" ),
   ( 98, "Analysis Output in JSON format" ),
   ( 99, "Analysis Output" ),
])
#
CONST_FMT_BIG_ENDIAN = ">"
CONST_FMT_LITTLE_ENDIAN = "<"
CONST_FMT_UINT64, CONST_FMT_UINT32, CONST_FMT_UINT16, CONST_FMT_UINT8 = 'Q', 'L', 'H', 'B'
CONST_FMT_INT64, CONST_FMT_INT32, CONST_FMT_INT16, CONST_FMT_INT8 = 'q', 'l', 'h', 'b'
#
CONST_READ_SIZE = random.randint(50,100) * 0x100000  ## Read in 50-100 MiB chunks to reduce memory usage and swapping

## Generic PKG definitions
CONST_CONTENT_ID_SIZE = 0x24
CONST_SHA256_HASH_SIZE = 0x20
#
## --> Platforms
class CONST_PLATFORM(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = 'PS3 PSX PSP PSV PSM PS4'
    PS3 = "PS3"
    PSX = "PSX"
    PSP = "PSP"
    PSV = "VITA"
    PSM = "PSM"
    PS4 = "PS4"
## --> Package Types
class CONST_PKG_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = 'GAME DLC PATCH THEME AVATAR'
    GAME = "Game"
    DLC = "DLC"
    PATCH = "Update"
    THEME = "Theme"
    AVATAR = "Avatar"
## --> Package Sub Types
class CONST_PKG_SUB_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = 'PSP_PC_ENGINE PSP_GO PSP_MINI PSP_NEOGEO'
    PSP_PC_ENGINE = "PC Engine"
    PSP_GO = "Go"
    PSP_MINI = "PSP Mini"
    PSP_NEOGEO = "PSP NeoGeo"

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
    ( "DIGEST",    { "FORMAT": "s", "SIZE": 16, "DEBUG": 1, "DESC": "Digest", "SEP": "", }, ),
    ( "DATARIV",   { "FORMAT": "s", "SIZE": 16, "DEBUG": 1, "DESC": "Data RIV", "SEP": "", }, ),
    #
    ( "KEYINDEX",  { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Key Index for Decryption of Item Entries Table", }, ),
    ( "PARAM.SFO", { "VIRTUAL": -1, "DEBUG": 1, "DESC": "PARAM.SFO Item Name", }, ),
    ( "MDSIZE",    { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Meta Data Size", }, ),
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
## --> PKG Update Keys
CONST_PKG3_UPDATE_KEYS = {
   2: { "KEY": bytes.fromhex("e5e278aa1ee34082a088279c83f9bbc806821c52f2ab5d2b4abd995450355114"), "DESC": "PSV", },
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
for Count in range(0x1f):
    Key = 0x1201 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "icon0_{:02}.png".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1241-0x125f: pic1_<nn>.png
for Count in range(0x1f):
    Key = 0x1241 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "pic1_{:02}.png".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1261-0x127f: pic1_<nn>.png
for Count in range(0x1f):
    Key = 0x1261 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "changeinfo/changeinfo_{:02}.xml".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1281-0x129f: icon0_<nn>.dds
for Count in range(0x1f):
    Key = 0x1281 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "icon0_{:02}.dds".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x12c1-0x12df: pic1_<nn>.dds
for Count in range(0x1f):
    Key = 0x12c1 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "pic1_{:02}.dds".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1400-0x1463: trophy/trophy<nn>.dds
for Count in range(0x64):
    Key = 0x1400 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "trophy/trophy{:02}.trp".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1600-0x1609: keymap_rp/<nn>.png
for Count in range(0x0a):
    Key = 0x1600 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "keymap_rp/{:03}.png".format(Count)
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))
#
## 0x1610-0x17f9: keymap_rp/<nn>/<nnn>.png
for Count in range(0x01ea):
    Key = 0x1610 + Count
    CONST_PKG4_FILE_ENTRY_NAME_MAP[Key] = "keymap_rp/{:02}/{:03}.png".format(Count >> 4, Count & 0xf )
    if Debug_Level >= 2:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_FILE_ENTRY_NAME_MAP[Key]))

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


def specialToJSON(python_object):
    if isinstance(python_object, bytes):
        return {'__class__': 'bytes',
                '__value__': convertBytesToHexString(python_object, sep="")}
    if isinstance(python_object, PkgAesCtrCounter):
        return ""
    raise TypeError("".join((repr(python_object), " is not JSON serializable")))

def convertBytesToHexString(data, format="", sep=" "):
    if isinstance(data, int):
        data = struct.pack(format, data)
    ## Python 2 workaround: convert str to bytes
    if isinstance(data, str):
        data = bytes(data)
    #
    return sep.join(["%02x" % b for b in data])


def calculateAesAlignedOffsetAndSize(offset, size):
    align = {}

    align["OFSDELTA"] = offset & (Cryptodome.Cipher.AES.block_size - 1)
    align["OFS"] = offset - align["OFSDELTA"]

    align["SIZEDELTA"] = (align["OFSDELTA"] + size) & (Cryptodome.Cipher.AES.block_size - 1)
    if align["SIZEDELTA"] > 0:
        align["SIZEDELTA"] = Cryptodome.Cipher.AES.block_size - align["SIZEDELTA"]
    align["SIZEDELTA"] += align["OFSDELTA"]
    align["SIZE"] = size + align["SIZEDELTA"]

    return align


class PkgReader():
    def __init__(self, source, headers, debug_level=0):
        self._source = source
        self._size = None

        if self._source.startswith("http:") \
        or self._source.startswith("https:"):
            if debug_level >= 2:
                dprint("Opening source as URL data stream")
            self._stream_type = "requests"
            self._pkg_name = os.path.basename(requests.utils.urlparse(self._source).path)
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            try:
                self._data_stream = requests.Session()
            except:
                eprint("Could not create HTTP/S session for PKG URL", self._source)
                eprint("", prefix=None)
                sys.exit(2)
            self._data_stream.headers = headers
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
            self._pkg_name = os.path.basename(self._source)
            try:
                self._data_stream = io.open(self._source, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("Could not open PKG FILE", self._source)
                eprint("", prefix=None)
                sys.exit(2)
            #
            self._data_stream.seek(0, os.SEEK_END)
            self._size = self._data_stream.tell()

        if debug_level >= 3:
            dprint("Data stream is of class", self._data_stream.__class__.__name__)

    def getSize(self, debug_level=0):
        return self._size

    def getSource(self, debug_level=0):
        return self._source

    def getPkgName(self, debug_level=0):
        return self._pkg_name

    def read(self, offset, size, debug_level=0):
        if self._stream_type == "file":
            self._data_stream.seek(offset, os.SEEK_SET)
            return self._data_stream.read(size)
        elif self._stream_type == "requests":
            ## Send request in persistent session
            ## http://docs.python-requests.org/en/master/api/#requests.Session.get
            ## http://docs.python-requests.org/en/master/api/#requests.request
            reqheaders={"Range": "bytes={}-{}".format(offset, (offset + size - 1) if size > 0 else "")}
            response = self._data_stream.get(self._source, headers=reqheaders)
            return response.content

    def close(self, debug_level=0):
        return self._data_stream.close()


class PkgAesCtrCounter():
    def __init__(self, key, iv):
        self._key = key
        self._key_size = Cryptodome.Cipher.AES.key_size[0] * 8  ## Key length 16 bytes = 128 bits
        if isinstance(iv, int):
            self._iv = iv
        elif isinstance(iv, bytes) \
        or isinstance(iv, bytearray):
            self._iv = int.from_bytes(iv, byteorder="big")
        self._block_offset = -1

    def _setOffset(self, offset):
        if offset == self._block_offset:
            return
        #
        start_counter = self._iv
        self._block_offset = 0
        count = offset // Cryptodome.Cipher.AES.block_size
        if count > 0:
            start_counter += count
            self._block_offset += count * Cryptodome.Cipher.AES.block_size
        #
        if hasattr(self, "_aes"):
            del self._aes
        counter = Cryptodome.Util.Counter.new(self._key_size, initial_value=start_counter)
        self._aes = Cryptodome.Cipher.AES.new(self._key, Cryptodome.Cipher.AES.MODE_CTR, counter=counter)

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
        return "ASIA", ["09", "11", "10", "00"]
    elif id == "E":
        return "EU", ["01", "18"]
    elif id == "H":
        return "ASIA(HKG)", ["11", "10"]
    elif id == "I":
        return "INT", ["01", "18"]
    elif id == "J":
        return "JP", ["00"]
    elif id == "K":
        return "ASIA(KOR)", ["09"]
    elif id == "U":
        return "US", ["01"]
    else:
        return "???", None


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


def dprintBytesStructure(CONST_STRUCTURE_FIELDS, CONST_STRUCTURE_ENDIAN, temp_fields, format_string, parent_debug_level):
    for key in CONST_STRUCTURE_FIELDS:
        if key == "STRUCTURE_SIZE" \
        or key == "STRUCTURE_UNPACK":
            continue
        #
        field_def = CONST_STRUCTURE_FIELDS[key]
        #
        if "VIRTUAL" in field_def \
        and field_def["VIRTUAL"]:
            continue
        #
        field_debug_level = 1
        if "DEBUG" in field_def:
            field_debug_level = field_def["DEBUG"]
        #
        if parent_debug_level >= field_debug_level:
            field_format = field_def["FORMAT"]
            if "SEP" in field_def:
                sep = field_def["SEP"]
            else:
                sep = " "
            output = format_string.format(field_def["INDEX"], field_def["OFFSET"], field_def["SIZE"], field_def["DESC"], convertBytesToHexString(temp_fields[field_def["INDEX"]], format="".join((CONST_STRUCTURE_ENDIAN, field_format)), sep=sep))
            #
            if "CONV" in field_def:
                if field_def["CONV"] == 0x0004 \
                or field_def["CONV"] == 0x0204:  ## UTF-8 not and NUL-terminated
                    value = convertUtf8BytesToString(temp_fields[field_def["INDEX"]], field_def["CONV"])
                    output = "".join((output, " => ", value))
            elif CONST_STRUCTURE_ENDIAN == CONST_FMT_LITTLE_ENDIAN \
            and (field_format == "L" \
                 or field_format == "H" \
                 or field_format == "Q") :
                output = "".join((output, " => ", convertBytesToHexString(temp_fields[field_def["INDEX"]], format="".join((CONST_FMT_BIG_ENDIAN, field_format)), sep=sep)))
            #
            dprint(output)


def dprintField(key, field, field_def, format_string, parent_debug_level, parent_prefix, print_func=dprint, sep=" "):
    if isinstance(key, unicode):
        key = "".join(("\"", key, "\""))
    if parent_prefix is None:
        format_values = {}
        format_values["KEY"] = key
        if field_def:
            format_values["INDEX"] = field_def["INDEX"]
            format_values["DESC"] = field_def["DESC"]
        prefix = format_string.format(**format_values)
    else:
        prefix = "".join((parent_prefix, "[", format_string.format(key), "]"))
    #
    if isinstance(field, list) \
    or isinstance(field, tuple):  ## indexed list
        dprintFieldsList(field, format_string, parent_debug_level, prefix, print_func=print_func, sep=sep)
    elif isinstance(field, dict):  ## dictionary
        dprintFieldsDict(field, format_string, parent_debug_level, prefix, print_func=print_func, sep=sep)
    else:
        if isinstance(field, int):
            value = "{0} = {0:#x}".format(field)
        elif isinstance(field, bytes) \
        or isinstance(field, bytearray):
            if field_def \
            and "SEP" in field_def:
                sep = field_def["SEP"]
            value = convertBytesToHexString(field, sep=sep)
        else:
            value = field
        #
        print_func("".join((prefix, ":")), value)

def dprintFieldsList(fields, format_string, parent_debug_level, parent_prefix, print_func=dprint, sep=" "):
    length = len(fields)
    #
    if parent_prefix:
        format_string = "".join(("{:", unicode(len(unicode(length))), "}"))
    #
    for key in range(length):
        field = fields[key]
        #
        dprintField(key, field, None, format_string, parent_debug_level, parent_prefix, print_func=print_func, sep=sep)

def dprintFieldsDict(fields, format_string, parent_debug_level, parent_prefix, print_func=dprint, sep=" "):
    if parent_prefix:
        format_string = "{}"
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
        field_def = None
        field_debug_level = 1
        if fields_structure \
        and key in fields_structure:
            field_def = fields_structure[key]
            if "DEBUG" in field_def:
                field_debug_level = field_def["DEBUG"]
        #
        if parent_debug_level >= field_debug_level:
            dprintField(key, field, field_def, format_string, parent_debug_level, parent_prefix, print_func=print_func, sep=sep)


def finalizeBytesStructure(CONST_STRUCTURE_FIELDS, CONST_STRUCTURE_ENDIAN, structure_name, format_string, parent_debug_level):
    unpack_format = CONST_STRUCTURE_ENDIAN
    offset = 0
    index = 0
    for key in CONST_STRUCTURE_FIELDS:
        field_def = CONST_STRUCTURE_FIELDS[key]
        #
        if "VIRTUAL" in field_def \
        and field_def["VIRTUAL"]:
            field_def["INDEX"] = -1
            field_def["OFFSET"] = -1
            continue
        #
        field_def["INDEX"] = index
        field_def["OFFSET"] = offset
        if "FORMAT" in field_def:
            field_format = field_def["FORMAT"]
            if field_format == "s":
                if "SUBSIZE" in field_def:
                    field_def["SIZE"] = field_def["SUBSIZE"] * field_def["SUBCOUNT"]
                elif field_def["SIZE"] < 0:
                    field_def["SIZE"] = abs(field_def["SIZE"]) - field_def["OFFSET"]
                field_format = "".join((unicode(field_def["SIZE"]), field_format))
            elif field_format == "L" \
            or field_format == "H" \
            or field_format == "Q":
                field_def["SIZE"] = struct.calcsize("".join((CONST_STRUCTURE_ENDIAN, field_format)))
            unpack_format = "".join((unpack_format, field_format))
        if parent_debug_level >= 3:
            dprint(format_string.format(structure_name, field_def["INDEX"], field_def["OFFSET"], field_def["SIZE"], key, field_def["DESC"]))
        offset += field_def["SIZE"]
        index += 1
    structure_size = struct.calcsize(unpack_format)
    if parent_debug_level >= 2:
        dprint("{}: Size {} Format {}".format(structure_name, structure_size, unpack_format))

    CONST_STRUCTURE_FIELDS["STRUCTURE_SIZE"] = structure_size
    CONST_STRUCTURE_FIELDS["STRUCTURE_UNPACK"] = unpack_format


def convertFieldsToOrdDict(CONST_STRUCTURE_FIELDS, temp_fields):
    fields = collections.OrderedDict()
    #
    for key in CONST_STRUCTURE_FIELDS:
        if key == "STRUCTURE_SIZE" \
        or key == "STRUCTURE_UNPACK":
            continue
        #
        field_def = CONST_STRUCTURE_FIELDS[key]
        #
        if "SKIP" in field_def \
        and field_def["SKIP"]:
            continue
        #
        if "VIRTUAL" in field_def \
        and field_def["VIRTUAL"]:
            if field_def["VIRTUAL"] > 0:
                fields[key] = None
            continue
        #
        fields[key] = temp_fields[field_def["INDEX"]]
        if "CONV" in field_def:
            if field_def["CONV"] == 0x0004 \
            or field_def["CONV"] == 0x0204:  ## UTF-8 not and NUL-terminated
                fields[key] = convertUtf8BytesToString(fields[key], field_def["CONV"])
        elif "FORMAT" in field_def:
            ## Python 2 workaround: convert str to bytes
            if field_def["FORMAT"] == "s" \
            and isinstance(fields[key], str):
                fields[key] = bytes(fields[key])
    #
    fields["STRUCTURE_DEF"] = CONST_STRUCTURE_FIELDS
    #
    return fields


def parsePkg4Header(header_bytes, data_stream, function_debug_level, print_unknown=False):
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps4/PKG_files#File_Header

    ## Extract fields from PKG4 Main Header
    temp_fields = struct.unpack(CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], header_bytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PKG4_MAIN_HEADER_FIELDS, CONST_PKG4_HEADER_ENDIAN, temp_fields, "PKG4 Main Header[{:2}]: [{:#05x}|{:3}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    header_fields = convertFieldsToOrdDict(CONST_PKG4_MAIN_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Process sub structures
    for key in header_fields:
        if not key in CONST_PKG4_MAIN_HEADER_FIELDS:
            continue
        #
        field_def = CONST_PKG4_MAIN_HEADER_FIELDS[key]
        if "SUBCOUNT" in field_def:
            unpack_format = CONST_PKG4_HEADER_ENDIAN
            field_format = "".join((unicode(field_def["SUBSIZE"]), field_def["FORMAT"]))
            for _i in range(field_def["SUBCOUNT"]):
                unpack_format = "".join((unpack_format, field_format))
            header_fields[key] = struct.unpack(unpack_format, header_fields[key])
            ## Python 2 workaround: convert str to bytes
            if field_def["FORMAT"] == "s" \
            and isinstance(header_fields[key][0], str):
                temp_fields = []
                for _i in range(len(header_fields[key])):
                    temp_fields.append(bytes(header_fields[key][_i]))
                header_fields[key] = temp_fields
                del temp_fields

    ## Prepare format strings
    file_cnt_len = unicode(len(unicode(header_fields["FILECNT"])))
    file_cnt_format_string = "".join(("{:", file_cnt_len, "}"))

    ## Retrieve PKG4 File Entry Table from data stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 File Entry Table:")
    pkg_file_table_size = header_fields["FILECNT"] * CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG4 file entry table from offset {:#x} with count {} and size {}".format(header_fields["FILETBLOFS"], header_fields["FILECNT"], pkg_file_table_size))
    temp_bytes = bytearray()
    try:
        temp_bytes.extend(data_stream.read(header_fields["FILETBLOFS"], pkg_file_table_size, function_debug_level))
    except:
        data_stream.close(function_debug_level)
        eprint("Could not get PKG4 file entry table at offset {:#x} with size {} from".format(header_fields["FILETBLOFS"], pkg_file_table_size), data_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Parse PKG4 File Entry Table Data
    file_table = []
    file_table_map = collections.OrderedDict()
    offset = 0
    #
    for _i in range(header_fields["FILECNT"]):  ## 0 to <file count - 1>
        temp_fields = struct.unpack(CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_UNPACK"], temp_bytes[offset:offset+CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG4_FILE_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, temp_fields, "".join(("PKG4 File Entry[", file_cnt_format_string.format(_i), "][{:2}]: [{:#04x}|{:2}] {} = {}")), function_debug_level)
        temp_fields = convertFieldsToOrdDict(CONST_PKG4_FILE_ENTRY_FIELDS, temp_fields)
        temp_fields["INDEX"] = _i
        temp_fields["KEYINDEX"] = (temp_fields["FLAGS2"] & 0xf000) >> 12  # TODO: correct?
        file_table.append(temp_fields)
        #
        file_table_map[temp_fields["FILEID"]] = _i
        #
        del temp_fields
        #
        offset += CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del temp_bytes

    ## Retrieve PKG4 Name Table from data stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Name Table:")
    name_table = None
    if not CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE in file_table_map:
        dprint("Not present!")
    else:
        file_entry = file_table[file_table_map[CONST_PKG4_FILE_ENTRY_ID_NAME_TABLE]]
        if function_debug_level >= 2:
                dprint("Get PKG4 name table from offset {:#x} with size {}".format(file_entry["DATAOFS"], file_entry["DATASIZE"]))
        name_table = bytearray()
        try:
            name_table.extend(data_stream.read(file_entry["DATAOFS"], file_entry["DATASIZE"], function_debug_level))
        except:
            data_stream.close(function_debug_level)
            eprint("Could not get PKG4 name table at offset {:#x} with size {} from".format(file_entry["DATAOFS"], file_entry["DATASIZE"]), data_stream.getSource())
            eprint("", prefix=None)
            sys.exit(2)
        name_table = bytes(name_table)

    ## Parse PKG4 Name Table Data for File Entries
    if function_debug_level >= 2:
        dprint("Parse PKG4 Name Table for File Names")
    for _i in range(header_fields["FILECNT"]):  ## 0 to <file count - 1>
        file_entry = file_table[_i]
        #
        if name_table \
        and file_entry["NAMERELOFS"] > 0:
            file_entry["NAME"] = convertUtf8BytesToString(name_table[file_entry["NAMERELOFS"]:], 0x0204)
        elif file_entry["FILEID"] in CONST_PKG4_FILE_ENTRY_NAME_MAP:
            file_entry["NAME"] = CONST_PKG4_FILE_ENTRY_NAME_MAP[file_entry["FILEID"]]
        #
        if "NAME" in file_entry \
        and function_debug_level >= 2:
            dprint("".join(("PKG4 File Entry[", file_cnt_format_string, "]: ID {:#06x} Name Offset {:#03x} =")).format(_i, file_entry["FILEID"], file_entry["NAMERELOFS"]), file_entry["NAME"])
        #
        if print_unknown \
        and not file_entry["FILEID"] in CONST_PKG4_FILE_ENTRY_NAME_MAP:
            eprint("PKG4 File ID {:#x} {}".format(file_entry["FILEID"], file_entry["NAME"] if "NAME" in file_entry else ""), prefix="[UNKNOWN] ")

    ## Debug print results
    dprint(">>>>> parsePkg4Header results:")
    dprintFieldsDict(header_fields, "headerfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsList(file_table, "".join(("filetable[{KEY:", file_cnt_len, "}]")), function_debug_level, None)
    if function_debug_level >= 2:
        dprintFieldsDict(file_table_map, "filetablemap[{KEY:#06x}]", function_debug_level, None)
        dprint("nametable:", name_table)

    return header_fields, file_table, file_table_map


def parsePkg3Header(header_bytes, data_stream, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2

    ## Extract fields from PKG3 Main Header
    temp_fields = struct.unpack(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], header_bytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PKG3_MAIN_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, temp_fields, "PKG3 Main Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    header_fields = convertFieldsToOrdDict(CONST_PKG3_MAIN_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Process sub structures
    for key in header_fields:
        if not key in CONST_PKG3_MAIN_HEADER_FIELDS:
            continue
        #
        field_def = CONST_PKG3_MAIN_HEADER_FIELDS[key]
        if "SUBCOUNT" in field_def:
            unpack_format = CONST_PKG3_HEADER_ENDIAN
            field_format = "".join((unicode(field_def["SUBSIZE"]), field_def["FORMAT"]))
            for _i in range(field_def["SUBCOUNT"]):
                unpack_format = "".join((unpack_format, field_format))
            header_fields[key] = struct.unpack(unpack_format, header_fields[key])
            ## Python 2 workaround: convert str to bytes
            if field_def["FORMAT"] == "s" \
            and isinstance(header_fields[key][0], str):
                temp_fields = []
                for _i in range(len(header_fields[key])):
                    temp_fields.append(bytes(header_fields[key][_i]))
                header_fields[key] = temp_fields
                del temp_fields

    ## Retrieve PKG3 Unencrypted Data from data stream
    if function_debug_level >= 2:
        dprint("Get PKG3 remaining unencrypted data with size", header_fields["DATAOFS"])
    unencrypted_bytes = header_bytes
    try:
        unencrypted_bytes.extend(data_stream.read(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], header_fields["DATAOFS"]-CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], function_debug_level))
    except:
        data_stream.close(function_debug_level)
        eprint("Could not get PKG3 unencrypted data at offset {:#x} with size {} from".format(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], header_fields["DATAOFS"] - CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]), data_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Extract fields from PKG3 Extended Header
    ext_header_fields = None
    main_hdr_size = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"] + CONST_PKG3_PS3_DIGEST_FIELDS["STRUCTURE_SIZE"]
    if header_fields["TYPE"] == 0x2:
# TODO: verify
#    and "HDRSIZE" in header_fields \
#    and header_fields["HDRSIZE"] >= main_hdr_size:
        if function_debug_level >= 2:
            dprint(">>>>> PKG3 Extended Main Header:")
        temp_fields = struct.unpack(CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_UNPACK"], header_bytes[main_hdr_size:main_hdr_size+CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_SIZE"]])
        ## --> Debug print all
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, temp_fields, "PKG3 Extended Main Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

        ## Convert to dictionary (associative array)
        ext_header_fields = convertFieldsToOrdDict(CONST_PKG3_EXT_HEADER_FIELDS, temp_fields)
        del temp_fields

        ## Check PKG3 Extended Header Magic
        if "MAGIC" in ext_header_fields \
        and ext_header_fields["MAGIC"] != CONST_PKG3_EXT_MAGIC:
            data_stream.close(function_debug_level)
            eprint("Not a known PKG3 Extended Main Header ({:#x} <> {:#x})".format(ext_header_fields["MAGIC"], CONST_PKG3_EXT_MAGIC), data_stream.getSource())
            eprint("", prefix=None)
            sys.exit(2)

    ## Determine key index for item entries plus path of PARAM.SFO
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Package Keys:")
    if header_fields["TYPE"] == 0x1:  ## PS3
        header_fields["KEYINDEX"] = 0
        header_fields["PARAM.SFO"] = "PARAM.SFO"
    elif header_fields["TYPE"] == 0x2:  ## PSX/PSP/PSV/PSM
        header_fields["PARAM.SFO"] = "PARAM.SFO"
        if ext_header_fields:
            header_fields["KEYINDEX"] = ext_header_fields["KEYID"] & 0xf
            if header_fields["KEYINDEX"] == 2:  ## PSV
                header_fields["PARAM.SFO"] = "sce_sys/param.sfo"
            elif header_fields["KEYINDEX"] == 3:  ## Unknown
                eprint("PKG3 Key Index", header_fields["KEYINDEX"], prefix="[UNKNOWN] ")
        else:
            header_fields["KEYINDEX"] = 1
    else:
        eprint("PKG3 Package Type", header_fields["TYPE"], prefix="[UNKNOWN] ")
    #
    header_fields["AES_CTR"] = {}
    for key in CONST_PKG3_CONTENT_KEYS:
        if function_debug_level >= 2:
            dprint("Content Key #{}: {}".format(key, convertBytesToHexString(CONST_PKG3_CONTENT_KEYS[key]["KEY"], sep="")))
        if "DERIVE" in CONST_PKG3_CONTENT_KEYS[key] \
        and CONST_PKG3_CONTENT_KEYS[key]["DERIVE"]:
            aes = Cryptodome.Cipher.AES.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], Cryptodome.Cipher.AES.MODE_ECB)
            pkg_key = aes.encrypt(header_fields["DATARIV"])
            ## Python 2 workaround: convert str to bytes
            if isinstance(pkg_key, str):
                pkg_key = bytes(pkg_key)
            header_fields["AES_CTR"][key] = PkgAesCtrCounter(pkg_key, header_fields["DATARIV"])
            del aes
            if function_debug_level >= 2:
                dprint("Derived Key #{} from IV encrypted with Content Key: {}".format(key, convertBytesToHexString(pkg_key, sep="")))
            del pkg_key
        else:
            header_fields["AES_CTR"][key] = PkgAesCtrCounter(CONST_PKG3_CONTENT_KEYS[key]["KEY"], header_fields["DATARIV"])

    ## Extract fields from PKG3 Main Header Meta Data
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Meta Data:")
    meta_data = collections.OrderedDict()
    #
    md_entry_type = -1
    md_entry_size = -1
    md_offset = header_fields["MDOFS"]
    md_format_string = "".join(("Metadata[{:", unicode(len(unicode(header_fields["MDCNT"]))), "}]: [{:#05x}|{:2}] ID {:#04x} ="))
    for _i in range(header_fields["MDCNT"]):  ## 0 to <meta data count - 1>
        md_entry_type = getInteger32BitBE(unencrypted_bytes, md_offset)
        md_offset += 0x04
        #
        md_entry_size = getInteger32BitBE(unencrypted_bytes, md_offset)
        md_offset += 0x04
        #
        temp_bytes = unencrypted_bytes[md_offset:md_offset + md_entry_size]
        if function_debug_level >= 2:
            dprint(md_format_string.format(_i, md_offset, md_entry_size, md_entry_type), \
                   convertBytesToHexString(temp_bytes))
        #
        meta_data[md_entry_type] = collections.OrderedDict()
        ## DRM Type (0x1), Content Type (0x2)
        if md_entry_type == 0x01 \
        or md_entry_type == 0x02:
            if md_entry_type == 0x01:
                meta_data[md_entry_type]["DESC"] = "DRM Type"
            elif md_entry_type == 0x02:
                meta_data[md_entry_type]["DESC"] = "Content Type"
            meta_data[md_entry_type]["VALUE"] = getInteger32BitBE(temp_bytes, 0)
            if md_entry_size > 0x04:
                meta_data[md_entry_type]["UNKNOWN"] = bytes(temp_bytes[0x04:])
        ## TitleID (when size 0xc) (otherwise Version + App Version)
        elif md_entry_type == 0x06 \
        and md_entry_size == 0x0C:
            meta_data[md_entry_type]["DESC"] = "Title ID"
            meta_data[md_entry_type]["VALUE"] = convertUtf8BytesToString(temp_bytes, 0x0204)
        ## (13) Items Info (PS Vita)
        elif md_entry_type == 0x0D:
            if md_entry_type == 0x0D:
                meta_data[md_entry_type]["DESC"] = "Items Info (SHA256 of decrypted data)"
            meta_data[md_entry_type]["OFS"] = getInteger32BitBE(temp_bytes, 0)
            meta_data[md_entry_type]["SIZE"] = getInteger32BitBE(temp_bytes, 0x04)
            meta_data[md_entry_type]["SHA256"] = bytes(temp_bytes[0x08:0x08+0x20])
            if md_entry_size > 0x28:
                meta_data[md_entry_type]["UNKNOWN"] = bytes(temp_bytes[0x28:])
        ## (14) PARAM.SFO Info (PS Vita)
        ## (15) Unknown Info (PS Vita)
        ## (16) Entirety Info (PS Vita)
        elif md_entry_type == 0x0E \
        or md_entry_type == 0x0F \
        or md_entry_type == 0x10 \
        or md_entry_type == 0x12:
            if md_entry_type == 0x0E:
                meta_data[md_entry_type]["DESC"] = "PARAM.SFO Info"
            elif md_entry_type == 0x10:
                meta_data[md_entry_type]["DESC"] = "Entirety Info"
            elif md_entry_type == 0x12:
                meta_data[md_entry_type]["DESC"] = "Self Info"
            meta_data[md_entry_type]["OFS"] = getInteger32BitBE(temp_bytes, 0)
            meta_data[md_entry_type]["SIZE"] = getInteger32BitBE(temp_bytes, 0x04)
            meta_data[md_entry_type]["UNKNOWN"] = bytes(temp_bytes[0x08:md_entry_size - 0x20])
            meta_data[md_entry_type]["SHA256"] = bytes(temp_bytes[md_entry_size - 0x20:])
        else:
            if md_entry_type == 0x03:
                meta_data[md_entry_type]["DESC"] = "Package Type/Flags"
            elif md_entry_type == 0x04:
                meta_data[md_entry_type]["DESC"] = "Package Size"
            elif md_entry_type == 0x06:
                meta_data[md_entry_type]["DESC"] = "Version + App Version"
            elif md_entry_type == 0x07:
                meta_data[md_entry_type]["DESC"] = "QA Digest"
            elif md_entry_type == 0x0A:
                meta_data[md_entry_type]["DESC"] = "Install Directory"
            meta_data[md_entry_type]["VALUE"] = bytes(temp_bytes)
        #
        md_offset += md_entry_size
    #
    del temp_bytes
    header_fields["MDSIZE"] = md_offset - header_fields["MDOFS"]

    ## Debug print results
    dprint(">>>>> parsePkg3Header results:")
    dprintFieldsDict(header_fields, "headerfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    if ext_header_fields:
        dprintFieldsDict(ext_header_fields, "extheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsDict(meta_data, "metadata[{KEY:#04x}]", function_debug_level, None)

    return header_fields, ext_header_fields, meta_data, unencrypted_bytes


def parsePkg3ItemEntries(header_fields, meta_data, data_stream, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entries:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Body

    ## Prepare format strings
    item_cnt_len = unicode(len(unicode(header_fields["ITEMCNT"])))
    item_cnt_format_string = "".join(("{:", item_cnt_len, "}"))

    ## Retrieve PKG3 Item Entries from data stream
    decrypted_item_entries = {}
    if 0xD in meta_data:
        decrypted_item_entries["OFS"] = meta_data[0xD]["OFS"]
    else:
        decrypted_item_entries["OFS"] = 0
    decrypted_item_entries["SIZE"] = header_fields["ITEMCNT"] * CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    decrypted_item_entries["ALIGN"] = calculateAesAlignedOffsetAndSize(decrypted_item_entries["OFS"], decrypted_item_entries["SIZE"])
    if function_debug_level >= 2:
        dprint("Get PKG3 item entries from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} with count {} and size {}+{}={}".format(decrypted_item_entries["OFS"], decrypted_item_entries["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+decrypted_item_entries["ALIGN"]["OFS"], header_fields["ITEMCNT"], decrypted_item_entries["SIZE"], decrypted_item_entries["ALIGN"]["SIZEDELTA"], decrypted_item_entries["ALIGN"]["SIZE"]))
    if decrypted_item_entries["ALIGN"]["OFSDELTA"] > 0:
        eprint("Unaligned offset {:#x}-{:#x}+{:#x}={:#x} for item entries in".format(decrypted_item_entries["OFS"], decrypted_item_entries["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+decrypted_item_entries["ALIGN"]["OFS"]), data_stream.getSource(), prefix="[ALIGN] ")
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
    encrypted_bytes = bytearray()
    try:
        encrypted_bytes.extend(data_stream.read(header_fields["DATAOFS"]+decrypted_item_entries["ALIGN"]["OFS"], decrypted_item_entries["ALIGN"]["SIZE"], function_debug_level))
    except:
        data_stream.close(function_debug_level)
        eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(header_fields["DATAOFS"]+decrypted_item_entries["ALIGN"]["OFS"], decrypted_item_entries["ALIGN"]["SIZE"]), data_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Decrypt PKG3 Item Entries
    decrypted_item_entries["DATA"] = header_fields["AES_CTR"][header_fields["KEYINDEX"]].decrypt(decrypted_item_entries["ALIGN"]["OFS"], bytes(encrypted_bytes))
    del encrypted_bytes

    ## Parse PKG3 Item Entries
    item_entries = []
    offset = decrypted_item_entries["ALIGN"]["OFSDELTA"]
    name_offset_start = -1
    name_offset_end = -1
    item_name_size_max = 0
    #
    for _i in range(header_fields["ITEMCNT"]):  ## 0 to <item count - 1>
        temp_fields = struct.unpack(CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_UNPACK"], decrypted_item_entries["DATA"][offset:offset+CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, temp_fields, "".join(("PKG3 Body Item Entry[", item_cnt_format_string.format(_i), "][{:1}]: [", "{:#06x}+".format(header_fields["DATAOFS"] + offset), "{:#04x}|{:1}] {} = {}")), function_debug_level)
        temp_fields = convertFieldsToOrdDict(CONST_PKG3_ITEM_ENTRY_FIELDS, temp_fields)
        temp_fields["INDEX"] = _i
        temp_fields["KEYINDEX"] = (temp_fields["FLAGS"] >> 28) & 0x7
        temp_fields["ALIGN"] = calculateAesAlignedOffsetAndSize(temp_fields["DATAOFS"], temp_fields["DATASIZE"])
        if temp_fields["ALIGN"]["OFSDELTA"] > 0:
            eprint("Unaligned offset {:#x}-{:#x}+{:#x}={:#x} for item data {} in".format(temp_fields["ALIGN"]["OFS"], temp_fields["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+temp_fields["ALIGN"]["OFS"]), data_stream.getSource(), prefix="[ALIGN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
        item_entries.append(temp_fields)
        #
        if temp_fields["ITEMNAMESIZE"] > 0:
            if name_offset_start == -1 \
            or temp_fields["ITEMNAMEOFS"] < name_offset_start:
                name_offset_start = temp_fields["ITEMNAMEOFS"]
            #
            if name_offset_end == -1 \
            or temp_fields["ITEMNAMEOFS"] > name_offset_end:
                name_offset_end = temp_fields["ITEMNAMEOFS"] + temp_fields["ITEMNAMESIZE"]
            #
            if temp_fields["ITEMNAMESIZE"] > item_name_size_max:
                item_name_size_max = temp_fields["ITEMNAMESIZE"]
        #
        del temp_fields
        #
        offset += CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    name_size = name_offset_end - name_offset_start

    ## Retrieve PKG3 Item Names from data stream
    decrypted_item_names = {}
    decrypted_item_names["OFS"] = name_offset_start
    decrypted_item_names["SIZE"] = name_size
    decrypted_item_names["ALIGN"] = calculateAesAlignedOffsetAndSize(decrypted_item_names["OFS"], decrypted_item_names["SIZE"])
    if function_debug_level >= 2:
        dprint("Get PKG3 item names from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} and size {}+{}={}".format(decrypted_item_names["OFS"], decrypted_item_names["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+decrypted_item_names["ALIGN"]["OFS"], decrypted_item_names["SIZE"], decrypted_item_names["ALIGN"]["SIZEDELTA"], decrypted_item_names["ALIGN"]["SIZE"]))
    if decrypted_item_names["ALIGN"]["OFSDELTA"] > 0:
        eprint("Unaligned offset {:#x}-{:#x}+{:#x}={:#x} for item names in".format(decrypted_item_names["OFS"], decrypted_item_names["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+decrypted_item_names["ALIGN"]["OFS"]), data_stream.getSource(), prefix="[ALIGN] ")
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
    encrypted_bytes = bytearray()
    try:
        encrypted_bytes.extend(data_stream.read(header_fields["DATAOFS"]+decrypted_item_names["ALIGN"]["OFS"], decrypted_item_names["ALIGN"]["SIZE"], function_debug_level))
    except:
        data_stream.close(function_debug_level)
        eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(header_fields["DATAOFS"]+decrypted_item_names["ALIGN"]["OFS"], decrypted_item_names["ALIGN"]["SIZE"]), data_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Decrypt and Parse PKG3 Item Names
    item_name_size_cnt_len = unicode(len(unicode(item_name_size_max)))
    item_name_size_format_string = "".join(("{:", item_name_size_cnt_len, "}"))
    #
    decrypted_item_names["DATA"] = bytearray()
    decrypted_item_names["DATA"].extend(encrypted_bytes)
    for item_entry in item_entries:
        if item_entry["ITEMNAMESIZE"] <= 0:
            continue
        #
        key_index = item_entry["KEYINDEX"]
        align = calculateAesAlignedOffsetAndSize(item_entry["ITEMNAMEOFS"], item_entry["ITEMNAMESIZE"])
        if align["OFSDELTA"] > 0:
            eprint("Unaligned offset {:#x}-{:#x}+{:#x}={:#x} for item name {} in".format(item_entry["ITEMNAMEOFS"], align["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+align["OFS"], item_entry["INDEX"]), data_stream.getSource(), prefix="[ALIGN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
        offset = align["OFS"] - decrypted_item_names["ALIGN"]["OFS"]
        #
        decrypted_item_names["DATA"][offset:offset+align["SIZE"]] = header_fields["AES_CTR"][key_index].decrypt(align["OFS"], bytes(encrypted_bytes[offset:offset+align["SIZE"]]))
        temp_bytes = decrypted_item_names["DATA"][offset+align["OFSDELTA"]:offset+align["OFSDELTA"]+item_entry["ITEMNAMESIZE"]]
        del align
        if function_debug_level >= 2:
            dprint("".join(("PKG3 Body Item Name[", item_cnt_format_string, "]: key {:#} [{:#06x}|", item_name_size_format_string, "] {}")).format(item_entry["INDEX"], key_index, header_fields["DATAOFS"]+item_entry["ITEMNAMEOFS"], item_entry["ITEMNAMESIZE"], temp_bytes))
        item_entry["NAME"] = convertUtf8BytesToString(temp_bytes, 0x0004, length=item_entry["ITEMNAMESIZE"])
        #
        del temp_bytes
    #
    del encrypted_bytes

    ## Calculate SHA-256 hash of decrypted data
    hash_sha256 = Cryptodome.Hash.SHA256.new()
    hash_sha256.update(bytes(decrypted_item_entries["DATA"]))
    hash_sha256.update(bytes(decrypted_item_names["DATA"]))

    ## Debug print results
    dprint(">>>>> parsePkg3ItemEntries results:")
    dprintFieldsList(item_entries, "".join(("itementries[{KEY:", item_cnt_len, "}]")), function_debug_level, None)
    dprint("SHA-256 of decrypted items entries and names:", hash_sha256.hexdigest())

    return item_entries, decrypted_item_entries, decrypted_item_names, hash_sha256.digest()


def processPkg3Item(header_fields, item_entry, data_stream, item_data, raw_stream, extract_stream, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entry #{} {}:".format(item_entry["INDEX"], item_entry["NAME"]))

    ## Retrieve PKG3 Item Data from data stream
    if function_debug_level >= 2:
        dprint("{} PKG3 item data from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} and size {}+{}={}".format("Get" if data_stream else "Process",item_entry["DATAOFS"], item_entry["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["DATASIZE"], item_entry["ALIGN"]["SIZEDELTA"], item_entry["ALIGN"]["SIZE"]))
        if raw_stream:
            dprint("Write PKG3 item data from offset {:#x} and size {}".format(header_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["ALIGN"]["SIZE"]), prefix="[RAW] ")
        if extract_stream:
            dprint("Write PKG3 item data from offset {:#x} and size {}".format(header_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["ALIGN"]["SIZE"]), prefix="[EXTRACT] ")
    #
    dataoffset = item_entry["ALIGN"]["OFS"]
    fileoffset = header_fields["DATAOFS"]+dataoffset
    filesize = item_entry["ALIGN"]["SIZE"]
    #
    encrypted_bytes = None
    decrypted_bytes = None
    ofsdelta = item_entry["ALIGN"]["OFSDELTA"]
    sizedelta = 0
    while filesize > 0:
        if data_stream \
        and filesize >= CONST_READ_SIZE:
            blocksize = CONST_READ_SIZE
        else:
            blocksize = filesize
            sizedelta = item_entry["ALIGN"]["SIZEDELTA"]

        ## Encrypted data block
        if data_stream:
            if function_debug_level >= 3:
                dprint("...read offset {:#010x} size {}".format(fileoffset, blocksize))
            ## Read encrypted data block
            try:
                encrypted_bytes = data_stream.read(fileoffset, blocksize, function_debug_level)
            except:
                data_stream.close(function_debug_level)
                eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(header_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["ALIGN"]["SIZE"]), data_stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)
            #
            if item_data \
            and "ENCRYPTED" in item_data:
                item_data["ENCRYPTED"].extend(encrypted_bytes)
        else:
            encrypted_bytes = item_data["ENCRYPTED"]
        #
        #if enc_hashes:
        #    hash encrypted_bytes

        ## Decrypted data block
        if data_stream:
            decrypted_bytes = header_fields["AES_CTR"][item_entry["KEYINDEX"]].decrypt(dataoffset, encrypted_bytes)
            #
            if item_data \
            and "DECRYPTED" in item_data:
                item_data["DECRYPTED"].extend(decrypted_bytes)
        else:
            decrypted_bytes = item_data["DECRYPTED"]
        #
        #if dec_hashes:
        #    hash decrypted_bytes
        #
        if raw_stream:
            raw_stream.write(decrypted_bytes)
        #
        if extract_stream:
            extract_stream.write(decrypted_bytes[ofsdelta:-sizedelta])
        #
        ## Prepare for next data block
        filesize -= blocksize
        fileoffset += blocksize
        dataoffset += blocksize
        ofsdelta = 0
    #
    del encrypted_bytes
    del decrypted_bytes

    return


def parseSfo(sfo_bytes, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> SFO Header:")

    ## For definition see https://playstationdev.wiki/psvitadevwiki/index.php?title=System_File_Object_(SFO)_(PSF)

    ## Extract fields from SFO Header
    temp_fields = struct.unpack(CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_UNPACK"], sfo_bytes[0:CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]])
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PARAM_SFO_HEADER_FIELDS, CONST_PARAM_SFO_ENDIAN, temp_fields, "SFO Header[{:1}]: [{:#04x}|{:1}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    header_fields = convertFieldsToOrdDict(CONST_PARAM_SFO_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Retrieve SFO Index Table from sfo bytes
    if function_debug_level >= 2:
        dprint(">>>>> SFO Index Table:")
    sfo_index_table_size = header_fields["COUNT"] * CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get SFO index table from offset {:#x} with count {} and size {}".format(CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"], header_fields["COUNT"], sfo_index_table_size))
    temp_bytes = sfo_bytes[CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]:CONST_PARAM_SFO_HEADER_FIELDS["STRUCTURE_SIZE"]+sfo_index_table_size]
    sfo_values = collections.OrderedDict()

    ## Parse SFO Index Table Data
    cnt_format_string = "".join(("{:", unicode(len(unicode(header_fields["COUNT"]))), "}"))
    format_string = ""
    if function_debug_level >= 2:
        if function_debug_level >= 3:
            format_string = "".join(("SFO Index Entry[", cnt_format_string, "][^]: [^^^|^] {} = {}"))
        elif function_debug_level >= 2:
            format_string = "".join(("SFO Index Entry[", cnt_format_string, "]: {} = {}"))
    #
    offset = 0
    #
    for _i in range(header_fields["COUNT"]):  ## 0 to <count - 1>
        temp_fields = struct.unpack(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_UNPACK"], temp_bytes[offset:offset+CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 3:
            dprintBytesStructure(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, CONST_PARAM_SFO_ENDIAN, temp_fields, "".join(("SFO Index Entry[", cnt_format_string.format(_i), "][{:1}]: [{:#03x}|{:1}] {} = {}")), function_debug_level)
        temp_fields = convertFieldsToOrdDict(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, temp_fields)
        key_name = convertUtf8BytesToString(sfo_bytes[header_fields["KEYTBLOFS"]+temp_fields["KEYOFS"]:], 0x0204)
        data = bytes(sfo_bytes[header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]:header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]+temp_fields["DATAUSEDSIZE"]])
        if function_debug_level >= 2:
            dprint(format_string.format(_i, "Key Name", key_name))
            data_desc = "Data Used (Fmt {:#0x})".format(temp_fields["DATAFORMAT"])
            dprint(format_string.format(_i, data_desc, convertBytesToHexString(data)))
        format = temp_fields["DATAFORMAT"]
        if format == 0x0004 \
        or format == 0x0204:  ## UTF-8 not and NUL-terminated
            data = convertUtf8BytesToString(data, format)
            #
            if function_debug_level >= 2:
                data_desc = "UTF-8 String"
                dprint(format_string.format(_i, data_desc, data))
            #
            if key_name == "STITLE" \
            or key_name[:7] == "STITLE_" \
            or key_name == "TITLE" \
            or (key_name[:6] == "TITLE_" \
                and key_name != "TITLE_ID"):
                data = data.replace("\r\n", " ").replace("\n\r", " ")
                data = re.sub(r"\s", " ", data, 0, re.UNICODE).strip()  ## also replaces \u3000
        elif format == 0x0404:
            data = getInteger32BitLE(data, 0x00)
            #
            if function_debug_level >= 2:
                data_desc = "Integer"
                data_display = "{0} = {0:#x}".format(data)
                dprint(format_string.format(_i, data_desc, data_display))
        #
        sfo_values[key_name] = data
        #
        del temp_fields
        #
        offset += CONST_PARAM_SFO_INDEX_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del temp_bytes

    ## Debug print results
    dprint(">>>>> parseSfo results:")
    dprintFieldsDict(sfo_values, "sfovalues[{KEY:20}]", function_debug_level, None)

    return sfo_values


def createArgParser():
    ## argparse: https://docs.python.org/3/library/argparse.html

    ## Create help texts
    ## --> Format Codes
    choices_format = []
    help_format = "Format of output via code (multiple allowed)\n"
    for key in OUTPUT_FORMATS:
        choices_format.append(key)
        help_format = "".join((help_format, "  {:#2} = {}\n".format(key, OUTPUT_FORMATS[key])))
    ## --> Raw
    help_raw = "Create decrypted PKG file of PS3/PSX/PSP/PSV/PSM package.\n\
  Specify a target path where to create the file, e.g. \".\".\n\
  If target path is a directory then file name is <package name>.decrypted.\n\
  Note that the signature and checksum in the file tail are for the *encrypted* data."
    ## --> Extract
    help_extract = "Extract PS3/PSX/PSP/PSV/PSM package in ux0-style hierarchy.\n\
  Specify a top path where to create the directories and files, e.g. \".\"."
    ## --> Overwrite
    help_overwrite = "Allow options \"--raw\" to overwrite existing files."
    ## --> Unclean
    help_unclean = "".join(("Do not clean up international/english tile, except for condensing\n\
multiple white spaces incl. new line to a single space.\n\
Default is to clean up by replacing ", unicode(Replace_List), "\nand condensing demo information to just \"(DEMO)\"."))
    ## --> Item Entries
    help_itementries = "Always decrypt item entries on PS3/PSX/PSP/PSV/PSM packages.\nUseful for analysis."
    ## --> Unknown
    help_unknown = "Print unknown file ids in PS4 packages.\nUseful for analysis."
    ## --> Debug
    choices_debug = range(4)
    help_debug = "Debug verbosity level\n\
  0 = No debug info [default]\n\
  1 = Show parsed results only\n\
  2 = Additionally show raw PKG and SFO data plus read/write actions\n\
  3 = Additionally show interim PKG and SFO data to get result"

    ## Create description
    description = "%(prog)s {version}\n{copyright}\n{author}\nExtract package information and/or files from PS3/PSX/PSP/PSV/PSM and PS4 packages.".format(version=__version__, copyright=__copyright__, author=__author__)
    ## Create epilog
    epilog = "It is recommended to place \"--\" before the package/JSON sources to avoid them being used as targets,\nthen wrong option usage like \"%(prog)s --raw -- 01.pkg 02.pkg\" will not overwrite \"01.pkg\".\n\
If you state URLs then only the necessary bytes are downloaded into memory.\nNote that the options \"--raw\" download the complete(!) package just once\nwithout storing the original data on the file system."

    ## Build Arg Parser
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-V", "--version", action='version', version=__version__)
    parser.add_argument("source", nargs="+", help="Path or URL to PKG or JSON file")
    parser.add_argument("--format", "-f", metavar="CODE", type=int, action="append", choices=choices_format, help=help_format)
    parser.add_argument("--raw", metavar="TARGETPATH", help=help_raw)
    parser.add_argument("--extract", "-x", metavar="TOPPATH", help=help_extract)
    parser.add_argument("--overwrite", action="store_true", help=help_overwrite)
    parser.add_argument("--unclean", "-u", action="store_true", help=help_unclean)
    parser.add_argument("--itementries", action="store_true", help=help_itementries)
    parser.add_argument("--unknown", action="store_true", help=help_unknown)
    parser.add_argument("--debug", "-d", metavar="LEVEL", type=int, default=0, choices=choices_debug, help=help_debug)

    return parser


## Global code
if __name__ == "__main__":
    try:
        ## Initialize (global) variables
        Replace_List = [ ["™®☆◆", " "], ["—–", "-"], ]

        ## Check parameters from command line
        Parser = createArgParser()
        Arguments = Parser.parse_args()
        ## Global Debug [Verbosity] Level: can be set via '-d'/'--debug='
        Debug_Level = Arguments.debug
        ## Output Format: can be set via '-f'/'--format='
        ## Fallback to default output format if none stated
        if Arguments.format is None:
            Arguments.format = [0]
        ## Raw Target Path
        Raw_Is_Dir = None
        if Arguments.raw:
            Arguments.raw = os.path.normpath(Arguments.raw)
            Raw_Is_Dir = os.path.isdir(Arguments.raw)
        if Arguments.extract:
            Arguments.extract = os.path.normpath(Arguments.extract)
            if not os.path.exists(Arguments.extract):
                eprint("Creating top extraction path.", Arguments.extract, prefix="[EXTRACT] ")
                os.makedirs(Arguments.extract)
            elif not os.path.isdir(Arguments.extract):
                eprint("Top extraction path is NOT a DIRECTORY.", Arguments.extract)
                eprint("", prefix=None)
                sys.exit(2)

        ## Enrich structure format arrays
        ## --> PKG3 Main Header
        finalizeBytesStructure(CONST_PKG3_MAIN_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Main Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:12} = {}", Debug_Level)
        ## --> PKG3 PS3 0x40 Digest
        finalizeBytesStructure(CONST_PKG3_PS3_DIGEST_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 PS3 0x40 Digest", "{}[{:1}]: ofs {:#04x} size {:2} key {:12} = {}", Debug_Level)
        ## --> PKG3 Extended Header
        finalizeBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Ext Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:12} = {}", Debug_Level)
        ## --> PKG3 Item Entry
        finalizeBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Item Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", Debug_Level)
        ## --> PKG4 Main Header
        finalizeBytesStructure(CONST_PKG4_MAIN_HEADER_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 Main Header", "{}[{:2}]: ofs {:#05x} size {:3} key {:12} = {}", Debug_Level)
        ## --> PKG4 File Entry
        finalizeBytesStructure(CONST_PKG4_FILE_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 File Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", Debug_Level)
        ## --> PARAM.SFO Header
        finalizeBytesStructure(CONST_PARAM_SFO_HEADER_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Header", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", Debug_Level)
        ## --> PARAM.SFO Index Entry
        finalizeBytesStructure(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Index Entry", "{}[{:1}]: ofs {:#03x} size {:1} key {:12} = {}", Debug_Level)

        ## Process paths and URLs
        for Source in Arguments.source:
            ## Initialize per-package variables
            Data_Stream = None
            Raw_Stream = None
            #
            Header_Fields = None
            Header_Bytes = None
            Ext_Header_Fields = None
            Meta_Data = None
            Item_Entries = None
            Decrypted_Item_Entries = None
            Decrypted_Item_Names = None
            Retrieve_Encrypted_Param_Sfo = False
            File_Table = None
            File_Table_Map = None
            Sfo_Item_Data = None
            Sfo_Bytes = None
            Sfo_Values = None
            Tail_Bytes = None
            Nps_Type = "UNKNOWN"
            #
            Results = collections.OrderedDict()
            Results["TOOL_VERSION"] = __version__
            #
            Headers = {"User-Agent": "Mozilla/5.0 (PLAYSTATION 3; 4.83)"}  ## Default to PS3 headers (fits PS3/PSX/PSP/PSV packages, but not PSM packages for PSV)

            ## If source is a JSON file then determine the first package url from it
            if Source.endswith(".json"):
                print("# >>>>>>>>>> JSON Source:", Source)
                Headers = {"User-Agent": "Download/1.00 libhttp/6.02 (PlayStation 4)"}  ## Switch to PS4 headers
                if Source.startswith("http:") \
                or Source.startswith("https:"):
                    if Debug_Level >= 2:
                        dprint("Opening source as URL data stream")
                    try:
                        Data_Stream = requests.get(Source, headers=Headers)
                    except:
                        eprint("Could not open URL (1)", Source)
                        eprint("", prefix=None)
                        sys.exit(2)
                    Stream_Data = Data_Stream.json()
                else:
                    if Debug_Level >= 2:
                        dprint("Opening source as FILE data stream")
                    try:
                        Data_Stream = io.open(Source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    except:
                        eprint("Could not open FILE", Source)
                        eprint("", prefix=None)
                        sys.exit(2)
                    Stream_Data = json.load(Data_Stream)
                    Data_Stream.close()

                ## Get PKG source from JSON data
                if not 'pieces' in Stream_Data \
                or not Stream_Data['pieces'][0] \
                or not 'url' in Stream_Data['pieces'][0]:
                    eprint("JSON source does not look like PKG meta data (missing [pieces][0])", Source)
                    eprint("", prefix=None)
                    sys.exit(2)

                Source = Stream_Data['pieces'][0]['url']
                del Stream_Data

            ## Open PKG source
            if not 3 in Arguments.format \
            and not 98 in Arguments.format:  ## Special case JSON output for parsing
                print("# >>>>>>>>>> PKG Source:", Source)
            else:
                eprint("# >>>>>>>>>> PKG Source:", Source, prefix=None)
            Data_Stream = PkgReader(Source, Headers, Debug_Level)
            Results["FILE_SIZE"] = Data_Stream.getSize(Debug_Level)
            if Results["FILE_SIZE"] is None:
                del Results["FILE_SIZE"]
            elif Debug_Level >= 2:
                dprint("File Size:", Results["FILE_SIZE"])

            ## Initialize header bytes array
            dprint(">>>>> PKG Main Header:")
            Header_Bytes = bytearray()

            ## Get file magic code/string and check for GAME PKG file
            ## see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2
            ## see http://www.psdevwiki.com/ps4/PKG_files#File_Header
            try:
                Header_Bytes.extend(Data_Stream.read(0, 4, Debug_Level))
            except:
                Data_Stream.close(Debug_Level)
                eprint("Could not get PKG unencrypted magic at offset {:#x} with size {} from".format(0, 4), Data_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)
            Pkg_Magic = getInteger32BitBE(Header_Bytes, 0x00)
            #
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Header_Size = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                Nps_Type = "".join((Nps_Type, " (PS3/PSX/PSP/PSV/PSM)"))
                dprint("Detected PS3/PSX/PSP/PSV/PSM game package")
                ## Determine decrypted PKG target
                if Arguments.raw:
                    if Raw_Is_Dir:
                        Target = "".join((Data_Stream.getPkgName(), ".decrypted"))
                        Target = os.path.join(Arguments.raw, Target)
                    else:
                        Target = Arguments.raw
                    if not 3 in Arguments.format \
                    and not 98 in Arguments.format:  ## Special case JSON output for parsing
                        print("# >>> Decrypted Target File:", Target)
                    else:
                        eprint("# >>> Decrypted Target File:", Target, prefix=None)
                    if not os.path.exists(Target) \
                    or Arguments.overwrite:
                        Raw_Stream = io.open(Target, mode="wb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    else:
                        eprint("Target File already exists and will NOT be WRITTEN.", Target)
                    del Target
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Header_Size = CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                Nps_Type = "".join((Nps_Type, " (PS4)"))
                dprint("Detected PS4 game package")
            else:
                Data_Stream.close(Debug_Level)
                eprint("Not a known GAME PKG file ({:#x} <> {:#x}|{:#x})".format(Pkg_Magic, CONST_PKG3_MAGIC, CONST_PKG4_MAGIC), Data_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)

            ## Get rest of PKG main header from data stream
            if Debug_Level >= 2:
                dprint("Get PKG main header from offset {:#x} with size {}".format(0, Header_Size))
            try:
                Header_Bytes.extend(Data_Stream.read(4, Header_Size-4, Debug_Level))
            except:
                Data_Stream.close(Debug_Level)
                eprint("Could not get rest of PKG unencrypted main header at offset {:#x} with size {} from".format(4, Header_Size-4), Data_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)

            ## Process GAME PKG main header data
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Header_Fields, Ext_Header_Fields, Meta_Data, Header_Bytes = parsePkg3Header(Header_Bytes, Data_Stream, max(0, Debug_Level))
                if Raw_Stream:
                    if Debug_Level >= 2:
                        dprint("Write PKG3 unencrypted header data from offset {:#x} and size {}".format(0, len(Header_Bytes)), prefix="[RAW] ")
                    Raw_Stream.write(Header_Bytes)
                ## --> Size of package (=file size)
                if "TOTALSIZE" in Header_Fields:
                    Results["PKG_TOTAL_SIZE"] = Header_Fields["TOTALSIZE"]
                ## --> Package content id
                if "CID" in Header_Fields:
                    Results["PKG_CONTENT_ID"] = Header_Fields["CID"]
                ## --> param.sfo offset + size
                if 0xE in Meta_Data:
                    Results["PKG_SFO_OFFSET"] = Meta_Data[0xE]["OFS"]
                    Results["PKG_SFO_SIZE"] = Meta_Data[0xE]["SIZE"]
                ## --> DRM Type
                if 0x1 in Meta_Data:
                    Results["PKG_DRM_TYPE"] = Meta_Data[0x1]["VALUE"]
                ## --> Content Type
                if 0x2 in Meta_Data:
                    Results["PKG_CONTENT_TYPE"] = Meta_Data[0x2]["VALUE"]
                ## --> Title ID
                if 0x6 in Meta_Data:  ## Version + App Version / TitleID (on size 0xC)
                    Results["PKG_TITLE_ID"] = Meta_Data[0x6]["VALUE"]
                ## --> Items Info offset (inside encrypted data)
                if 0xD in Meta_Data \
                and Meta_Data[0xD]["OFS"] != 0:
                    eprint("Items Info offset (in encrypted data) {:#0x} <> 0x0.".format(Meta_Data[0xD]["OFS"]), Data_Stream.getSource(), prefix="[UNKNOWN] ")
                ## If PARAM.SFO not present in unencrypted data, then search in encrypted item entries
                if not "PKG_SFO_OFFSET" in Results \
                and "PARAM.SFO" in Header_Fields \
                and Header_Fields["PARAM.SFO"].strip():
                    Retrieve_Encrypted_Param_Sfo = True
                ## Process PKG3 encrypted item entries
                if not Header_Fields["KEYINDEX"] is None \
                and (Arguments.itementries \
                     or Raw_Stream \
                     or Arguments.extract \
                     or Retrieve_Encrypted_Param_Sfo ):
                    Item_Entries, Decrypted_Item_Entries, Decrypted_Item_Names, Results["ITEMS_INFO_SHA256"] = parsePkg3ItemEntries(Header_Fields, Meta_Data, Data_Stream, max(0, Debug_Level))
                    #
                    Results["ITEM_ENTRIES_OFS"] = Decrypted_Item_Entries["ALIGN"]["OFS"]
                    Results["ITEM_ENTRIES_SIZE"] = Decrypted_Item_Entries["ALIGN"]["SIZE"]
                    Results["ITEM_NAMES_OFS"] = Decrypted_Item_Names["ALIGN"]["OFS"]
                    Results["ITEM_NAMES_SIZE"] = Decrypted_Item_Names["ALIGN"]["SIZE"]
                    Results["ITEMS_INFO_SIZE"] = Results["ITEM_ENTRIES_SIZE"]+Results["ITEM_NAMES_SIZE"]
                    #
                    if (Results["ITEM_ENTRIES_OFS"]+Results["ITEM_ENTRIES_SIZE"] != Results["ITEM_NAMES_OFS"]):
                        eprint("Item Names are not directly following the Item Entries {:#0x} <> {:#0x}+{:#0x}={:#0x}.".format(Results["ITEM_NAMES_OFS"], Results["ITEM_ENTRIES_OFS"], Results["ITEM_ENTRIES_SIZE"], Results["ITEM_ENTRIES_OFS"]+Results["ITEM_ENTRIES_SIZE"]), Data_Stream.getSource(), prefix="[UNKNOWN] ")
                    if 0xD in Meta_Data \
                    and Results["ITEMS_INFO_SIZE"] != Meta_Data[0xD]["SIZE"]:
                        eprint("Calculated Items Info size {:#} <> {:#} from match meta data 0xD.".format(Results["ITEMS_INFO_SIZE"], Meta_Data[0xD]["SIZE"]), Data_Stream.getSource())
                    #
                    if Raw_Stream:
                        if Debug_Level >= 2:
                            dprint("Write PKG3 unencrypted item entries from offset {:#x} and size {}".format(Decrypted_Item_Entries["ALIGN"]["OFS"]+Header_Fields["DATAOFS"], len(Decrypted_Item_Entries["DATA"])), prefix="[RAW] ")
                        Raw_Stream.write(Decrypted_Item_Entries["DATA"])
                        if Debug_Level >= 2:
                            dprint("Write PKG3 unencrypted item names from offset {:#x} and size {}".format(Decrypted_Item_Names["ALIGN"]["OFS"]+Header_Fields["DATAOFS"], len(Decrypted_Item_Names["DATA"])), prefix="[RAW] ")
                        Raw_Stream.write(Decrypted_Item_Names["DATA"])
                    del Decrypted_Item_Entries
                    del Decrypted_Item_Names
                #
                if not Item_Entries is None \
                and Retrieve_Encrypted_Param_Sfo:
                    for Item_Entry in Item_Entries:
                        Item_Data = None
                        if Retrieve_Encrypted_Param_Sfo \
                        and "NAME" in Item_Entry \
                        and Item_Entry["NAME"] == Header_Fields["PARAM.SFO"] \
                        and Item_Entry["DATASIZE"] > 0:
                            Item_Data = {}
                            Item_Data["ENCRYPTED"] = bytearray()
                            Item_Data["DECRYPTED"] = bytearray()
                        #
                        if Item_Data:
                            processPkg3Item(Header_Fields, Item_Entry, Data_Stream, Item_Data, None, None, max(0, Debug_Level))
                            #
                            if Retrieve_Encrypted_Param_Sfo \
                            and "NAME" in Item_Entry \
                            and Item_Entry["NAME"] == Header_Fields["PARAM.SFO"] \
                            and Item_Entry["DATASIZE"] > 0:
                                Sfo_Item_Data = Item_Data
                                Sfo_Bytes = Sfo_Item_Data["DECRYPTED"][Item_Entry["ALIGN"]["OFSDELTA"]:Item_Entry["ALIGN"]["OFSDELTA"]+Item_Entry["DATASIZE"]]
                        #
                        del Item_Data
                    del Item_Entry
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Header_Fields, File_Table, File_Table_Map = parsePkg4Header(Header_Bytes, Data_Stream, max(0, Debug_Level), print_unknown=Arguments.unknown)
                ## --> Size of package (=file size)
                if "PKGSIZE" in Header_Fields:
                    Results["PKG_TOTAL_SIZE"] = Header_Fields["PKGSIZE"]
                ## --> Package content id
                if "CID" in Header_Fields:
                    Results["PKG_CONTENT_ID"] = Header_Fields["CID"]
                ## --> param.sfo offset + size
                if CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO in File_Table_Map:
                    File_Entry = File_Table[File_Table_Map[CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO]]
                    Results["PKG_SFO_OFFSET"] = File_Entry["DATAOFS"]
                    Results["PKG_SFO_SIZE"] = File_Entry["DATASIZE"]
                ## --> DRM Type
                if "DRMTYPE" in Header_Fields:
                    Results["PKG_DRM_TYPE"] = Header_Fields["DRMTYPE"]
                ## --> Content Type
                if "CONTTYPE" in Header_Fields:
                    Results["PKG_CONTENT_TYPE"] = Header_Fields["CONTTYPE"]
            #
            if "PKG_TITLE_ID" in Results \
            and Results["PKG_TITLE_ID"].strip():
                Results["TITLE_ID"] = Results["PKG_TITLE_ID"].strip()
            #
            if "PKG_CONTENT_ID" in Results \
            and Results["PKG_CONTENT_ID"].strip():
                Results["CONTENT_ID"] = Results["PKG_CONTENT_ID"].strip()
                if not ("PKG_TITLE_ID" in Results \
                        and Results["PKG_TITLE_ID"].strip()):
                    Results["TITLE_ID"] = Results["CONTENT_ID"][7:16]

            ## Retrieve PARAM.SFO from unencrypted data if present
            if "PKG_SFO_OFFSET" in Results \
            and Results["PKG_SFO_OFFSET"] > 0 \
            and not Sfo_Bytes:
                if Debug_Level >= 2:
                    dprint(">>>>> PARAM.SFO:")
                ## Get PARAM.SFO from data stream
                if Debug_Level >= 2:
                    dprint("Get PARAM.SFO from unencrypted data with offset {:#x} with size {}".format(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"]), end=" ")
                Sfo_Bytes = bytearray()
                if len(Header_Bytes) > (Results["PKG_SFO_OFFSET"]+Results["PKG_SFO_SIZE"]):
                    if Debug_Level >= 2:
                        dprint("from header data", prefix=None)
                    Sfo_Bytes.extend(Header_Bytes[Results["PKG_SFO_OFFSET"]:Results["PKG_SFO_OFFSET"]+Results["PKG_SFO_SIZE"]])
                else:
                    if Debug_Level >= 2:
                        dprint("from data stream", prefix=None)
                    try:
                        Sfo_Bytes.extend(Data_Stream.read(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"], Debug_Level))
                    except:
                        Data_Stream.close(Debug_Level)
                        eprint("Could not get PARAM.SFO at offset {:#x} with size {} from".format(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"]), Data_Stream.getSource())
                        eprint("", prefix=None)
                        sys.exit(2)

            ## Process PARAM.SFO if present
            if Sfo_Bytes:
                ## Check for known PARAM.SFO data
                SfoMagic = getInteger32BitLE(Sfo_Bytes, 0)
                if SfoMagic != 0x46535000:
                    Data_Stream.close(Debug_Level)
                    eprint("Not a known PARAM.SFO structure ({:#x} <> 0x46535000)".format(SfoMagic), Data_Stream.getSource())
                    eprint("", prefix=None)
                    sys.exit(2)

                ## Process PARAM.SFO data
                Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                ## -->
                if "TITLE_ID" in Sfo_Values:
                    Results["SFO_TITLE_ID"] = Sfo_Values["TITLE_ID"]
                ## -->
                if "CONTENT_ID" in Sfo_Values:
                    Results["SFO_CONTENT_ID"] = Sfo_Values["CONTENT_ID"]
                ## --> Firmware PS4
                if "SYSTEM_VER" in Sfo_Values \
                and Sfo_Values["SYSTEM_VER"]:
                    Results["SFO_MIN_VER"] = float("{:02x}.{:02x}".format((Sfo_Values["SYSTEM_VER"] >> 24) & 0xff, (Sfo_Values["SYSTEM_VER"] >> 16) & 0xff))
                ## --> Firmware PS3
                if "PS3_SYSTEM_VER" in Sfo_Values \
                and Sfo_Values["PS3_SYSTEM_VER"]:
                    Results["SFO_MIN_VER"] = float(Sfo_Values["PS3_SYSTEM_VER"])
                ## --> Firmware PS Vita
                if "PSP2_DISP_VER" in Sfo_Values \
                and Sfo_Values["PSP2_DISP_VER"]:
                    Results["SFO_MIN_VER"] = float(Sfo_Values["PSP2_DISP_VER"])
                ## -->
                if "CATEGORY" in Sfo_Values:
                    Results["SFO_CATEGORY"] = Sfo_Values["CATEGORY"]
                ## -->
                if "VERSION" in Sfo_Values \
                and Sfo_Values["VERSION"]:
                    Results["SFO_VERSION"] = float(Sfo_Values["VERSION"])
                ## -->
                if "APP_VER" in Sfo_Values \
                and Sfo_Values["APP_VER"]:
                    Results["SFO_APP_VER"] = float(Sfo_Values["APP_VER"])
                ## -->
                if "PUBTOOLINFO" in Sfo_Values:
                    try:
                        Results["SFO_CREATION_DATE"] = Sfo_Values["PUBTOOLINFO"][7:15]
                        Results["SFO_SDK_VER"] = int(Sfo_Values["PUBTOOLINFO"][24:32]) / 1000000
                    except:
                        pass
                #
                if "SFO_TITLE_ID" in Results \
                and Results["SFO_TITLE_ID"].strip():
                    Results["TITLE_ID"] = Results["SFO_TITLE_ID"].strip()
                #
                if "SFO_CONTENT_ID" in Results \
                and Results["SFO_CONTENT_ID"].strip():
                    Results["CONTENT_ID"] = Results["SFO_CONTENT_ID"].strip()
                    if not ("SFO_TITLE_ID" in Results
                            and Results["SFO_TITLE_ID"].strip()):
                        Results["TITLE_ID"] = Results["CONTENT_ID"][7:16]
            #
            if not "SFO_MIN_VER" in Results:
                Results["SFO_MIN_VER"] = 0.00  ## mandatory value

            ## Determine platform and package type
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                if "PKG_CONTENT_TYPE" in Results:
                    ## TODO: Complete and optimize coding
                    ## PS3 packages
                    if Results["PKG_CONTENT_TYPE"] == 0x4 \
                    or Results["PKG_CONTENT_TYPE"] == 0xB:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        if 0xB in Meta_Data:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                    elif Results["PKG_CONTENT_TYPE"] == 0x5:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                    elif Results["PKG_CONTENT_TYPE"] == 0x9:
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC  #md_entry_type = 9 | Also PS3 THEMES : md_entry_type = 9
                    elif Results["PKG_CONTENT_TYPE"] == 0xD:
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.AVATAR  #md_entry_type = 9
                    ## PSX packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x1 \
                    or Results["PKG_CONTENT_TYPE"] == 0x6:
                        Results["PLATFORM"] = CONST_PLATFORM.PSX
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        ## TODO: find_psp_info > title id
                        Results["PKG_EXTRACT_ROOT"] = os.path.join("pspemu", "PSP", "GAME", Results["TITLE_ID"])  ## TODO: maybe explicitly <PKG_|PSP_>TITLE_ID
                    ## PSP packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x7 \
                    or Results["PKG_CONTENT_TYPE"] == 0xE \
                    or Results["PKG_CONTENT_TYPE"] == 0xF \
                    or Results["PKG_CONTENT_TYPE"] == 0x10:
                        Results["PLATFORM"] = CONST_PLATFORM.PSP
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        Results["PKG_EXTRACT_ROOT"] = "pspemu/ISO"
                        if Results["PKG_CONTENT_TYPE"] == 0x7:
                            ## TODO: find_psp_info > category == "HG" ? "PSP-PCEngine" : "PSP"
#                            if 0xB in Meta_Data:
#                                Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
# #md_entry_type = 9 | Also PSP DLCS : md_entry_type = 10
                            if False:
                                Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_PC_ENGINE
                            else:
                                ## TODO: find_psp_info > title id
                                Results["PKG_EXTRACT_ROOT"] = os.path.join("pspemu", "PSP", "GAME", Results["TITLE_ID"])  ## TODO: maybe explicitly <PKG_|PSP_>TITLE_ID
                        elif Results["PKG_CONTENT_TYPE"] == 0xE:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_GO
                        elif Results["PKG_CONTENT_TYPE"] == 0xF:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_MINI
                        elif Results["PKG_CONTENT_TYPE"] == 0x10:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_NEOGEO
                    ## PSV packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x15:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        if "SFO_CATEGORY" in Results \
                        and Results["SFO_CATEGORY"] == "gp":
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                            Results["PKG_EXTRACT_ROOT"] = os.path.join("patch", Results["TITLE_ID"])  ## TODO: maybe explicitly <PKG_|SFO_>TITLE_ID
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                            Results["PKG_EXTRACT_ROOT"] = os.path.join("app", Results["TITLE_ID"])  ## TODO: maybe explicitly <PKG_|SFO_>TITLE_ID
                    elif Results["PKG_CONTENT_TYPE"] == 0x16:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                        Results["PKG_EXTRACT_ROOT"] = os.path.join("addcont", Results["TITLE_ID"], Results["CONTENT_ID"])  ## TODO: maybe explicitly <PKG_|SFO_><TITLE_ID|CONTENT_ID>
                    elif Results["PKG_CONTENT_TYPE"] == 0x1F:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.THEME
                    ## PSM packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x18 \
                    or Results["PKG_CONTENT_TYPE"] == 0x1D:
                        Results["PLATFORM"] = CONST_PLATFORM.PSM
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        Results["PKG_EXTRACT_ROOT"] = os.path.join("psm", Results["TITLE_ID"])  ## TODO: maybe explicitly <PKG_|SFO_>TITLE_ID
                        print(Results["PKG_EXTRACT_ROOT"])
                    ## UNKNOWN packages
                    else:
                        eprint("PKG content type {0}/{0:#0x} not supported.".format(Results["PKG_CONTENT_TYPE"]), Data_Stream.getSource(), prefix="[UNKNOWN] ")
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Results["PLATFORM"] = CONST_PLATFORM.PS4

            ## Prepare package extraction path
            if Arguments.extract:
                if "PKG_EXTRACT_ROOT" in Results:
                    Target = os.path.join(Arguments.extract, Results["PKG_EXTRACT_ROOT"])
                    if not 3 in Arguments.format \
                    and not 98 in Arguments.format:  ## Special case JSON output for parsing
                        print("# >>> Extraction path for package:", Target)
                    else:
                        eprint("# >>> Extraction path for package:", Target, prefix=None)
                    #
                    if not os.path.exists(Target):
                        eprint("Creating package extraction path.", Target, prefix="[EXTRACT] ")
                        os.makedirs(Target)
                        Results["PKG_EXTRACT_PATH"] = Target
                    elif os.path.isdir(Arguments.extract):
                        if Arguments.overwrite:
                            Results["PKG_EXTRACT_PATH"] = Target
                        else:
                            eprint("Extraction path already exists and will NOT be WRITTEN.", Target)
                    else:
                        eprint("Extraction path already exists and is NOT a DIRECTORY.", Target)
                    #
                    del Target
                else:
                    eprint("Extraction not supported for package type", end=" ")
                    if "PLATFORM" in Results:
                        eprint(Results["PLATFORM"], end=" ")
                    if "PKG_TYPE" in Results:
                        eprint(Results["PKG_TYPE"], end=" ")
                    if "PKG_SUB_TYPE" in Results:
                        eprint(Results["PKG_SUB_TYPE"], end=" ")
                    eprint()

            ## Process GAME PKG items/files and tail for --extract and --raw
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                if not Item_Entries is None \
                and (Raw_Stream \
                     or "PKG_EXTRACT_PATH" in Results):
                    dprint("Executing --raw/--extract")
                    Item_Entries_Sorted = sorted(Item_Entries, key=lambda x: x["DATAOFS"])
                    for Item_Entry in Item_Entries_Sorted:
                        if Item_Entry["DATASIZE"] <= 0:
                            if "PKG_EXTRACT_PATH" in Results:
                                pass ## TODO
                            #
                            continue
                        #
                        Item_Data = None
                        Used_Data_Stream = Data_Stream
                        #
                        if Sfo_Item_Data \
                        and "NAME" in Item_Entry \
                        and Item_Entry["NAME"] == Header_Fields["PARAM.SFO"] \
                        and Item_Entry["DATASIZE"] > 0:
                            Used_Data_Stream = None
                            Item_Data = Sfo_Item_Data
                        #
                        Extract_Stream = None
                        if "PKG_EXTRACT_PATH" in Results:
                            Extract_Stream = None  ## TODO
                        #
                        if Raw_Stream \
                        or Extract_Stream:
                            processPkg3Item(Header_Fields, Item_Entry, Used_Data_Stream, Item_Data, Raw_Stream, Extract_Stream, max(0, Debug_Level))
                        #
                        if Extract_Stream:
                            Extract_Stream.close()
                        #
                        del Item_Data
                        del Used_Data_Stream
                    #
                    del Item_Entry
                    del Item_Entries_Sorted

                ## Get unencrypted tail data
                if Debug_Level >= 2:
                    dprint(">>>>> PKG3 Tail:")
                    dprint("Get PKG3 tail data from offset {:#x}".format(Header_Fields["DATAOFS"]+Header_Fields["DATASIZE"]))
                try:
                    Tail_Bytes = Data_Stream.read(Header_Fields["DATAOFS"]+Header_Fields["DATASIZE"], -1, Debug_Level)
                except:
                    Data_Stream.close(Debug_Level)
                    eprint("Could not get PKG3 unencrypted tail at offset {:#x} from".format(Header_Fields["DATAOFS"]+Header_Fields["DATASIZE"]), Data_Stream.getSource())
                    eprint("", prefix=None)
                    sys.exit(2)
                #
                Results["PKG_TAIL_SIZE"] = len(Tail_Bytes)
                Results["PKG_TAIL_SHA1"] = Tail_Bytes[-0x20:-0x0c]

                ## Write unencrypted tail data
                if Raw_Stream:
                    if Debug_Level >= 2:
                        dprint("Write PKG3 unencrypted tail data from offset {:#x} and size {}".format(Header_Fields["DATAOFS"]+Header_Fields["DATASIZE"], Results["PKG_TAIL_SIZE"]), prefix="[RAW] ")
                    Raw_Stream.write(Tail_Bytes)
                    Raw_Size_Written = Raw_Stream.tell()
                    Raw_Stream.close()
                    if ("PKG_TOTAL_SIZE" in Results \
                        and Raw_Size_Written != Results["PKG_TOTAL_SIZE"]) \
                    or ("FILE_SIZE" in Results \
                        and Raw_Size_Written != Results["FILE_SIZE"]):
                        eprint("Written size {} of unencrypted/decrypted data from".format(Raw_Size_Written), Data_Stream.getSource())
                        if ("PKG_TOTAL_SIZE" in Results \
                            and Raw_Size_Written != Results["PKG_TOTAL_SIZE"]):
                            eprint("mismatches package total size of", Results["PKG_TOTAL_SIZE"])
                        if ("FILE_SIZE" in Results \
                            and Raw_Size_Written != Results["FILE_SIZE"]):
                            eprint("mismatches file size of", Results["FILE_SIZE"])
                        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
                    del Raw_Size_Written
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                pass  ## TODO: not supported yet

            ## Close data stream
            Data_Stream.close(Debug_Level)

            ## Determine some derived variables
            if Debug_Level >= 1:
                dprint(">>>>> Results:")
            ## a) Region and related languages
            if "CONTENT_ID" in Results \
            and Results["CONTENT_ID"].strip():
                Results["REGION"], Results["LANGUAGES"] = getRegion(Results["CONTENT_ID"][0])
                if Results["LANGUAGES"] is None:
                    Results["LANGUAGES"]
            ## b) International/English title
            for Language in ["01", "18"]:
                Key = "".join(("TITLE_", Language))
                if Sfo_Values \
                and Key in Sfo_Values \
                and Sfo_Values[Key].strip():
                   if Debug_Level >= 2:
                       dprint("Set international name to", Key)
                   Results["SFO_TITLE"] = Sfo_Values[Key].strip()
                   break
            if not "SFO_TITLE" in Results \
            and Sfo_Values \
            and "TITLE" in Sfo_Values \
            and Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set international title to TITLE")
                Results["SFO_TITLE"] = Sfo_Values["TITLE"].strip()
            ## --> Clean international/english title
            if "SFO_TITLE" in Results \
            and not Arguments.unclean:
                if Replace_List:
                    for Replace_Chars in Replace_List:
                        if Debug_Level >= 2:
                            dprint("Clean international title from", Replace_Chars[0])
                        for _i in range(len(Replace_Chars[0])):
                            Replace_Char = Replace_Chars[0][_i]
                            if Replace_Chars[1] == " ":
                                Results["SFO_TITLE"] = Results["SFO_TITLE"].replace("".join((Replace_Char, ":")), ":")
                            Results["SFO_TITLE"] = Results["SFO_TITLE"].replace(Replace_Char, Replace_Chars[1])
                Results["SFO_TITLE"] = re.sub(r"\s+", " ", Results["SFO_TITLE"], 0, re.UNICODE).strip()  ## also replaces \u3000
                ## Condense demo information in title to "(DEMO)"
                Results["SFO_TITLE"] = Results["SFO_TITLE"].replace("demo ver.", "(DEMO)").replace("(Demo Version)", "(DEMO)").replace("Demo Version", "(DEMO)").replace("Demo version", "(DEMO)").replace("DEMO Version", "(DEMO)").replace("DEMO version", "(DEMO)").replace("【体験版】", "(DEMO)").replace("(体験版)", "(DEMO)").replace("体験版", "(DEMO)").strip()
                Results["SFO_TITLE"] = re.sub(r"\(demo\)", r"(DEMO)", Results["SFO_TITLE"], 0, re.IGNORECASE|re.UNICODE)
                Results["SFO_TITLE"] = re.sub(r"(^|[^a-z(]{1})demo([^a-z)]{1}|$)", r"\1(DEMO)\2", Results["SFO_TITLE"], 0, re.IGNORECASE|re.UNICODE)
            ## c) Regional title
            if "LANGUAGES" in Results \
            and Results["LANGUAGES"]:
                for Language in Results["LANGUAGES"]:
                    Key = "".join(("TITLE_", Language))
                    if Sfo_Values \
                    and Key in Sfo_Values \
                    and Sfo_Values[Key].strip():
                       if Debug_Level >= 2:
                           dprint("Set regional title to", Key)
                       Results["SFO_TITLE_REGIONAL"] = Sfo_Values[Key].strip()
                       break
            if not "SFO_TITLE_REGIONAL" in Results \
            and Sfo_Values \
            and "TITLE" in Sfo_Values \
            and Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set regional title to TITLE")
                Results["SFO_TITLE_REGIONAL"] = Sfo_Values["TITLE"].strip()
            ## --> Clean regional title
            if "SFO_TITLE_REGIONAL" in Results \
            and not Arguments.unclean:
                if Replace_List:
                    for Replace_Chars in Replace_List:
                        if Debug_Level >= 2:
                            dprint("Clean regional title from", Replace_Chars[0])
                        for _i in range(len(Replace_Chars[0])):
                            Replace_Char = Replace_Chars[0][_i]
                            if Replace_Chars[1] == " ":
                                Results["SFO_TITLE_REGIONAL"] = Results["SFO_TITLE_REGIONAL"].replace("".join((Replace_Char, ":")), ":")
                            Results["SFO_TITLE_REGIONAL"] = Results["SFO_TITLE_REGIONAL"].replace(Replace_Char, Replace_Chars[1])
                Results["SFO_TITLE_REGIONAL"] = re.sub(r"\s+", " ", Results["SFO_TITLE_REGIONAL"], 0, re.UNICODE).strip()  ## also replaces \u3000

            ## Determine NPS package type from data
            if not "PKG_CONTENT_TYPE" in Results:
                eprint("PKG content type missing.", Data_Stream.getSource())
            else:
                if Results["PKG_CONTENT_TYPE"] == 0x1 \
                or Results["PKG_CONTENT_TYPE"] == 0x6:
                    Nps_Type = "PSX GAME"  #md_entry_type = 9
                    if Results["PKG_CONTENT_TYPE"] == 0x6:
                        Results["PSX_TITLE_ID"] = Header_Bytes[712:721].decode("utf-8", errors="ignore")
                elif Results["PKG_CONTENT_TYPE"] == 0x4 \
                or Results["PKG_CONTENT_TYPE"] == 0xB:
                    if 0xB in Meta_Data:
                        Nps_Type = "PS3 UPDATE"
                    else:
                        Nps_Type = "PS3 DLC"  #md_entry_type = 9 | Also PS3 updates : md_entry_type = 11
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                elif Results["PKG_CONTENT_TYPE"] == 0x5:
                    Nps_Type = "PS3 GAME"  #md_entry_type = 5
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                elif Results["PKG_CONTENT_TYPE"] == 0x7 \
                or Results["PKG_CONTENT_TYPE"] == 0xE \
                or Results["PKG_CONTENT_TYPE"] == 0xF \
                or Results["PKG_CONTENT_TYPE"] == 0x10:
                    ## PSP & PSP-PCEngine / PSP-Go / PSP-Mini / PSP-NeoGeo
                    if 0xB in Meta_Data:
                        Nps_Type = "PSP DLC"
                    else:
                        Nps_Type = "PSP GAME"  #md_entry_type = 9 | Also PSP DLCS : md_entry_type = 10
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                elif Results["PKG_CONTENT_TYPE"] == 0x9:
                    Nps_Type = "PSP or PS3 THEME"  #md_entry_type = 9 | Also PS3 THEMES : md_entry_type = 9
                elif Results["PKG_CONTENT_TYPE"] == 0xD:
                    Nps_Type = "PS3 AVATAR"  #md_entry_type = 9
                elif Results["PKG_CONTENT_TYPE"] == 0x15:
                    Nps_Type = "PSV GAME"  #md_entry_type = 18
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"] == "gp":
                        Nps_Type = "PSV UPDATE"
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                        Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                        del Update_Hash
                elif Results["PKG_CONTENT_TYPE"] == 0x16:
                    Nps_Type = "PSV DLC"  #md_entry_type = 17
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                        Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                        del Update_Hash
                elif Results["PKG_CONTENT_TYPE"] == 0x1F:
                    Nps_Type = "PSV THEME"  #md_entry_type = 17
                elif Results["PKG_CONTENT_TYPE"] == 0x18 \
                or Results["PKG_CONTENT_TYPE"] == 0x1D:
                    Nps_Type = "PSM GAME"  #md_entry_type = 16
                else:
                    eprint("PKG content type {0}/{0:#0x} not supported.".format(Results["PKG_CONTENT_TYPE"]), Data_Stream.getSource(), prefix="[UNKNOWN] ")
            #
            Results["NPS_TYPE"] = Nps_Type

            for Output_Format in Arguments.format:
                if Output_Format == 0:  ## Human-readable reduced Output
                    print()
                    print("{:13} {}".format("NPS Type:", Results["NPS_TYPE"]))
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        print("{:13} {}".format("Title ID:", Results["TITLE_ID"]))
                    if "SFO_TITLE" in Results \
                    and Results["SFO_TITLE"].strip():
                        print("{:13} {}".format("Title:", Results["SFO_TITLE"]))
                    if "SFO_TITLE_REGIONAL" in Results\
                    and Results["SFO_TITLE_REGIONAL"].strip():
                        print("{:13} {}".format("Title Region:", Results["SFO_TITLE_REGIONAL"].strip()))
                    if "REGION" in Results \
                    and Results["REGION"].strip():
                        print("{:13} {}".format("Region:", Results["REGION"]))
                    if "SFO_MIN_VER" in Results \
                    and Results["SFO_MIN_VER"] >= 0:
                        print("{:13} {:.2f}".format("Min FW:", Results["SFO_MIN_VER"]))
                    if "SFO_SDK_VER" in Results \
                    and Results["SFO_SDK_VER"] >= 0:
                        print("{:13} {:.2f}".format("SDK Ver:", Results["SFO_SDK_VER"]))
                    if "SFO_CREATION_DATE" in Results \
                    and Results["SFO_CREATION_DATE"].strip():
                        print("{:13} {}".format("c_date:", datetime.strptime(Results["SFO_CREATION_DATE"], "%Y%m%d").strftime("%Y.%m.%d")))
                    if "SFO_VERSION" in Results\
                    and Results["SFO_VERSION"] >= 0:
                        print("{:13} {:.2f}".format("Version:", Results["SFO_VERSION"]))
                    if "SFO_APP_VER" in Results \
                    and Results["SFO_APP_VER"] >= 0:
                        print("{:13} {:.2f}".format("App Ver:", Results["SFO_APP_VER"]))
                    if "PSX_TITLE_ID" in Results \
                    and Results["PSX_TITLE_ID"].strip():
                        print("{:13} {}".format("PSX Title ID:", Results["PSX_TITLE_ID"]))
                    if "CONTENT_ID" in Results \
                    and Results["CONTENT_ID"].strip():
                        print("{:13} {}".format("Content ID:", Results["CONTENT_ID"]))
                        if "SFO_CONTENT_ID" in Results \
                        and Results["SFO_CONTENT_ID"].strip() \
                        and "PKG_CONTENT_ID" in Results \
                        and Results["PKG_CONTENT_ID"].strip() != Results["SFO_CONTENT_ID"].strip():
                            print("{:13} {}".format("PKG Hdr CID:", Results["PKG_CONTENT_ID"]))
                    if "PKG_TOTAL_SIZE" in Results \
                    and Results["PKG_TOTAL_SIZE"] > 0:
                        print("{:13} {}".format("Size:", Results["PKG_TOTAL_SIZE"]))
                        print("{:13} {}".format("Pretty Size:", prettySize(Results["PKG_TOTAL_SIZE"])))
                    if "FILE_SIZE" in Results:
                        print("{:13} {}".format("File Size:", Results["FILE_SIZE"]))
                    if "TITLE_UPDATE_URL" in Results \
                    and Results["TITLE_UPDATE_URL"].strip():
                        print("{:13} {}".format("Update URL:", Results["TITLE_UPDATE_URL"]))
                    print()
                elif Output_Format == 1:  ## Linux Shell Variable Output
                    if "PKG_TOTAL_SIZE" in Results \
                    and Results["PKG_TOTAL_SIZE"] > 0:
                        print("PSN_PKG_SIZE='{}'".format(Results["PKG_TOTAL_SIZE"]))
                    else:
                        print("unset PSN_PKG_SIZE")
                    print("PSN_PKG_NPS_TYPE='{}'".format(Results["NPS_TYPE"]))
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        print("PSN_PKG_TITLEID='{}'".format(Results["TITLE_ID"]))
                    else:
                        print("unset PSN_PKG_TITLEID")
                    if "CONTENT_ID" in Results \
                    and Results["CONTENT_ID"].strip():
                        print("PSN_PKG_CONTENTID='{}'".format(Results["CONTENT_ID"]))
                        print("PSN_PKG_REGION='{}'".format(Results["REGION"].replace("(HKG)", "").replace("(KOR)", "")))
                    else:
                        print("unset PSN_PKG_CONTENTID")
                        print("unset PSN_PKG_REGION")
                    if "SFO_TITLE" in Results \
                    and Results["SFO_TITLE"].strip():
                        print("PSN_PKG_SFO_TITLE=\"\\\"{}\\\"\"".format(Results["SFO_TITLE"].replace("\"", "\\\"\\\"")))
                    else:
                        print("unset PSN_PKG_SFO_TITLE")
                    if "SFO_TITLE_REGIONAL" in Results \
                    and Results["SFO_TITLE_REGIONAL"].strip():
                        print("PSN_PKG_SFO_TITLE_REGION=\"\\\"{}\\\"\"".format(Results["SFO_TITLE_REGIONAL"].strip().replace("\"", "\\\"\\\"")))
                    else:
                        print("unset PSN_PKG_SFO_TITLE_REGION")
                    if "SFO_MIN_VER" in Results \
                    and Results["SFO_MIN_VER"] >= 0:
                        print("PSN_PKG_SFO_FW_VER='{:.2f}'".format(Results["SFO_MIN_VER"]))
                    else:
                        print("unset PSN_PKG_SFO_FW_VER")
                    if "SFO_VERSION" in Results \
                    and Results["SFO_VERSION"] >= 0:
                        print("PSN_PKG_SFO_VERSION='{:.2f}'".format(Results["SFO_VERSION"]))
                    else:
                        print("unset PSN_PKG_SFO_VERSION")
                    if "SFO_APP_VER" in Results \
                    and Results["SFO_APP_VER"] >= 0:
                        print("PSN_PKG_SFO_APP_VER='{:.2f}'".format(Results["SFO_APP_VER"]))
                    else:
                        print("unset PSN_PKG_SFO_APP_VER")
                    if "SFO_SDK_VER" in Results \
                    and Results["SFO_SDK_VER"] >= 0:
                        print("PSN_PKG_SFO_SDK_VER='{:.2f}'".format(Results["SFO_SDK_VER"]))
                    else:
                        print("unset PSN_PKG_SFO_SDK_VER")
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"].strip():
                        print("PSN_PKG_SFO_CATEGORY='{}'".format(Results["SFO_CATEGORY"]))
                    else:
                        print("unset PSN_PKG_SFO_CATEGORY")
                    if "SFO_CREATION_DATE" in Results \
                    and Results["SFO_CREATION_DATE"].strip():
                        print("PSN_PKG_SFO_CREATION='{}'".format(Results["SFO_CREATION_DATE"]))
                    else:
                        print("unset PSN_PKG_SFO_CREATION")
                    if "PSX_TITLE_ID" in Results \
                    and Results["PSX_TITLE_ID"].strip():
                        print("PSN_PKG_PSXTITLEID='{}'".format(Results["PSX_TITLE_ID"]))
                    else:
                        print("unset PSN_PKG_PSXTITLEID")
                    if "FILE_SIZE" in Results:
                        print("PSN_PKG_FILESIZE='{}'".format(Results["FILE_SIZE"]))
                    else:
                        print("unset PSN_PKG_FILESIZE")
                elif Output_Format == 3 \
                or Output_Format == 98:  ## Results/Analysis JSON Output
                    JSON_Output = collections.OrderedDict()
                    #
                    JSON_Output["results"] = collections.OrderedDict()
                    JSON_Output["results"]["npsType"] = Results["NPS_TYPE"]
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        JSON_Output["results"]["titleId"] = Results["TITLE_ID"]
                    if "SFO_TITLE" in Results \
                    and Results["SFO_TITLE"].strip():
                        JSON_Output["results"]["title"] = Results["SFO_TITLE"]
                    if "SFO_TITLE_REGIONAL" in Results \
                    and Results["SFO_TITLE_REGIONAL"].strip():
                        JSON_Output["results"]["regionalTitle"] = Results["SFO_TITLE_REGIONAL"].strip()
                    if "CONTENT_ID" in Results \
                    and Results["CONTENT_ID"].strip():
                        JSON_Output["results"]["region"] = Results["REGION"]
                    if "SFO_MIN_VER" in Results \
                    and Results["SFO_MIN_VER"] >= 0:
                        JSON_Output["results"]["minFw"] = Results["SFO_MIN_VER"]
                    if "SFO_SDK_VER" in Results \
                    and Results["SFO_SDK_VER"] >= 0:
                        JSON_Output["results"]["sdkVer"] = Results["SFO_SDK_VER"]
                    if "SFO_CREATION_DATE" in Results \
                    and Results["SFO_CREATION_DATE"].strip():
                        JSON_Output["results"]["creationDate"] = datetime.strptime(Results["SFO_CREATION_DATE"], "%Y%m%d").strftime("%Y.%m.%d")
                    if "SFO_VERSION" in Results \
                    and Results["SFO_VERSION"] >= 0:
                        JSON_Output["results"]["version"] = Results["SFO_VERSION"]
                    if "SFO_APP_VER" in Results \
                    and Results["SFO_APP_VER"] >= 0:
                        JSON_Output["results"]["appVer"] = Results["SFO_APP_VER"]
                    if "PSX_TITLE_ID" in Results \
                    and Results["PSX_TITLE_ID"].strip():
                        JSON_Output["results"]["psxTitleId"] = Results["PSX_TITLE_ID"]
                    if "CONTENT_ID" in Results \
                    and Results["CONTENT_ID"].strip():
                        JSON_Output["results"]["contentId"] = Results["CONTENT_ID"]
                        if "SFO_CONTENT_ID" in Results \
                        and Results["SFO_CONTENT_ID"].strip() \
                        and "PKG_CONTENT_ID" in Results \
                        and Results["PKG_CONTENT_ID"].strip() != Results["SFO_CONTENT_ID"].strip():
                            JSON_Output["results"]["pkgContentId"] = Results["PKG_CONTENT_ID"]
                    if "PKG_TOTAL_SIZE" in Results \
                    and Results["PKG_TOTAL_SIZE"] > 0:
                        JSON_Output["results"]["pkgTotalSize"] = Results["PKG_TOTAL_SIZE"]
                        JSON_Output["results"]["prettySize"] = prettySize(Results["PKG_TOTAL_SIZE"])
                    if "FILE_SIZE" in Results:
                        JSON_Output["results"]["fileSize"] = Results["FILE_SIZE"]
                    JSON_Output["results"]["pkgUrl"] = Data_Stream.getSource()
                    if "TITLE_UPDATE_URL" in Results \
                    and Results["TITLE_UPDATE_URL"].strip():
                        JSON_Output["results"]["titleUpdateUrl"] = Results["TITLE_UPDATE_URL"]
                    #
                    if Output_Format == 98:  ## Analysis JSON Output
                        JSON_Output["headerFields"] = Header_Fields
                        del JSON_Output["headerFields"]["STRUCTURE_DEF"]
                        if Ext_Header_Fields:
                            JSON_Output["extHeaderFields"] = Ext_Header_Fields
                            del JSON_Output["extHeaderFields"]["STRUCTURE_DEF"]
                        if Meta_Data:
                            JSON_Output["metaData"] = Meta_Data
                        if Sfo_Values:
                            JSON_Output["paramSfo"] = Sfo_Values
                        if Item_Entries:
                            JSON_Output["itemEntries"] = copy.deepcopy(Item_Entries)
                            for Item_Entry in JSON_Output["itemEntries"]:
                                del Item_Entry["STRUCTURE_DEF"]
                        if File_Table:
                            JSON_Output["fileTable"] = copy.deepcopy(File_Table)
                            for File_Entry in JSON_Output["fileTable"]:
                                del File_Entry["STRUCTURE_DEF"]
                    #
                    print(json.dumps(JSON_Output, ensure_ascii=False, indent=2, default=specialToJSON))
                    del JSON_Output
                elif Output_Format == 2 \
                or Output_Format == 99:  ## Results/Analysis Output
                    if Output_Format == 99:  ## Analysis Output
                        dprintFieldsDict(Header_Fields, "headerfields[{KEY:14}|{INDEX:2}]", 2, None, print_func=print)
                        if Ext_Header_Fields:
                            dprintFieldsDict(Ext_Header_Fields, "extheaderfields[{KEY:14}|{INDEX:2}]", 2, None, print_func=print)
                        if Meta_Data:
                            for Key in Meta_Data:
                                print("metadata[{:#04x}]:".format(Key), end=" ")
                                if "DESC" in Meta_Data[Key]:
                                    print("Desc \"", Meta_Data[Key]["DESC"], "\"", sep="", end=" ")
                                if "OFS" in Meta_Data[Key]:
                                    print("Ofs {:#012x}".format(Meta_Data[Key]["OFS"]), end=" ")
                                if "SIZE" in Meta_Data[Key]:
                                    print("Size {:12}".format(Meta_Data[Key]["SIZE"]), end=" ")
                                if "SHA256" in Meta_Data[Key]:
                                    print("SHA256", convertBytesToHexString(Meta_Data[Key]["SHA256"], sep=""), end=" ")
                                if "VALUE" in Meta_Data[Key]:
                                    if isinstance(Meta_Data[Key]["VALUE"], bytes) \
                                    or isinstance(Meta_Data[Key]["VALUE"], bytearray):
                                        print("Value", convertBytesToHexString(Meta_Data[Key]["VALUE"], sep=""), end=" ")
                                    else:
                                        print("Value", Meta_Data[Key]["VALUE"], end=" ")
                                if "UNKNOWN" in Meta_Data[Key]:
                                    print("Unknown", convertBytesToHexString(Meta_Data[Key]["UNKNOWN"], sep=""), end=" ")
                                print()
                        if Sfo_Values:
                            dprintFieldsDict(Sfo_Values, "sfovalues[{KEY:20}]", 2, None, print_func=print)
                        if Item_Entries:
                            Format_String = "".join(("{:", unicode(len(unicode(Header_Fields["ITEMCNT"]))), "}"))
                            for Item_Entry in Item_Entries:
                                print("".join(("itementries[", Format_String, "]: Ofs {:#012x} Size {:12} Key Index {} {}")).format(Item_Entry["INDEX"], Item_Entry["DATAOFS"], Item_Entry["DATASIZE"], Item_Entry["KEYINDEX"], "".join(("Name \"", Item_Entry["NAME"], "\"")) if "NAME" in Item_Entry else ""))
                        if File_Table:
                            Format_String = "".join(("{:", unicode(len(unicode(Header_Fields["FILECNT"]))), "}"))
                            for File_Entry in File_Table:
                                print("".join(("filetable[", Format_String, "]: ID {:#06x} Ofs {:#012x} Size {:12} {}")).format(File_Entry["INDEX"], File_Entry["FILEID"], File_Entry["DATAOFS"], File_Entry["DATASIZE"], "".join(("Name \"", File_Entry["NAME"], "\"")) if "NAME" in File_Entry else ""))
                            dprintFieldsDict(File_Table_Map, "filetablemap[{KEY:#06x}]", 2, None, print_func=print)
                    dprintFieldsDict(Results, "results[{KEY:20}]", 2, None, print_func=print, sep="")
            del Header_Bytes
            del Sfo_Item_Data
            del Sfo_Bytes
            del Tail_Bytes
            sys.stdout.flush()
            sys.stderr.flush()
    except SystemExit:
        raise  ## re-raise/throw up (let Python handle it)
    except:
        print_exc_plus()
