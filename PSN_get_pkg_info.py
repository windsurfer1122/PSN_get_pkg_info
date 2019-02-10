#!/usr/bin/env python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PSN_get_pky_info.py (c) 2018-2019 by "windsurfer1122"
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
### - use bytearray() instead of bytes() to avoid dumps on JSON output
### - convert byte string of struct.pack()/.unpack() to bytearray()
### - must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
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
__version__ = "2019.01.00a6"
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
import zlib
import base64
import xml.etree.ElementTree

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
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding \
and sys.stderr.encoding.lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("STDERR Encoding setting from {} to UTF-8".format(sys.stderr.encoding))
    sys.stderr.reconfigure(encoding="utf-8")

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

## Python 2/3 shortcoming: older zlib modules do not support compression dictionaries
Zrif_Support = False
try:
    Decompress_Object = zlib.decompressobj(wbits=8, zdict=bytes(2^8))
    del Decompress_Object
    Zrif_Support = True
except TypeError:
    pass


## Generic definitions
PYTHON_VERSION = ".".join((unicode(sys.version_info[0]), unicode(sys.version_info[1]), unicode(sys.version_info[2])))
#
OUTPUT_FORMATS = collections.OrderedDict([ \
   ( 0, "Human-readable reduced Output [default]" ),
   ( 1, "Linux Shell Variable Output" ),
   ( 2, "Results Output" ),
   ( 3, "Results Output in JSON format" ),
   ( 50, "Additional debugging Output (Extractions, etc.)" ),
   ( 98, "Analysis Output in JSON format" ),
   ( 99, "Analysis Output" ),
])
#
CONST_FMT_BIG_ENDIAN = ">"
CONST_FMT_LITTLE_ENDIAN = "<"
CONST_FMT_UINT64, CONST_FMT_UINT32, CONST_FMT_UINT16, CONST_FMT_UINT8 = "Q", "L", "H", "B"
CONST_FMT_INT64, CONST_FMT_INT32, CONST_FMT_INT16, CONST_FMT_INT8 = "q", "l", "h", "b"
CONST_FMT_CHAR = "s"
#
CONST_READ_SIZE = random.randint(50,100) * 0x100000  ## Read in 50-100 MiB chunks to reduce memory usage and swapping
CONST_READ_AHEAD_SIZE = 128 * 0x400 ## Read first 128 KiB to reduce read requests (fits header of known packages; Kib/Mib = 0x400/0x100000; biggest header + Items Info found was 2759936 = 0x2a1d00 = ~2.7 MiB)
#
CONST_EXTRACT_RAW = "RAW"
CONST_EXTRACT_UX0 = "UX0"
CONST_EXTRACT_CONTENT = "CONTENT"
#
CONST_DATATYPE_AS_IS = "AS-IS"
CONST_DATATYPE_DECRYPTED = "DECRYPTED"
CONST_DATATYPE_UNENCRYPTED = "UNENCRYPTED"
#
CONST_ZRIF_COMPRESSION_DICTIONARY = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003030303039000000000000000000000030303030363030303037303030303800303030303330303030343030303035305f30302d414444434f4e5430303030322d5043534730303030303030303030312d504353453030302d504353463030302d504353433030302d504353443030302d504353413030302d504353423030300001000100010002efcdab8967452301")

## Generic PKG definitions
CONST_CONTENT_ID_SIZE = 0x30  ## not 0x24 anymore, due to pkg2zip's extraction code for PSM's RW/System/content_id
CONST_SHA256_HASH_SIZE = 0x20
#
## --> Platforms
class CONST_PLATFORM(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = "PS3 PSX PSP PSV PSM PS4"
    PS3 = "PS3"
    PSX = "PSX"
    PSP = "PSP"
    PSV = "PSV"
    PSM = "PSM"
    PS4 = "PS4"
## --> Package Types
class CONST_PKG_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = "GAME DLC PATCH THEME AVATAR"
    GAME = "Game"
    DLC = "DLC"
    PATCH = "Update"
    THEME = "Theme"
    AVATAR = "Avatar"
## --> Package Sub Types
class CONST_PKG_SUB_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = "PSP_PC_ENGINE PSP_GO PSP_MINI PSP_NEOGEO"
    PSP_PC_ENGINE = "PC Engine"
    PSP_GO = "Go"
    PSP_MINI = "PSP Mini"
    PSP_NEOGEO = "PSP NeoGeo"
    PS2 = "PS2 Classic"

##
## PKG3 Definitions
##
#
CONST_PKG3_XML_ROOT = "hfs_manifest"
## --> Header
CONST_PKG3_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PKG3_MAGIC = 0x7f504b47  ## "\x7FPKG"
CONST_PKG3_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Magic", }, ),
    ( "REV",          { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "MDOFS",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Data Offset", }, ),
    ( "MDCNT",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Data Count", }, ),
    ( "HDRSIZE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Header [Additional] Size incl. PS3 0x40 Digest [and Extensions]", }, ),
    ( "ITEMCNT",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Item Count", }, ),
    ( "TOTALSIZE",    { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Total Size", }, ),
    ( "DATAOFS",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Offset", }, ),
    ( "DATASIZE",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "CONV": 0x0204, "DEBUG": 1, "DESC": "Content ID", }, ),
    ( "DIGEST",       { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Digest", "SEP": "", }, ),
    ( "DATARIV",      { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Data RIV", "SEP": "", }, ),
    #
    ( "KEYINDEX",     { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Key Index for Decryption of Item Entries Table", }, ),
    ( "AES_CTR",      { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Keys for Decryption", }, ),
    ( "PARAM.SFO",    { "VIRTUAL": -1, "DEBUG": 1, "DESC": "PARAM.SFO Item Name", }, ),
    ( "MDSIZE",       { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Meta Data Size", }, ),
])
## --> PS3 0x40 Digest
CONST_PKG3_PS3_DIGEST_FIELDS = collections.OrderedDict([ \
    ( "CMACHASH",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "CMAC Hash", }, ),
    ( "NPDRMSIG",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 40, "DEBUG": 1, "DESC": "NpDrm Signature", }, ),
    ( "SHA1HASH",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 8, "DEBUG": 1, "DESC": "SHA1 Hash", }, ),
])
## --> Extended Header
CONST_PKG3_EXT_MAGIC = 0x7f657874
CONST_PKG3_EXT_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Magic", }, ),
    ( "UNKNOWN",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Unknown (likely version/type)", }, ),
    ( "HDRSIZE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Ext Header Size", }, ),
    ( "DATASIZE",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "RSA Size", }, ),
    ( "HDRRSAOFS",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Header RSA Offset", }, ),
    ( "METARSAOFS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Data RSA Offset", }, ),
    ( "DATARSAOFS",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data RSA Offset", }, ),
    ( "PADDING1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "KEYID",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PKG Key Index", }, ),
    ( "ALLHDRRSAOFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "All Header RSA Offset", }, ),
    ( "PADDING2",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 20, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
])
## --> Item Entry
CONST_PKG3_ITEM_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "ITEMNAMEOFS",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Item Name Offset", }, ),
    ( "ITEMNAMESIZE", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Item Name Size", }, ),
    ( "DATAOFS",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Offset", }, ),
    ( "DATASIZE",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "FLAGS",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags", }, ),
    ( "PADDING1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    #
    ( "NAME",         { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Item Name", }, ),
])
## --> Content PKG Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_CONTENT_KEYS = {
   0: { "KEY": "Lntx18nJoU6jIh8YiCi4+A==", "DESC": "PS3",     },
   1: { "KEY": "B/LGgpC1DSwzgY1wm2DmKw==", "DESC": "PSX/PSP", },
   2: { "KEY": "4xpwyc4d1yvzwGIpY/Lsyw==", "DESC": "PSV",     "DERIVE": True, },
   3: { "KEY": "QjrKOivVZJ+Whqutb9iAHw==", "DESC": "Unknown", "DERIVE": True, },
   4: { "KEY": "rwf9WWUlJ7rxM4lmixfZ6g==", "DESC": "PSM",     "DERIVE": True, },
}
for Key in CONST_PKG3_CONTENT_KEYS:
    CONST_PKG3_CONTENT_KEYS[Key]["KEY"] = base64.standard_b64decode(CONST_PKG3_CONTENT_KEYS[Key]["KEY"])
del Key
## --> PKG Update Keys
CONST_PKG3_UPDATE_KEYS = {
   2: { "KEY": "5eJ4qh7jQIKgiCecg/m7yAaCHFLyq10rSr2ZVFA1URQ=", "DESC": "PSV", },
}
for Key in CONST_PKG3_UPDATE_KEYS:
    CONST_PKG3_UPDATE_KEYS[Key]["KEY"] = base64.standard_b64decode(CONST_PKG3_UPDATE_KEYS[Key]["KEY"])
del Key
## --> RIF
## https://github.com/weaknespase/PkgDecrypt/blob/master/rif.h
## https://github.com/TheOfficialFloW/NoNpDrm/blob/master/main.c
## https://github.com/frangarcj/NoPsmDrm/blob/master/src/main.c
CONST_RIF_FAKE_AID = 0x0123456789abcdef
CONST_RIF_TYPE_OFFSET = 0x04
#
CONST_PSV_RIF_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PSV_RIF_FIELDS = collections.OrderedDict([ \
    ( "VERSION",      { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version", }, ),
    ( "VERSION_FLAG", { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version Flag", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "FLAGS",        { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Flags", }, ),
    ( "AID",          { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Account ID", }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", }, ),
    ( "KEY_TABLE",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key Table", "SEP": "", }, ),
    ( "KEY",          { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key", "SEP": "", }, ),
    ( "START_TIME",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Start Time", }, ),
    ( "EXPIRE_TIME",  { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Expiration Time", }, ),
    ( "ECDSA_SIG",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x28, "DEBUG": 1, "DESC": "ECDSA Signature", "SEP": "", }, ),
    ( "FLAGS2",       { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Flags 2", }, ),
    ( "KEY2",         { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key 2", "SEP": "", }, ),
    ( "UNKNOWN_B0",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 3, "DESC": "Unknown", "SEP": "", }, ),
    ( "OPEN_PS_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Open PS ID", "SEP": "", }, ),
    ( "UNKNOWN_D0",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 3, "DESC": "Unknown", "SEP": "", }, ),
    ( "CMD56HNDSHKE", { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x14, "DEBUG": 1, "DESC": "CMD56 Handshake", "SEP": "", }, ),
    ( "UNKNOWN_F4",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "UNKNOWN_F8",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "SKU_FLAG",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "SKU Flag", }, ),
    ( "DIGEST",       { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x100, "DEBUG": 1, "DESC": "RSA Digest", "SEP": "", }, ),
    #
    ( "LIC_TYPE",   { "VIRTUAL": -1, "DEBUG": 1, "DESC": "License Type", }, ),
])
#
CONST_PSM_RIF_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PSM_RIF_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",       { "FORMAT": CONST_FMT_CHAR, "SIZE": 8, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
    ( "UNKNOWN1",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "UNKNOWN2",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "AID",         { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Account ID", }, ),
    ( "UNKNOWN3",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "UNKNOWN4",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 3, "DESC": "Unknown", }, ),
    ( "START_TIME",  { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Start Time", }, ),
    ( "EXPIRE_TIME", { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Expiration Time", }, ),
    ( "ACT_DIGEST",  { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x20, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
    ( "CONTENT_ID",  { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", }, ),
    ( "UNKNOWN5",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x80, "DEBUG": 3, "DESC": "Unknown", "SEP": "", }, ),
    ( "KEY",         { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x200, "DEBUG": 1, "DESC": "License Key", "SEP": "", }, ),
    ( "DIGEST",      { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x100, "DEBUG": 1, "DESC": "RSA Digest", "SEP": "", }, ),
    #
    ( "LIC_TYPE",   { "VIRTUAL": -1, "DEBUG": 1, "DESC": "License Type", }, ),
])

##
## PKG4 Definitions
##
#
## --> Header
CONST_PKG4_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PKG4_MAGIC = 0x7f434e54
CONST_PKG4_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Magic", }, ),
    ( "REV",          { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "UNKNOWN1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
    ( "FILECNT",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "File Count", }, ),
    ( "ENTCNT",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Entry Count", }, ),
    ( "SCENTCNT",     { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "SC Entry Count", }, ),
    ( "ENTCNT2",      { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Entry Count 2", }, ),
    ( "FILETBLOFS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Table Offset", }, ),
    ( "ENTSIZE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Ent Data Size", }, ),
    ( "BODYOFS",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Body Offset", }, ),
    ( "BODYSIZE",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Body Size", }, ),
    ( "PADDING1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", }, ),
    ( "DRMTYPE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "DRM Type", }, ),
    ( "CONTTYPE",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Content Type", }, ),
    ( "CONTFLAGS",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Content Flags", }, ),
    ( "PROMOTSIZE",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Promote Size", }, ),
    ( "VERSIONDAT",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Version Date", }, ),
    ( "VERSIONHAS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Version Hash", }, ),
    ( "UNKNOWN2",     { "FORMAT": CONST_FMT_CHAR, "SIZE": -0x098, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
    ( "IROTAG",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "IRO Tag", }, ),
    ( "EKCVERSION",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "EKC Version", }, ),
    ( "UNKNOWN3",     { "FORMAT": CONST_FMT_CHAR, "SIZE": -0x100, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),

    ( "DIGESTTABL",   { "FORMAT": CONST_FMT_CHAR, "SUBCOUNT": 24, "SUBSIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 2, "DESC": "Digest Table", }, ),
      ## [0] = main_  entries1_digest
      ## [1] = main_  entries2_digest
      ## [2] = diges  t_table_digest
      ## [3] = body_  digest
      ## [4]-[23] =   unused
    ( "UNKNOWN4",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Unknown (Maybe count)", }, ),
    ( "PFSIMGCNT",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PFS Image Count", }, ),
## >>> Could be a 136 bytes structure, that may be repeated up to 3 times (or even more? 22x up to 0xfd9)
##     While the 2 integers before may define the count and number of each pfs container
    ( "PFSFLAGS",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Flags", }, ),
    ( "PFSIMGOFS",    { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Image Offset", }, ),
    ( "PFSIMGSIZE",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Image Size", }, ),
    ( "MNTIMGOFS",    { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Mount Image Offset", }, ),
    ( "MNTIMGSIZE",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Mount Image Size", }, ),
    ( "PKGSIZE",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Package Size", }, ),
    ( "PFSSIGNSIZE",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PFS Signed Size", }, ),
    ( "PFSCACHESIZE", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PFS Cache Size", }, ),
    ( "PFSIMGDIG",    { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Image Digest", }, ),
    ( "PFSSIGNDIG",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Signed Digest", }, ),
    ( "PFSSPLITNTH0", { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Split NTH 0", }, ),
    ( "PFSSPLITNTH1", { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Split NTH 1", }, ),
## <<< Could be 136 bytes structure
## >>> Could be 2x 136 bytes structure from before
    ( "UNKNOWN5",     { "FORMAT": CONST_FMT_CHAR, "SIZE": -0x5a0, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
## <<< Could be 2x 136 bytes structure from before
## real size looks like it is 0x2000
])
#
## --> File Entry Table
CONST_PKG4_FILE_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "FILEID",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "File ID", }, ),
    ( "NAMERELOFS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Name Table Offset", }, ),
    ( "FLAGS1",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags 1", }, ),
    ( "FLAGS2",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags 2", }, ),
    ( "DATAOFS",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PKG Offset", }, ),
    ( "DATASIZE",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "File Size", }, ),
    ( "PADDING1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 8, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
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
#
## Clean-up
del Key
del Count

##
## PARAM.SFO Definitions
##
CONST_PARAM_SFO_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PARAM_SFO_MAGIC = 0x46535000
#
## --> Header
CONST_PARAM_SFO_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Magic", }, ),
    ( "VERSION",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Version", }, ),
    ( "KEYTBLOFS",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Key Table Offset", }, ),
    ( "DATATBLOFS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Data Table Offset", }, ),
    ( "COUNT",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Entry Count", }, ),
])
#
## --> File Entry Table
CONST_PARAM_SFO_INDEX_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "KEYOFS",       { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Key Offset", }, ),
    ( "DATAFORMAT",   { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Data Format", }, ),
    ( "DATAUSEDSIZE", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Data Used Size", }, ),
    ( "DATAMAXSIZE",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Data Maximum Size", }, ),
    ( "DATAOFS",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Data Offset", }, ),
])

##
## PBP Definitions
##
CONST_PBP_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PBP_MAGIC = 0x00504250
#
## --> Header
CONST_PBP_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",         { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Magic", }, ),
    ( "VERSION",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Version", }, ),
    ( "PARAM_SFO_OFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PARAM.SFO Offset", }, ),
    ( "ICON0_PNG_OFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "ICON0.PNG Offset", }, ),
    ( "ICON1_PMF_OFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "ICON1.PMF/PNG Offset", }, ),
    ( "PIC0_PNG_OFS",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PIC0.PNG or UNKNOWN.PNG Offset", }, ),
    ( "PIC1_PNG_OFS",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PIC1.PNG or PICT1.PNG Offset", }, ),
    ( "SND0_AT3_OFS",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "SND0.AT3 Offset", }, ),
    ( "DATA_PSP_OFS",  { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "DATA.PSP Offset", }, ),
    ( "DATA_PSAR_OFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "DATA.PSAR Offset", }, ),
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
    if isinstance(python_object, bytes) \
    or isinstance(python_object, bytearray):
        return {"__class__": "bytes",
                "__value__": convertBytesToHexString(python_object, sep="")}
    if isinstance(python_object, PkgAesCtrCounter):
        return unicode(python_object)
    if isinstance(python_object, aenum.Enum):
        return unicode(python_object)
    raise TypeError("".join((repr(python_object), " is not JSON serializable")))


def convertBytesToHexString(data, format="", sep=" "):
    if isinstance(data, int):
        data = struct.pack(format, data)
    ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
    if isinstance(data, str):
        data = bytearray(data)
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


class PkgInputReader():
    def __init__(self, source, debug_level=0):
        self._source = source
        self._pkg_name = None
        self._size = None
        self._multipart = False
        self._partscount = None
        self._parts = []
        #
        self._buffer = None
        self._buffer_size = 0
        #
        self._headers = {"User-Agent": "Mozilla/5.0 (PLAYSTATION 3; 4.83)"}  ## Default to PS3 headers (fits PS3/PSX/PSP/PSV packages, but not PSM packages for PSV)

        ## Check for multipart package
        ## --> XML
        if self._source.endswith(".xml"):
            input_stream = None
            xml_root = None
            xml_element = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if debug_level >= 2:
                    dprint("[INPUT] Opening source as URL XML data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.text)
                input_stream.close()
            else:
                if debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE XML data stream")
                try:
                    input_stream = io.open(self._source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.read())
                input_stream.close()
            del input_stream
            ## Check for known XML
            if xml_root.tag != CONST_PKG3_XML_ROOT:
                eprint("[INPUT] Not a known PKG XML file ({} <> {})".format(xml_root.tag, CONST_PKG3_XML_ROOT), self._source)
                eprint("", prefix=None)
                sys.exit(2)
            ## Determine values from XML data
            xml_element = xml_root.find("file_name")
            if not xml_element is None:
                self._pkg_name = xml_element.text.strip()
            #
            xml_element = xml_root.find("file_size")
            if not xml_element is None:
                self._size = int(xml_element.text.strip())
            #
            xml_element = xml_root.find("number_of_split_files")
            if not xml_element is None:
                self._partscount = int(xml_element.text.strip())
                if self._partscount > 1:
                    self._multipart = True
            ## Determine file parts from XML data
            for xml_element in xml_root.findall("pieces"):
                xml_element.attrib["INDEX"] = int(xml_element.attrib["index"])
                del xml_element.attrib["index"]
                #
                xml_element.attrib["SIZE"] = int(xml_element.attrib["file_size"])
                del xml_element.attrib["file_size"]
                #
                self._parts.append(xml_element.attrib)
            #
            self._parts = sorted(self._parts, key=lambda x: (x["INDEX"]))
            #
            offset = 0
            file_part = None
            for file_part in self._parts:
                file_part["START_OFS"] = offset
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
                offset += file_part["SIZE"]
                #
                if debug_level >= 2:
                    dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
            del file_part
            del offset
            #
            del xml_element
            del xml_root
        ## --> JSON
        elif self._source.endswith(".json"):
            self._headers = {"User-Agent": "Download/1.00 libhttp/6.20 (PlayStation 4)"}  ## Switch to PS4 headers
            input_stream = None
            json_data = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if debug_level >= 2:
                    dprint("[INPUT] Opening source as URL JSON data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                json_data = input_stream.json()
                input_stream.close()
            else:
                if debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE JSON data stream")
                try:
                    input_stream = io.open(self._source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                json_data = json.load(input_stream)
                input_stream.close()
            del input_stream
            #
            ## Check for known JSON
            if not "pieces" in json_data \
            or not json_data["pieces"][0] \
            or not "url" in json_data["pieces"][0]:
                eprint("[INPUT] JSON source does not look like PKG meta data (missing [pieces][0])", self._source)
                eprint("", prefix=None)
                sys.exit(2)
            ## Determine values from JSON data
            if "originalFileSize" in json_data:
                self._size = json_data["originalFileSize"]
            #
            if "numberOfSplitFiles" in json_data:
                self._partscount = json_data["numberOfSplitFiles"]
                if self._partscount > 1:
                    self._multipart = True
            ## Determine file parts from JSON data
            if "pieces" in json_data:
                json_data["pieces"] = sorted(json_data["pieces"], key=lambda x: (x["fileOffset"]))
                #
                count = 0
                file_part = None
                for file_part in json_data["pieces"]:
                    if not self._pkg_name:
                        if file_part["url"].startswith("http:") \
                        or file_part["url"].startswith("https:"):
                            self._pkg_name = os.path.basename(requests.utils.urlparse(file_part["url"]).path).strip()
                        else:
                            self._pkg_name = os.path.basename(file_part["url"]).strip()
                        #
                        self._pkg_name = re.sub(r"_[0-9]+\.pkg$", r".pkg", self._pkg_name, flags=re.UNICODE)
                    #
                    file_part["INDEX"] = count
                    count += 1
                    #
                    file_part["START_OFS"] = file_part["fileOffset"]
                    del file_part["fileOffset"]
                    #
                    file_part["SIZE"] = file_part["fileSize"]
                    del file_part["fileSize"]
                    #
                    file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
                    #
                    self._parts.append(file_part)
                    #
                    if debug_level >= 2:
                        dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
                del file_part
                del count
            #
            del json_data
        else:
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if debug_level >= 2:
                    dprint("[INPUT] Using source as URL PKG data stream")
                self._pkg_name = os.path.basename(requests.utils.urlparse(self._source).path).strip()
            else:
                if debug_level >= 2:
                    dprint("[INPUT] Using source as FILE PKG data stream")
                self._pkg_name = os.path.basename(self._source).strip()
            #
            self._multipart = False
            self._partscount = 1
            #
            file_part = {}
            file_part["INDEX"] = 0
            file_part["START_OFS"] = 0
            file_part["url"] = self._source
            self._parts.append(file_part)
            if debug_level >= 2:
                dprint("[INPUT] Pkg Part #{} Offset {:#012x} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["url"]))
            del file_part
            #
            self.open(self._parts[0], debug_level)
            if "SIZE" in self._parts[0]:
                self._size = self._parts[0]["SIZE"]

        read_size = CONST_READ_AHEAD_SIZE
        if read_size > self._size:
            read_size = self._size
        if read_size > 0:
            self._buffer = self.read(0, read_size, debug_level)
            self._buffer_size = len(self._buffer)
            if debug_level >= 2:
                dprint("[INPUT] Buffered first {} bytes of package".format(self._buffer_size), "(max {})".format(CONST_READ_AHEAD_SIZE) if self._buffer_size != CONST_READ_AHEAD_SIZE else "")

    def getSize(self, debug_level=0):
        return self._size

    def getSource(self, debug_level=0):
        return self._source

    def getPkgName(self, debug_level=0):
        return self._pkg_name

    def open(self, file_part, debug_level=0):
        ## Check if already opened
        if "STREAM" in file_part:
            return

        part_size = None
        if file_part["url"].startswith("http:") \
        or file_part["url"].startswith("https:"):
            if debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as URL PKG data stream".format(file_part["INDEX"]))
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            file_part["STREAM_TYPE"] = "requests"
            try:
                file_part["STREAM"] = requests.Session()
            except:
                eprint("[INPUT] Could not create HTTP/S session for PKG URL", file_part["url"])
                eprint("", prefix=None)
                sys.exit(2)
            #
            file_part["STREAM"].headers = self._headers
            response = file_part["STREAM"].head(file_part["url"])
            if debug_level >= 3:
                dprint("[INPUT]", response)
                dprint("[INPUT] Response headers:", response.headers)
            if "content-length" in response.headers:
                part_size = int(response.headers["content-length"])
        else:
            if debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as FILE PKG data stream".format(file_part["INDEX"]))
            #
            file_part["STREAM_TYPE"] = "file"
            try:
                file_part["STREAM"] = io.open(file_part["url"], mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("[INPUT] Could not open PKG FILE", file_part["url"])
                eprint("", prefix=None)
                sys.exit(2)
            #
            file_part["STREAM"].seek(0, os.SEEK_END)
            part_size = file_part["STREAM"].tell()

        ## Check file size
        if not part_size is None:
            if not "SIZE" in file_part:
                file_part["SIZE"] = part_size
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
            else:
                if part_size != file_part["SIZE"]:
                    eprint("[INPUT] File size differs from meta data {} <> {}", part_size, file_part["SIZE"])
                    eprint("", prefix=None)
                    sys.exit(2)

        if debug_level >= 3:
            dprint("[INPUT] Data stream is of class", file_part["STREAM"].__class__.__name__)

    def read(self, offset, size, debug_level=0):
        result = bytearray()
        read_offset = offset
        read_size = size

        if read_size < 0:
            raise ValueError("Negative read size {}".format(read_size))

        if self._buffer \
        and self._buffer_size > read_offset \
        and read_size > 0:
            read_buffer_size = read_size
            if (read_offset+read_buffer_size) > self._buffer_size:
                read_buffer_size = self._buffer_size-read_offset
            #
            if debug_level >= 3:
                dprint("[INPUT] Get offset {:#012x} size {}/{} bytes from buffer".format(read_offset, read_buffer_size, size))
            #
            result.extend(self._buffer[read_offset:read_offset+read_buffer_size])
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        count = 0
        lastcount = -1
        while read_size > 0:
            while count < self._partscount \
            and self._parts[count]["START_OFS"] <= read_offset:
                count += 1
            count -= 1
            if lastcount == count:  ## Avoid endless loop
                raise ValueError("[INPUT] Read offset {:#012x} out of range (max. {:#012x})".format(read_offset, self._size-1))
            lastcount = count
            #
            file_part = self._parts[count]
            #
            file_offset = read_offset - file_part["START_OFS"]
            #
            read_buffer_size = read_size
            if (read_offset+read_buffer_size) > file_part["END_OFS"]:
                read_buffer_size = file_part["END_OFS"]-read_offset
            #
            if debug_level >= 3:
                dprint("[INPUT] Read offset {:#012x} size {}/{} bytes from Pkg Part #{} Offset {:#012x}".format(read_offset, read_buffer_size, size, file_part["INDEX"], file_offset))
            #
            self.open(file_part, debug_level)
            #
            if file_part["STREAM_TYPE"] == "file":
                file_part["STREAM"].seek(file_offset, os.SEEK_SET)
                result.extend(file_part["STREAM"].read(read_buffer_size))
                ## supports the following.
                ## * offset=9000 + size=-1 => all bytes from offset 9000 to the end
                ## does *NOT* support the following, have to calculate size from file size.
                ## * bytes=-32 => last 32 bytes
            elif file_part["STREAM_TYPE"] == "requests":
                ## Send request in persistent session
                ## http://docs.python-requests.org/en/master/api/#requests.Session.get
                ## http://docs.python-requests.org/en/master/api/#requests.request
                ## https://www.rfc-editor.org/info/rfc7233
                ## supports the following.
                ## * bytes=9000- => all bytes from offset 9000 to the end
                ## * bytes=-32 => last 32 bytes
                reqheaders={"Range": "bytes={}-{}".format(file_offset, (file_offset + read_buffer_size - 1) if read_buffer_size > 0 else "")}
                response = file_part["STREAM"].get(file_part["url"], headers=reqheaders)
                result.extend(response.content)
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        return result

    def close(self, debug_level=0):
        for file_part in self._parts:
            if not "STREAM" in file_part:
                continue

            file_part["STREAM"].close()
            del file_part["STREAM"]

        return


class PkgAesCtrCounter():
    def __str__(self):
        return convertBytesToHexString(self._key, sep="")

    def __init__(self, key, iv):
        ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
        self._key = bytes(key)
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
        ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
        decrypted_data = bytearray(self._aes.decrypt(bytes(data)))
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
    ## Python 2 workaround: convert byte string to bytearray()
    if isinstance(data, str):
        data = bytearray(data)
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
            and (field_format == CONST_FMT_UINT32 \
                 or field_format == CONST_FMT_UINT16 \
                 or field_format == CONST_FMT_UINT64) :
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
            if field_format == CONST_FMT_CHAR:
                if "SUBSIZE" in field_def:
                    field_def["SIZE"] = field_def["SUBSIZE"] * field_def["SUBCOUNT"]
                elif field_def["SIZE"] < 0:
                    field_def["SIZE"] = abs(field_def["SIZE"]) - field_def["OFFSET"]
                field_format = "".join((unicode(field_def["SIZE"]), field_format))
            elif field_format == CONST_FMT_UINT32 \
            or field_format == CONST_FMT_UINT16 \
            or field_format == CONST_FMT_UINT64:
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
            ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
            if field_def["FORMAT"] == CONST_FMT_CHAR \
            and isinstance(fields[key], str):
                fields[key] = bytearray(fields[key])
    #
    fields["STRUCTURE_DEF"] = CONST_STRUCTURE_FIELDS
    #
    return fields


def parsePkg4Header(head_bytes, input_stream, function_debug_level, print_unknown=False):
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps4/PKG_files#File_Header

    ## Extract fields from PKG4 Main Header
    temp_fields = struct.unpack(CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes)
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
            ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
            if field_def["FORMAT"] == CONST_FMT_CHAR \
            and isinstance(header_fields[key][0], str):
                temp_fields = []
                for _i in range(len(header_fields[key])):
                    temp_fields.append(bytearray(header_fields[key][_i]))
                header_fields[key] = temp_fields
                del temp_fields

    ## Prepare format strings
    file_cnt_len = unicode(len(unicode(header_fields["FILECNT"])))
    file_cnt_format_string = "".join(("{:", file_cnt_len, "}"))

    ## Retrieve PKG4 File Entry Table from input stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 File Entry Table:")
    pkg_file_table_size = header_fields["FILECNT"] * CONST_PKG4_FILE_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG4 file entry table from offset {:#x} with count {} and size {}".format(header_fields["FILETBLOFS"], header_fields["FILECNT"], pkg_file_table_size))
    temp_bytes = bytearray()
    try:
        temp_bytes.extend(input_stream.read(header_fields["FILETBLOFS"], pkg_file_table_size, function_debug_level))
    except:
        input_stream.close(function_debug_level)
        eprint("Could not get PKG4 file entry table at offset {:#x} with size {} from".format(header_fields["FILETBLOFS"], pkg_file_table_size), input_stream.getSource())
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

    ## Retrieve PKG4 Name Table from input stream
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
            name_table.extend(input_stream.read(file_entry["DATAOFS"], file_entry["DATASIZE"], function_debug_level))
        except:
            input_stream.close(function_debug_level)
            eprint("Could not get PKG4 name table at offset {:#x} with size {} from".format(file_entry["DATAOFS"], file_entry["DATASIZE"]), input_stream.getSource())
            eprint("", prefix=None)
            sys.exit(2)

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
    dprintFieldsDict(header_fields, "pkgheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsList(file_table, "".join(("pkgfiletable[{KEY:", file_cnt_len, "}]")), function_debug_level, None)
    if function_debug_level >= 2:
        dprintFieldsDict(file_table_map, "pkgfiletablemap[{KEY:#06x}]", function_debug_level, None)
        dprint("pkgnametable:", name_table)

    return header_fields, file_table, file_table_map


def parsePkg3Header(head_bytes, input_stream, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Main Header:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2

    ## Extract fields from PKG3 Main Header
    temp_fields = struct.unpack(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes)
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
            ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
            if field_def["FORMAT"] == CONST_FMT_CHAR \
            and isinstance(header_fields[key][0], str):
                temp_fields = []
                for _i in range(len(header_fields[key])):
                    temp_fields.append(bytearray(header_fields[key][_i]))
                header_fields[key] = temp_fields
                del temp_fields

    ## Retrieve PKG3 Unencrypted Data from input stream
    read_size = header_fields["DATAOFS"] - CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG3 remaining unencrypted data with size {}/{}".format(read_size, header_fields["DATAOFS"]))
    unencrypted_bytes = head_bytes
    try:
        unencrypted_bytes.extend(input_stream.read(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], read_size, function_debug_level))
    except:
        input_stream.close(function_debug_level)
        eprint("Could not get PKG3 unencrypted data at offset {:#x} with size {} from".format(CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"], read_size), input_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Extract fields from PKG3 Extended Header
    ext_header_fields = None
    main_hdr_size = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"] + CONST_PKG3_PS3_DIGEST_FIELDS["STRUCTURE_SIZE"]
    if header_fields["TYPE"] == 0x2:
        if function_debug_level >= 2:
            dprint(">>>>> PKG3 Extended Main Header:")
        temp_fields = struct.unpack(CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes[main_hdr_size:main_hdr_size+CONST_PKG3_EXT_HEADER_FIELDS["STRUCTURE_SIZE"]])
        ## --> Debug print all
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, temp_fields, "PKG3 Extended Main Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

        ## Convert to dictionary (associative array)
        ext_header_fields = convertFieldsToOrdDict(CONST_PKG3_EXT_HEADER_FIELDS, temp_fields)
        del temp_fields

        ## Check PKG3 Extended Header Magic
        if "MAGIC" in ext_header_fields \
        and ext_header_fields["MAGIC"] != CONST_PKG3_EXT_MAGIC:
            input_stream.close(function_debug_level)
            eprint("Not a known PKG3 Extended Main Header ({:#x} <> {:#x})".format(ext_header_fields["MAGIC"], CONST_PKG3_EXT_MAGIC), input_stream.getSource())
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
            ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
            pkg_key = bytearray(aes.encrypt(bytes(header_fields["DATARIV"])))
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
        ## (1) DRM Type
        ## (2) Content Type
        if md_entry_type == 0x01 \
        or md_entry_type == 0x02:
            if md_entry_type == 0x01:
                meta_data[md_entry_type]["DESC"] = "DRM Type"
            elif md_entry_type == 0x02:
                meta_data[md_entry_type]["DESC"] = "Content Type"
            meta_data[md_entry_type]["VALUE"] = getInteger32BitBE(temp_bytes, 0)
            if md_entry_size > 0x04:
                meta_data[md_entry_type]["UNKNOWN"] = temp_bytes[0x04:]
        ## (6) TitleID (when size 0xc) (otherwise Version + App Version)
        elif md_entry_type == 0x06 \
        and md_entry_size == 0x0C:
            if md_entry_type == 0x06:
                meta_data[md_entry_type]["DESC"] = "Title ID"
            meta_data[md_entry_type]["VALUE"] = convertUtf8BytesToString(temp_bytes, 0x0204)
        ## (10) Install Directory
        elif md_entry_type == 0x0A:
            if md_entry_type == 0x0A:
                meta_data[md_entry_type]["DESC"] = "Install Directory"
            meta_data[md_entry_type]["UNKNOWN"] = temp_bytes[:0x8]
            meta_data[md_entry_type]["VALUE"] = convertUtf8BytesToString(temp_bytes[0x8:], 0x0204)
        ## (13) Items Info (PS Vita)
        elif md_entry_type == 0x0D:
            if md_entry_type == 0x0D:
                meta_data[md_entry_type]["DESC"] = "Items Info (SHA256 of decrypted data)"
            meta_data[md_entry_type]["OFS"] = getInteger32BitBE(temp_bytes, 0)
            meta_data[md_entry_type]["SIZE"] = getInteger32BitBE(temp_bytes, 0x04)
            meta_data[md_entry_type]["SHA256"] = temp_bytes[0x08:0x08+0x20]
            if md_entry_size > 0x28:
                meta_data[md_entry_type]["UNKNOWN"] = temp_bytes[0x28:]
        ## (14) PARAM.SFO Info (PS Vita)
        ## (15) Unknown Info (PS Vita)
        ## (16) Entirety Info (PS Vita)
        ## (18) Self Info (PS Vita)
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
            meta_data[md_entry_type]["UNKNOWN"] = temp_bytes[0x08:md_entry_size - 0x20]
            meta_data[md_entry_type]["SHA256"] = temp_bytes[md_entry_size - 0x20:]
        else:
            if md_entry_type == 0x03:
                meta_data[md_entry_type]["DESC"] = "Package Type/Flags"
            elif md_entry_type == 0x04:
                meta_data[md_entry_type]["DESC"] = "Package Size"
            elif md_entry_type == 0x06:
                meta_data[md_entry_type]["DESC"] = "Version + App Version"
            elif md_entry_type == 0x07:
                meta_data[md_entry_type]["DESC"] = "QA Digest"
            meta_data[md_entry_type]["VALUE"] = temp_bytes
        #
        md_offset += md_entry_size
    #
    del temp_bytes
    header_fields["MDSIZE"] = md_offset - header_fields["MDOFS"]

    ## Debug print results
    dprint(">>>>> parsePkg3Header results:")
    dprintFieldsDict(header_fields, "pkgheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    if ext_header_fields:
        dprintFieldsDict(ext_header_fields, "pkgextheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsDict(meta_data, "pkgmetadata[{KEY:#04x}]", function_debug_level, None)

    return header_fields, ext_header_fields, meta_data, unencrypted_bytes


def parsePbpHeader(head_bytes, input_stream, function_debug_level, file_size):
    if function_debug_level >= 2:
        dprint(">>>>> PBP Header:")

    ## For definition see http://www.psdevwiki.com/ps3/Eboot.PBP

    ## Extract fields from PBP Header
    temp_fields = struct.unpack(CONST_PBP_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PBP_HEADER_FIELDS, CONST_PBP_ENDIAN, temp_fields, "PBP Header[{:1}]: [{:#04x}|{:1}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    pbp_header_fields = convertFieldsToOrdDict(CONST_PBP_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Retrieve PKG3 Unencrypted Data from input stream
    read_size = pbp_header_fields["ICON0_PNG_OFS"] - CONST_PBP_HEADER_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PBP remaining unencrypted data with size {}/{}".format(read_size, pbp_header_fields["ICON0_PNG_OFS"]))
    unencrypted_bytes = head_bytes
    try:
        unencrypted_bytes.extend(input_stream.read(CONST_PBP_HEADER_FIELDS["STRUCTURE_SIZE"], read_size, function_debug_level))
    except:
        input_stream.close(function_debug_level)
        eprint("Could not get PBP unencrypted data at offset {:#x} with size {} from".format(CONST_PBP_HEADER_FIELDS["STRUCTURE_SIZE"], read_size), input_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Determine key index for data
    pass  ## TODO

    ## Build item entries
    item_entries = []
    item_index = 0
    last_item = None
    #
    for key in ("PARAM_SFO_OFS", "ICON0_PNG_OFS", "ICON1_PMF_OFS", "PIC0_PNG_OFS", "PIC1_PNG_OFS", "SND0_AT3_OFS", "DATA_PSP_OFS", "DATA_PSAR_OFS"):
        item_entry = {}
        item_entry["INDEX"] = item_index
        #
        item_entry["DATAOFS"] = pbp_header_fields[key]
        item_entry["IS_FILE_OFS"] = item_entry["DATAOFS"]
        #
        if not last_item is None:
            item_entries[last_item]["DATASIZE"] = item_entry["DATAOFS"] - item_entries[last_item]["DATAOFS"]
            item_entries[last_item]["ALIGN"] = calculateAesAlignedOffsetAndSize(item_entries[last_item]["DATAOFS"], item_entries[last_item]["DATASIZE"])
        last_item = item_index
        #
        if key == "PARAM_SFO_OFS":
            item_entry["NAME"] = "PARAM.SFO"
        elif key == "ICON0_PNG_OFS":
            item_entry["NAME"] = "ICON0.PNG"
        elif key == "ICON1_PMF_OFS":
            item_entry["NAME"] = "ICON1.PMF"
        elif key == "PIC0_PNG_OFS":
            item_entry["NAME"] = "PIC0.PNG"
        elif key == "PIC1_PNG_OFS":
            item_entry["NAME"] = "PIC1.PNG"
        elif key == "SND0_AT3_OFS":
            item_entry["NAME"] = "SND0.AT3"
        elif key == "DATA_PSP_OFS":
            item_entry["NAME"] = "DATA.PSP"
        elif key == "DATA_PSAR_OFS":
            item_entry["NAME"] = "DATA.PSAR"
        #
        item_entries.append(item_entry)
        #
        item_index += 1
    #
    if not last_item is None:
        item_entries[last_item]["DATASIZE"] = file_size - item_entries[last_item]["DATAOFS"]
        item_entries[last_item]["ALIGN"] = calculateAesAlignedOffsetAndSize(item_entries[last_item]["DATAOFS"], item_entries[last_item]["DATASIZE"])

    ## Debug print results
    dprint(">>>>> parsePbpHeader results:")
    dprintFieldsDict(pbp_header_fields, "pbpheaderfields[{KEY:15}|{INDEX:1}]", function_debug_level, None)
    dprintFieldsList(item_entries, "".join(("pbpitementries[{KEY:1}]")), function_debug_level, None)

    return pbp_header_fields, item_entries


def parsePkg3ItemsInfo(header_fields, meta_data, input_stream, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Items Info:")

    ## For definition see http://www.psdevwiki.com/ps3/PKG_files#File_Body

    ## Prepare format strings
    item_cnt_len = unicode(len(unicode(header_fields["ITEMCNT"])))
    item_cnt_format_string = "".join(("{:", item_cnt_len, "}"))

    ## Retrieve PKG3 Items Info (or Item Entries and Names separately) from input stream
    items_info_bytes = collections.OrderedDict()
    #
    items_info_bytes["OFS"] = 0
    items_info_bytes["SIZE"] = header_fields["ITEMCNT"] * CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    items_info_bytes["ALIGN"] = {}
    items_info_bytes["ENTRIES_SIZE"] = header_fields["ITEMCNT"] * CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    if 0x0D in meta_data:
        items_info_bytes["OFS"] = meta_data[0x0D]["OFS"]
        if items_info_bytes["SIZE"] < meta_data[0x0D]["SIZE"]:
            items_info_bytes["SIZE"] = meta_data[0x0D]["SIZE"]
    #
    items_info_bytes["ALIGN"] = calculateAesAlignedOffsetAndSize(items_info_bytes["OFS"], items_info_bytes["SIZE"])
    #
    if function_debug_level >= 2:
        dprint("Get PKG3 Items Info/Item Entries from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} with count {} and size {}+{}={}".format(items_info_bytes["OFS"], items_info_bytes["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+items_info_bytes["ALIGN"]["OFS"], header_fields["ITEMCNT"], items_info_bytes["SIZE"], items_info_bytes["ALIGN"]["SIZEDELTA"], items_info_bytes["ALIGN"]["SIZE"]))
    if items_info_bytes["ALIGN"]["OFSDELTA"] > 0:
        eprint("Unaligned encrypted offset {:#x}-{:#x}={:#x}(+{:#x}) for Items Info/Item Entries.".format(items_info_bytes["OFS"], items_info_bytes["ALIGN"]["OFSDELTA"], items_info_bytes["ALIGN"]["OFS"], header_fields["DATAOFS"]), input_stream.getSource(), prefix="[ALIGN] ")
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
    #
    items_info_bytes[CONST_DATATYPE_AS_IS] = bytearray()
    try:
        items_info_bytes[CONST_DATATYPE_AS_IS].extend(input_stream.read(header_fields["DATAOFS"]+items_info_bytes["ALIGN"]["OFS"], items_info_bytes["ALIGN"]["SIZE"], function_debug_level))
    except:
        input_stream.close(function_debug_level)
        eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(header_fields["DATAOFS"]+items_info_bytes["ALIGN"]["OFS"], items_info_bytes["ALIGN"]["SIZE"]), input_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)

    ## Decrypt PKG3 Item Entries
    items_info_bytes[CONST_DATATYPE_DECRYPTED] = header_fields["AES_CTR"][header_fields["KEYINDEX"]].decrypt(items_info_bytes["ALIGN"]["OFS"], items_info_bytes[CONST_DATATYPE_AS_IS])

    ## Parse PKG3 Item Entries
    item_entries = []
    offset = items_info_bytes["ALIGN"]["OFSDELTA"]
    items_info_bytes["NAMES_OFS"] = None
    name_offset_end = None
    item_name_size_max = 0
    #
    for _i in range(header_fields["ITEMCNT"]):  ## 0 to <item count - 1>
        temp_fields = struct.unpack(CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_UNPACK"], items_info_bytes[CONST_DATATYPE_DECRYPTED][offset:offset+CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, temp_fields, "".join(("PKG3 Body Item Entry[", item_cnt_format_string.format(_i), "][{:1}]: [", "{:#06x}+".format(header_fields["DATAOFS"]+items_info_bytes["ALIGN"]["OFS"]+offset), "{:#04x}|{:1}] {} = {}")), function_debug_level)
        temp_fields = convertFieldsToOrdDict(CONST_PKG3_ITEM_ENTRY_FIELDS, temp_fields)
        temp_fields["INDEX"] = _i
        temp_fields["KEYINDEX"] = (temp_fields["FLAGS"] >> 28) & 0x7
        temp_fields["ALIGN"] = calculateAesAlignedOffsetAndSize(temp_fields["DATAOFS"], temp_fields["DATASIZE"])
        if temp_fields["ALIGN"]["OFSDELTA"] > 0:
            eprint("Unaligned encrypted offset {:#x}-{:#x}={:#x}(+{:#x}) for #{} item data.".format(temp_fields["DATAOFS"], temp_fields["ALIGN"]["OFSDELTA"], temp_fields["ALIGN"]["OFS"], header_fields["DATAOFS"], temp_fields["INDEX"]), input_stream.getSource(), prefix="[ALIGN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
        #
        item_flags = temp_fields["FLAGS"] & 0xff
        if item_flags == 0x04 \
        or item_flags == 0x12:  ## Directory
            temp_fields["IS_FILE_OFS"] = -1
        else:  ## Files
            temp_fields["IS_FILE_OFS"] = temp_fields["DATAOFS"]
        del item_flags
        #
        item_entries.append(temp_fields)
        #
        if temp_fields["ITEMNAMESIZE"] > 0:
            if items_info_bytes["NAMES_OFS"] is None \
            or temp_fields["ITEMNAMEOFS"] < items_info_bytes["NAMES_OFS"]:
                items_info_bytes["NAMES_OFS"] = temp_fields["ITEMNAMEOFS"]
            #
            if name_offset_end is None \
            or temp_fields["ITEMNAMEOFS"] >= name_offset_end:
                name_offset_end = temp_fields["ITEMNAMEOFS"] + temp_fields["ITEMNAMESIZE"]
            #
            if temp_fields["ITEMNAMESIZE"] > item_name_size_max:
                item_name_size_max = temp_fields["ITEMNAMESIZE"]
        #
        del temp_fields
        #
        offset += CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    items_info_bytes["NAMES_SIZE"] = name_offset_end - items_info_bytes["NAMES_OFS"]

    ## Check if Item Names follow immediately after Item Entries (relative offsets inside Items Info)
    if items_info_bytes["NAMES_OFS"] < items_info_bytes["ENTRIES_SIZE"]:
        eprint("Item Names with offset {:#0x} are INTERLEAVED with the Item Entries of size {:#0x}.".format(items_info_bytes["NAMES_OFS"], items_info_bytes["ENTRIES_SIZE"]), input_stream.getSource())
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
    elif items_info_bytes["NAMES_OFS"] > items_info_bytes["ENTRIES_SIZE"]:
        eprint("Item Names with offset {:#0x} are not directly following the Item Entries with size {:#0x}.".format(items_info_bytes["NAMES_OFS"], items_info_bytes["ENTRIES_SIZE"]), input_stream.getSource(), prefix="[UNKNOWN] ")
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")

    ## Retrieve PKG3 remaining Items Info data (if any) for Item Names from input stream
    ## Calculate complete size via first relative name offset inside Items Info plus names size
    read_size = items_info_bytes["NAMES_OFS"] + items_info_bytes["NAMES_SIZE"]
    if read_size > items_info_bytes["SIZE"]:
        if 0x0D in meta_data \
        and meta_data[0x0D]["SIZE"] >= items_info_bytes["ENTRIES_SIZE"]:
            ## meta data size too small for whole Items Info
            eprint("Items Info size {} from meta data 0x0D is too small for complete Items Info (Entries+Names) with total size of {}.".format(meta_data[0x0D]["SIZE"], read_size), input_stream.getSource())
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
        #
        items_info_bytes["SIZE"] = read_size
        items_info_bytes["ALIGN"] = calculateAesAlignedOffsetAndSize(items_info_bytes["OFS"], items_info_bytes["SIZE"])
        read_offset = items_info_bytes["ALIGN"]["OFS"] + len(items_info_bytes[CONST_DATATYPE_AS_IS])
        read_size = items_info_bytes["ALIGN"]["SIZE"] - len(items_info_bytes[CONST_DATATYPE_AS_IS])
        #
        if function_debug_level >= 2:
            dprint("Get PKG3 remaining Items Info/Item Names data with size {}/{} ".format(read_size, items_info_bytes["ALIGN"]["SIZE"]))
        try:
            items_info_bytes[CONST_DATATYPE_AS_IS].extend(input_stream.read(header_fields["DATAOFS"]+read_offset, read_size, function_debug_level))
        except:
            input_stream.close(function_debug_level)
            eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(header_fields["DATAOFS"]+read_offset, read_size), input_stream.getSource())
            eprint("", prefix=None)
            sys.exit(2)
        #
        items_info_bytes[CONST_DATATYPE_DECRYPTED].extend(items_info_bytes[CONST_DATATYPE_AS_IS][len(items_info_bytes[CONST_DATATYPE_DECRYPTED]):])
    else:
        if 0x0D in meta_data:
            align = calculateAesAlignedOffsetAndSize(items_info_bytes["OFS"], read_size)
            if align["SIZE"] != meta_data[0x0D]["SIZE"]:
                eprint("Determined aligned Items Info size {:#} <> {:#} from meta data 0x0D.".format(align["SIZE"], meta_data[0x0D]["SIZE"]), input_stream.getSource())
                eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")

    ## Decrypt and Parse PKG3 Item Names
    item_name_size_cnt_len = unicode(len(unicode(item_name_size_max)))
    item_name_size_format_string = "".join(("{:", item_name_size_cnt_len, "}"))
    #
    for item_entry in item_entries:
        if item_entry["ITEMNAMESIZE"] <= 0:
            continue
        #
        key_index = item_entry["KEYINDEX"]
        offset = items_info_bytes["OFS"] + item_entry["ITEMNAMEOFS"]
        align = calculateAesAlignedOffsetAndSize(offset, item_entry["ITEMNAMESIZE"])
        if align["OFSDELTA"] > 0:
            eprint("Unaligned encrypted offset {:#x}-{:#x}={:#x}(+{:#x}) for #{} item name.".format(offset, align["OFSDELTA"], align["OFS"], header_fields["DATAOFS"], item_entry["INDEX"]), input_stream.getSource(), prefix="[ALIGN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[ALIGN] ")
        #
        offset = align["OFS"] - items_info_bytes["ALIGN"]["OFS"]
        items_info_bytes[CONST_DATATYPE_DECRYPTED][offset:offset+align["SIZE"]] = header_fields["AES_CTR"][key_index].decrypt(align["OFS"], items_info_bytes[CONST_DATATYPE_AS_IS][offset:offset+align["SIZE"]])
        temp_bytes = items_info_bytes[CONST_DATATYPE_DECRYPTED][offset+align["OFSDELTA"]:offset+align["OFSDELTA"]+item_entry["ITEMNAMESIZE"]]
        del align
        #
        if function_debug_level >= 2:
            dprint("".join(("PKG3 Body Item Name[", item_cnt_format_string, "]: key {:#} [{:#06x}|", item_name_size_format_string, "] {}")).format(item_entry["INDEX"], key_index, header_fields["DATAOFS"]+items_info_bytes["OFS"]+item_entry["ITEMNAMEOFS"], item_entry["ITEMNAMESIZE"], temp_bytes))
        item_entry["NAME"] = convertUtf8BytesToString(temp_bytes, 0x0004, length=item_entry["ITEMNAMESIZE"])
        #
        del temp_bytes

    ## Calculate SHA-256 hash of decrypted data
    hash_sha256 = Cryptodome.Hash.SHA256.new()
    ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
    hash_sha256.update(bytes(items_info_bytes[CONST_DATATYPE_DECRYPTED]))
    items_info_bytes["SHA256"] = bytearray(hash_sha256.digest())
    if 0x0D in meta_data \
    and items_info_bytes["SHA256"] != meta_data[0x0D]["SHA256"]:
        eprint("Calculated SHA-256 of decrypted Items Info does not match the one from meta data 0x0D.", input_stream.getSource())
        eprint("{} <> {}".format(convertBytesToHexString(items_info_bytes["SHA256"], sep=""), convertBytesToHexString(meta_data[0x0D]["SHA256"], sep="")))
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")

    ## Further analysis data
    items_info_bytes["FILE_OFS"] = header_fields["DATAOFS"] + items_info_bytes["OFS"]
    items_info_bytes["FILE_OFS_END"] = items_info_bytes["FILE_OFS"] + items_info_bytes["SIZE"]

    ## Debug print results
    dprint(">>>>> parsePkg3ItemsInfo results:")
    dprintFieldsList(item_entries, "".join(("pkgitementries[{KEY:", item_cnt_len, "}]")), function_debug_level, None)

    return item_entries, items_info_bytes


def processPkg3Item(extractions_fields, item_entry, input_stream, item_data, extractions, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entry #{} {}:".format(item_entry["INDEX"], item_entry["NAME"]))

    ## Prepare dicitionaries
    if input_stream \
    and not item_data is None:
        item_data[CONST_DATATYPE_AS_IS] = bytearray()
        item_data[CONST_DATATYPE_DECRYPTED] = bytearray()
    #
    if extractions:
        for key in extractions:
            extract = extractions[key]
            extract["ITEM_BYTES_WRITTEN"] = 0
        del extract
        del key

    ## Retrieve PKG3 Item Data from input stream
    if function_debug_level >= 2:
        dprint("{} PKG3 item data from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} and size {}+{}={}".format("Get" if input_stream else "Process", item_entry["DATAOFS"], item_entry["ALIGN"]["OFSDELTA"], extractions_fields["DATAOFS"], extractions_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["DATASIZE"], item_entry["ALIGN"]["SIZEDELTA"], item_entry["ALIGN"]["SIZE"]))
    #
    data_offset = item_entry["ALIGN"]["OFS"]
    file_offset = extractions_fields["DATAOFS"]+data_offset
    rest_size = item_entry["ALIGN"]["SIZE"]
    #
    encrypted_bytes = None
    decrypted_bytes = None
    block_data_ofs = item_entry["ALIGN"]["OFSDELTA"]
    block_data_size_delta = 0
    while rest_size > 0:
        ## Calculate next data block
        if input_stream \
        and rest_size >= CONST_READ_SIZE:
            block_size = CONST_READ_SIZE
        else:  ## final block
            block_size = rest_size
            block_data_size_delta = item_entry["ALIGN"]["SIZEDELTA"] - item_entry["ALIGN"]["OFSDELTA"]
        block_data_size = block_size - block_data_ofs - block_data_size_delta

        ## Get and process encrypted data block
        if input_stream:
            ## Read encrypted data block
            try:
                encrypted_bytes = input_stream.read(file_offset, block_size, function_debug_level)
            except:
                input_stream.close(function_debug_level)
                eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(extractions_fields["DATAOFS"]+item_entry["ALIGN"]["OFS"], item_entry["ALIGN"]["SIZE"]), input_stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)
            #
            if item_data:
                item_data[CONST_DATATYPE_AS_IS].extend(encrypted_bytes)
        else:
            encrypted_bytes = item_data[CONST_DATATYPE_AS_IS]
        #
        #if enc_hashes:
        #    hash encrypted_bytes

        ## Get and process decrypted data block
        if "KEYINDEX" in item_entry \
        and "AES_CTR" in extractions_fields:
            if input_stream:
                decrypted_bytes = extractions_fields["AES_CTR"][item_entry["KEYINDEX"]].decrypt(data_offset, encrypted_bytes)
                #
                if item_data:
                    item_data[CONST_DATATYPE_DECRYPTED].extend(decrypted_bytes)
            else:
                decrypted_bytes = item_data[CONST_DATATYPE_DECRYPTED]
            #
            #if dec_hashes:
            #    hash decrypted_bytes

        ## Write extractions
        if extractions:
            for key in extractions:
                extract = extractions[key]
                if not "STREAM" in extract:
                    continue
                #
                write_bytes = None
                if extract["ITEM_DATATYPE"] == CONST_DATATYPE_AS_IS:
                    write_bytes = encrypted_bytes
                elif extract["ITEM_DATATYPE"] == CONST_DATATYPE_DECRYPTED:
                    write_bytes = decrypted_bytes
                else:
                    continue  ## TODO: error handling
                #
                if extract["ALIGNED"]:
                    extract["ITEM_BYTES_WRITTEN"] += extract["STREAM"].write(write_bytes)
                else:
                    extract["ITEM_BYTES_WRITTEN"] += extract["STREAM"].write(write_bytes[block_data_ofs:block_data_ofs+block_data_size])
            del key
            del extract

        ## Prepare for next data block
        rest_size -= block_size
        file_offset += block_size
        data_offset += block_size
        block_data_ofs = 0
    #
    del encrypted_bytes
    del decrypted_bytes

    ## Clean-up extractions
    if extractions:
        for key in extractions:
            extract = extractions[key]
            if "STREAM" in extract:
                extract["BYTES_WRITTEN"] += extract["ITEM_BYTES_WRITTEN"]
                if function_debug_level >= 2:
                    dprint("[{}] Wrote {} PKG3 item data with {}size {}".format(extract["KEY"], extract["ITEM_DATATYPE"].lower(), "aligned " if extract["ALIGNED"] else "", extract["ITEM_BYTES_WRITTEN"]))
            del extract["ITEM_BYTES_WRITTEN"]
        del extract
        del key

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
        data = sfo_bytes[header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]:header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]+temp_fields["DATAUSEDSIZE"]]
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
                data = re.sub(r"\s", " ", data, flags=re.UNICODE).strip()  ## also replaces \u3000
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


def createDirectory(extract, dirtype, extracttype, overwrite, quiet, function_debug_level):
    result = None

    if isinstance(extract, dict):
        target_display = extract["ITEM_NAME"]
        target = extract["TARGET"] = os.path.join(extract["ROOT"], extract["ITEM_EXTRACT_PATH"])
    else:
        target_display = target = extract

    if not os.path.exists(target):
        result = 0
        if quiet <= 0:
            eprint("Create {} directory \"{}\"".format(dirtype, target_display), prefix="[{}] ".format(extracttype))
        os.makedirs(target)
    elif os.path.isdir(target):
        xprint = None
        if overwrite:
            result = 0
            if function_debug_level >= 2:
                xprint = dprint
        else:
            result = 1
            xprint = eprint
        #
        if xprint:
            xprint("[{}] {}{} directory already exists and will".format(extracttype, dirtype[0].upper(), dirtype[1:]), end=" ")
            if not overwrite:
                xprint("*NOT*", end=" ", prefix=None)
            xprint("be written:", target, prefix=None)
    else:
        result = -1
        eprint("[{}] {}{} path already exists and is NOT a DIRECTORY:".format(extracttype, dirtype[0].upper(), dirtype[1:]), target)

    return result


def checkExtractFile(extract, overwrite, quiet, function_debug_level):
    result = None
    if "STREAM" in extract:
        del extract["STREAM"]

    extract["TARGET_EXISTS"] = os.path.exists(extract["TARGET"])
    if extract["TARGET_EXISTS"] \
    and os.path.isdir(extract["TARGET"]):
        result = -1
        eprint("[{}] Target file path already exists and is A DIRECTORY.".format(extract["KEY"]), extract["TARGET"] if quiet >= 1 else "")
    elif extract["TARGET_EXISTS"] \
    and not overwrite:
        result = 1
        eprint("[{}] Target file already exists and will *NOT* be overwritten.".format(extract["KEY"]), extract["TARGET"] if quiet >= 1 else "")
    else:
        result = 0

        if extract["TARGET_EXISTS"] \
        and overwrite \
        and function_debug_level >= 1:
            dprint("[{}] Target file already exists and will be OVERWRITTEN.".format(extract["KEY"]), extract["TARGET"] if quiet >= 1 else "")

        extract["STREAM"] = io.open(extract["TARGET"], mode="wb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)

    return result

def createArgParser():
    ## argparse: https://docs.python.org/3/library/argparse.html

    ## Create help texts
    ## --> Format Codes
    choices_format = []
    help_format = "Format of output via code (multiple allowed)\n"
    for key in OUTPUT_FORMATS:
        choices_format.append(key)
        help_format = "".join((help_format, "  {:#2} = {}\n".format(key, OUTPUT_FORMATS[key])))
    ## --> Extractions
    help_raw = "Create decrypted PKG file of PS3/PSX/PSP/PSV/PSM package.\n\
  Specify a target path where to create the file, e.g. \".\".\n\
  If target path is a directory then file name is <package name>.decrypted.\n\
  Note that the signature and checksum in the package tail are for the *encrypted* data."
    help_ux0 = "Extract PSX/PSV/PSM package in ux0 style hierarchy for PSV.\n\
  Specify a top dir where to create the directories and files, e.g. \".\"."
    help_content = "Extract PS3/PSX/PSP/PSV/PSM package as-is in content id style hierarchy.\n\
  Specify a top dir where to create the directories and files, e.g. \".\"."
    ## --> Overwrite
    help_overwrite = "Allow extract options, e.g. \"--raw\"/\"--ux0\", to overwrite existing files."
    ## --> Quiet
    help_quiet = "Extraction messages suppress level.\n\
  0 = All extraction messages [default]\n\
  1 = Only main extraction messages\n\
  2 = No extraction messages"
    ## --> Zrif
    help_zrif = "To create valid license file for PSV Game/DLC/Theme (work.bin) or PSM Game (FAKE.rif)."
    if not Zrif_Support:
        help_zrif = "\n".join((help_zrif, " ".join(("NOT SUPPORTED!!! As this implementation of the Python", PYTHON_VERSION, "module zlib", zlib.__version__)), "lacks support for compression dictionaries."))
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
    help_debug = "Debug verbosity level.\n\
  0 = No debug info [default]\n\
  1 = Show parsed results only\n\
  2 = Additionally show raw PKG and SFO data plus read/write actions\n\
  3 = Additionally show interim PKG and SFO data to get result plus sub-level read/write actions"

    ## Create description
    description = "%(prog)s {version}\n{copyright}\n{author}\nExtract package information and/or files from PS3/PSX/PSP/PSV/PSM and PS4 packages.".format(version=__version__, copyright=__copyright__, author=__author__)
    ## Create epilog
    epilog = "It is recommended to place \"--\" before the package/JSON sources to avoid them being used as targets,\nthen wrong option usage like \"%(prog)s --raw -- 01.pkg 02.pkg\" will not overwrite \"01.pkg\".\n\
If you state URLs then only the necessary bytes are downloaded into memory.\nNote that the options \"--raw\" download the complete(!) package just once\nwithout storing the original data on the file system."

    ## Build Arg Parser
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("source", metavar="SOURCE", nargs="+", help="Path or URL to PKG or JSON file")
    parser.add_argument("--format", "-f", metavar="CODE", type=int, action="append", choices=choices_format, help=help_format)
    parser.add_argument("--raw", metavar="TARGETPATH", help=help_raw)
    parser.add_argument("--ux0", metavar="TOPDIR", help=help_ux0)
    parser.add_argument("--content", metavar="TOPDIR", help=help_content)
    parser.add_argument("--overwrite", action="store_true", help=help_overwrite)
    parser.add_argument("--quiet", metavar="LEVEL", type=int, default=0, help=help_quiet)
    parser.add_argument("--zrif", metavar="LICENSE", action="append", help=help_zrif)
    parser.add_argument("--unclean", action="store_true", help=help_unclean)
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
            ## Check special cases if file specified
            if not Raw_Is_Dir:
                if os.path.exists(Arguments.raw):
                    XPrint = None
                    if Arguments.overwrite:
                        if Debug_Level >= 2:
                            XPrint = dprint
                    else:
                        XPrint = eprint
                    #
                    if XPrint:
                        XPrint("[{}] Extraction file already exists and will".format(CONST_EXTRACT_RAW), end=" ")
                        if not Arguments.overwrite:
                            XPrint("*NOT*", end=" ", prefix=None)
                        XPrint("be overwritten:", Arguments.raw, prefix=None)
                        del XPrint
                    #
                    if not Arguments.overwrite:
                        Arguments.raw = -1
                elif len(Arguments.source) > 1 \
                and not Arguments.overwrite:
                    eprint("[{}] Multiple sources specified but extraction file will *NOT* be overwritten:".format(CONST_EXTRACT_RAW), Arguments.raw)
                    Arguments.raw = -1
        if Arguments.ux0:
            Arguments.ux0 = os.path.normpath(Arguments.ux0)
            if createDirectory(Arguments.ux0, "top extraction", CONST_EXTRACT_UX0, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                Arguments.ux0 = -1
        if Arguments.content:
            Arguments.content = os.path.normpath(Arguments.content)
            if createDirectory(Arguments.content, "top extraction", CONST_EXTRACT_CONTENT, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                Arguments.content = -1
        if Arguments.raw == -1 \
        or Arguments.ux0 == -1 \
        or Arguments.content == -1:
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
        ## --> PBP Header
        finalizeBytesStructure(CONST_PBP_HEADER_FIELDS, CONST_PBP_ENDIAN, "PBP Header", "{}[{:1}]: ofs {:#04x} size {:1} key {:13} = {}", Debug_Level)
        ## --> RIF PSP/PSV
        finalizeBytesStructure(CONST_PSV_RIF_FIELDS, CONST_PSV_RIF_ENDIAN, "PSP/PSV RIF", "{}[{:2}]: ofs {:#04x} size {:1} key {:13} = {}", Debug_Level)
        ## --> RIF PSM
        finalizeBytesStructure(CONST_PSM_RIF_FIELDS, CONST_PSM_RIF_ENDIAN, "PSM RIF", "{}[{:2}]: ofs {:#04x} size {:1} key {:13} = {}", Debug_Level)

        ## Prepare ZRIF licenses
        Rifs = collections.OrderedDict()
        Rif_Number = 0
        if Zrif_Support and Arguments.zrif:
            for Zrif in Arguments.zrif:
                Rif_Number += 1
                Zrif_Bytes = bytes(base64.b64decode(Zrif.encode("ascii")))
                #
                Decompress_Object = zlib.decompressobj(wbits=10, zdict=bytes(CONST_ZRIF_COMPRESSION_DICTIONARY))
                Rif_Bytes = bytearray()
                Rif_Bytes.extend(Decompress_Object.decompress(Zrif_Bytes))
                Rif_Bytes.extend(Decompress_Object.flush())
                #
                Rif_Fields = None
                if getInteger16BitLE(Rif_Bytes, CONST_RIF_TYPE_OFFSET) == 0:  ## PSM license
                    Temp_Fields = struct.unpack(CONST_PSM_RIF_FIELDS["STRUCTURE_UNPACK"], Rif_Bytes)
                    Rif_Fields = convertFieldsToOrdDict(CONST_PSM_RIF_FIELDS, Temp_Fields)
                    del Temp_Fields
                    #
                    if Rif_Fields["AID"] == CONST_RIF_FAKE_AID:
                        Rif_Fields["LIC_TYPE"] = "PSM NoPsmDrm fake license"
                    else:
                        Rif_Fields["LIC_TYPE"] = "PSM *NOT* a fake license"
                else:
                    Temp_Fields = struct.unpack(CONST_PSV_RIF_FIELDS["STRUCTURE_UNPACK"], Rif_Bytes)
                    Rif_Fields = convertFieldsToOrdDict(CONST_PSV_RIF_FIELDS, Temp_Fields)
                    del Temp_Fields
                    #
                    if Rif_Fields["AID"] == CONST_RIF_FAKE_AID:
                        Rif_Fields["LIC_TYPE"] = "PSV NoNpDrm fake license"
                    else:
                        Rif_Fields["LIC_TYPE"] = "PSV *NOT* a fake license"
                #
                Key = Rif_Fields["CONTENT_ID"]
                Rifs[Key] = Rif_Fields
                Rifs[Key]["BYTES"] = Rif_Bytes

                ## Output additional results
                if 50 in Arguments.format:  ## Additional debugging Output
                    print(">>>>> Rif #{} \"{}\" ({})".format(Rif_Number, Key, Rif_Fields["LIC_TYPE"]))
                    dprintFieldsDict(Rif_Fields, "rif[{KEY:14}]", 3, None, print_func=print)
            #
            del Key
            del Rif_Fields
            del Rif_Bytes
            del Decompress_Object
            del Zrif_Bytes
            del Zrif
        del Rif_Number

        ## Process paths and URLs
        for Source in Arguments.source:
            ## Initialize per-package variables
            Input_Stream = None
            Extractions = {}
            Extractions_Fields = {}
            Process_Extractions = False
            #
            Package = {}
            Package["HEAD_BYTES"] = bytearray()
            Package["TAIL_BYTES"] = bytearray()
            Pkg_Header = None
            Pkg_Ext_Header = None
            Pkg_Meta_Data = None
            Pkg_Item_Entries = None
            Pkg_Items_Info_Bytes = None
            Retrieve_Encrypted_Param_Sfo = False
            Pkg_File_Table = None
            Pkg_File_Table_Map = None
            Sfo_Item_Data = None
            Sfo_Bytes = None
            Pkg_Sfo_Values = None
            Pbp_Header = None
            Pbp_Item_Entries = None
            Nps_Type = "UNKNOWN"
            #
            Results = collections.OrderedDict()
            Results["TOOL_VERSION"] = __version__
            Results["PYTHON_VERSION"] = PYTHON_VERSION

            ## Open PKG source
            if not 3 in Arguments.format \
            and not 98 in Arguments.format:  ## Special case JSON output for parsing
                print("# >>>>>>>>>> PKG Source:", Source)
            else:
                eprint("# >>>>>>>>>> PKG Source:", Source, prefix=None)
            #
            Input_Stream = PkgInputReader(Source, max(0, Debug_Level))
            Results["FILE_SIZE"] = Input_Stream.getSize(Debug_Level)
            if Results["FILE_SIZE"] is None:
                del Results["FILE_SIZE"]
            elif Debug_Level >= 2:
                dprint("File Parts Combined Size:", Results["FILE_SIZE"])

            ## Initialize header bytes array
            dprint(">>>>> PKG Main Header:")

            ## Get file magic code/string and check for PKG/PBP file
            ## see http://www.psdevwiki.com/ps3/PKG_files#File_Header_2
            ## see http://www.psdevwiki.com/ps4/PKG_files#File_Header
            try:
                Package["HEAD_BYTES"].extend(Input_Stream.read(0, 4, Debug_Level))
            except:
                Input_Stream.close(Debug_Level)
                eprint("Could not get PKG magic at offset {:#x} with size {} from".format(0, 4), Input_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)
            Pkg_Magic = getInteger32BitBE(Package["HEAD_BYTES"], 0x00)
            #
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Header_Size = CONST_PKG3_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                Nps_Type = "".join((Nps_Type, " (PS3/PSX/PSP/PSV/PSM)"))
                dprint("Detected PS3/PSX/PSP/PSV/PSM package")
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Header_Size = CONST_PKG4_MAIN_HEADER_FIELDS["STRUCTURE_SIZE"]
                Nps_Type = "".join((Nps_Type, " (PS4)"))
                dprint("Detected PS4 package")
            ## --> PBP
            elif Pkg_Magic == CONST_PBP_MAGIC:
                Header_Size = CONST_PBP_HEADER_FIELDS["STRUCTURE_SIZE"]
                Nps_Type = "".join((Nps_Type, " (PBP)"))
                dprint("Detected PBP")
            else:
                Input_Stream.close(Debug_Level)
                eprint("Not a known PKG/PBP file ({:#x} <> {:#x}|{:#x}|{:#x})".format(Pkg_Magic, CONST_PKG3_MAGIC, CONST_PKG4_MAGIC, CONST_PBP_MAGIC), Input_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)

            ## Get rest of PKG main header from input stream
            if Debug_Level >= 2:
                dprint("Get main header from offset {:#x} with size {}".format(0, Header_Size))
            try:
                Package["HEAD_BYTES"].extend(Input_Stream.read(4, Header_Size-4, Debug_Level))
            except:
                Input_Stream.close(Debug_Level)
                eprint("Could not get rest of main header at offset {:#x} with size {} from".format(4, Header_Size-4), Input_Stream.getSource())
                eprint("", prefix=None)
                sys.exit(2)

            ## Process PKG main header data
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Pkg_Header, Pkg_Ext_Header, Pkg_Meta_Data, Package["HEAD_BYTES"] = parsePkg3Header(Package["HEAD_BYTES"], Input_Stream, max(0, Debug_Level))
                ## --> Size of package (=file size)
                if "TOTALSIZE" in Pkg_Header:
                    Results["PKG_TOTAL_SIZE"] = Pkg_Header["TOTALSIZE"]
                ## --> Package content id
                if "CONTENT_ID" in Pkg_Header:
                    Results["PKG_CONTENT_ID"] = Pkg_Header["CONTENT_ID"]
                    Results["PKG_CID_TITLE_ID1"] = Results["PKG_CONTENT_ID"][7:16]
                    Results["PKG_CID_TITLE_ID2"] = Results["PKG_CONTENT_ID"][20:]
                ## --> param.sfo offset + size
                if 0x0E in Pkg_Meta_Data:
                    Results["PKG_SFO_OFFSET"] = Pkg_Meta_Data[0x0E]["OFS"]
                    Results["PKG_SFO_SIZE"] = Pkg_Meta_Data[0x0E]["SIZE"]
                ## --> DRM Type
                if 0x01 in Pkg_Meta_Data:
                    Results["PKG_DRM_TYPE"] = Pkg_Meta_Data[0x01]["VALUE"]
                ## --> Content Type
                if 0x02 in Pkg_Meta_Data:
                    Results["PKG_CONTENT_TYPE"] = Pkg_Meta_Data[0x02]["VALUE"]
                ## --> Title ID
                if 0x06 in Pkg_Meta_Data:  ## Version + App Version / TitleID (on size 0xC)
                    Results["MD_TITLE_ID"] = Pkg_Meta_Data[0x06]["VALUE"]
                ## --> Items Info checks
                if 0x0D in Pkg_Meta_Data:
                    ## a) offset inside encrypted data
                    if Pkg_Meta_Data[0x0D]["OFS"] != 0:
                        eprint("Items Info start offset inside encrypted data {:#0x} <> 0x0.".format(Pkg_Meta_Data[0x0D]["OFS"]), Input_Stream.getSource(), prefix="[UNKNOWN] ")
                        eprint("Please report this unknown case at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")
                    ## b) size
                    if Pkg_Meta_Data[0x0D]["SIZE"] < (Pkg_Header["ITEMCNT"]*CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]):
                        eprint("Items Info size {} from meta data 0x0D is too small for {} Item Entries with total size of {}.".format(Pkg_Meta_Data[0x0D]["SIZE"], Pkg_Header["ITEMCNT"], Pkg_Header["ITEMCNT"]*CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]), Input_Stream.getSource())
                        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
                ## If PARAM.SFO not present in unencrypted data, then search in encrypted item entries
                if not "PKG_SFO_OFFSET" in Results \
                and "PARAM.SFO" in Pkg_Header \
                and Pkg_Header["PARAM.SFO"].strip():
                    Retrieve_Encrypted_Param_Sfo = True
                ## Process PKG3 encrypted item entries
                if not Pkg_Header["KEYINDEX"] is None \
                and (Arguments.itementries \
                     or Arguments.raw \
                     or Arguments.ux0 \
                     or Arguments.content \
                     or Retrieve_Encrypted_Param_Sfo ):
                    Pkg_Item_Entries, Pkg_Items_Info_Bytes = parsePkg3ItemsInfo(Pkg_Header, Pkg_Meta_Data, Input_Stream, max(0, Debug_Level))
                    #
                    Results["ITEMS_INFO"] = copy.copy(Pkg_Items_Info_Bytes)
                    if CONST_DATATYPE_AS_IS in Results["ITEMS_INFO"]:
                        del Results["ITEMS_INFO"][CONST_DATATYPE_AS_IS]
                    if CONST_DATATYPE_DECRYPTED in Results["ITEMS_INFO"]:
                        del Results["ITEMS_INFO"][CONST_DATATYPE_DECRYPTED]
                #
                if not Pkg_Item_Entries is None \
                and Retrieve_Encrypted_Param_Sfo:
                    for Item_Entry in Pkg_Item_Entries:
                        Item_Data = None
                        #
                        if Retrieve_Encrypted_Param_Sfo \
                        and "NAME" in Item_Entry \
                        and Item_Entry["NAME"] == Pkg_Header["PARAM.SFO"] \
                        and Item_Entry["DATASIZE"] > 0:
                            Item_Data = {}
                        #
                        if not Item_Data is None:
                            processPkg3Item(Pkg_Header, Item_Entry, Input_Stream, Item_Data, None, max(0, Debug_Level))
                            #
                            if Retrieve_Encrypted_Param_Sfo \
                            and "NAME" in Item_Entry \
                            and Item_Entry["NAME"] == Pkg_Header["PARAM.SFO"]:
                                Sfo_Item_Data = Item_Data
                                Sfo_Bytes = Sfo_Item_Data[CONST_DATATYPE_DECRYPTED][Item_Entry["ALIGN"]["OFSDELTA"]:Item_Entry["ALIGN"]["OFSDELTA"]+Item_Entry["DATASIZE"]]
                        #
                        del Item_Data
                    del Item_Entry
                ## Get PKG3 unencrypted tail data
                if Debug_Level >= 2:
                    dprint(">>>>> PKG3 Tail:")
                    dprint("Get PKG3 unencrypted tail data from offset {:#x} size {}".format(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"])))
                try:
                    Package["TAIL_BYTES"] = Input_Stream.read(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"]), Debug_Level)
                except:
                    Input_Stream.close(Debug_Level)
                    eprint("Could not get PKG3 unencrypted tail at offset {:#x} size {} from".format(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"])), Input_Stream.getSource())
                    eprint("", prefix=None)
                #
                if Package["TAIL_BYTES"]:  ## may not be present or have failed, e.g. when analyzing a head.bin file, a broken download or only thje first file of a multi-part package
                    Results["PKG_TAIL_SIZE"] = len(Package["TAIL_BYTES"])
                    Results["PKG_TAIL_SHA1"] = Package["TAIL_BYTES"][-0x20:-0x0c]
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Pkg_Header, Pkg_File_Table, Pkg_File_Table_Map = parsePkg4Header(Package["HEAD_BYTES"], Input_Stream, max(0, Debug_Level), print_unknown=Arguments.unknown)
                ## --> Size of package (=file size)
                if "PKGSIZE" in Pkg_Header:
                    Results["PKG_TOTAL_SIZE"] = Pkg_Header["PKGSIZE"]
                ## --> Package content id
                if "CONTENT_ID" in Pkg_Header:
                    Results["PKG_CONTENT_ID"] = Pkg_Header["CONTENT_ID"]
                    Results["PKG_CID_TITLE_ID1"] = Results["PKG_CONTENT_ID"][7:16]
                    Results["PKG_CID_TITLE_ID2"] = Results["PKG_CONTENT_ID"][20:]
                ## --> param.sfo offset + size
                if CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO in Pkg_File_Table_Map:
                    File_Entry = Pkg_File_Table[Pkg_File_Table_Map[CONST_PKG4_FILE_ENTRY_ID_PARAM_SFO]]
                    Results["PKG_SFO_OFFSET"] = File_Entry["DATAOFS"]
                    Results["PKG_SFO_SIZE"] = File_Entry["DATASIZE"]
                ## --> DRM Type
                if "DRMTYPE" in Pkg_Header:
                    Results["PKG_DRM_TYPE"] = Pkg_Header["DRMTYPE"]
                ## --> Content Type
                if "CONTTYPE" in Pkg_Header:
                    Results["PKG_CONTENT_TYPE"] = Pkg_Header["CONTTYPE"]
            ## --> PBP
            elif Pkg_Magic == CONST_PBP_MAGIC:
                Pbp_Header, Pbp_Item_Entries = parsePbpHeader(Package["HEAD_BYTES"], Input_Stream, max(0, Debug_Level), Results["FILE_SIZE"])
                ## --> param.sfo offset + size
                if "PARAM_SFO_OFS" in Pbp_Header:
                    Results["PKG_SFO_OFFSET"] = Pbp_Header["PARAM_SFO_OFS"]
                    Results["PKG_SFO_SIZE"] = Pbp_Header["ICON0_PNG_OFS"] - Pbp_Header["PARAM_SFO_OFS"]
            #
            if "PKG_CONTENT_ID" in Results \
            and Results["PKG_CONTENT_ID"].strip():
                Results["CONTENT_ID"] = Results["PKG_CONTENT_ID"].strip()
                Results["CID_TITLE_ID1"] = Results["CONTENT_ID"][7:16]
                Results["CID_TITLE_ID2"] = Results["CONTENT_ID"][20:]
                Results["TITLE_ID"] = Results["CID_TITLE_ID1"]
            #
            if "MD_TITLE_ID" in Results \
            and Results["MD_TITLE_ID"].strip():
                if not "TITLE_ID" in Results:
                    Results["TITLE_ID"] = Results["MD_TITLE_ID"].strip()
                if "CID_TITLE_ID1" in Results \
                and Results["MD_TITLE_ID"] != Results["CID_TITLE_ID1"]:
                    Results["MD_TID_DIFFER"] = True

            ## Retrieve PARAM.SFO from unencrypted data if present
            if "PKG_SFO_OFFSET" in Results \
            and Results["PKG_SFO_OFFSET"] > 0 \
            and not Sfo_Bytes:
                if Debug_Level >= 2:
                    dprint(">>>>> PARAM.SFO:")
                ## Get PARAM.SFO from input stream
                if Debug_Level >= 2:
                    dprint("Get PARAM.SFO from unencrypted data with offset {:#x} with size {}".format(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"]), end=" ")
                Sfo_Bytes = bytearray()
                if len(Package["HEAD_BYTES"]) >= (Results["PKG_SFO_OFFSET"]+Results["PKG_SFO_SIZE"]):
                    if Debug_Level >= 2:
                        dprint("from head data", prefix=None)
                    Sfo_Bytes.extend(Package["HEAD_BYTES"][Results["PKG_SFO_OFFSET"]:Results["PKG_SFO_OFFSET"]+Results["PKG_SFO_SIZE"]])
                else:
                    if Debug_Level >= 2:
                        dprint("from input stream", prefix=None)
                    try:
                        Sfo_Bytes.extend(Input_Stream.read(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"], Debug_Level))
                    except:
                        Input_Stream.close(Debug_Level)
                        eprint("Could not get PARAM.SFO at offset {:#x} with size {} from".format(Results["PKG_SFO_OFFSET"], Results["PKG_SFO_SIZE"]), Input_Stream.getSource())
                        eprint("", prefix=None)
                        sys.exit(2)

            ## Process PARAM.SFO if present
            if Sfo_Bytes:
                ## Check for known PARAM.SFO data
                SfoMagic = getInteger32BitLE(Sfo_Bytes, 0)
                if SfoMagic != CONST_PARAM_SFO_MAGIC:
                    Input_Stream.close(Debug_Level)
                    eprint("Not a known PARAM.SFO structure ({:#x} <> {:#x})".format(SfoMagic, CONST_PARAM_SFO_MAGIC), Input_Stream.getSource())
                    eprint("", prefix=None)
                    sys.exit(2)

                ## Process PARAM.SFO data
                Pkg_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                ## -->
                if "DISC_ID" in Pkg_Sfo_Values:
                    Results["SFO_TITLE_ID"] = Pkg_Sfo_Values["DISC_ID"]
                if "TITLE_ID" in Pkg_Sfo_Values:
                    Results["SFO_TITLE_ID"] = Pkg_Sfo_Values["TITLE_ID"]
                    if "PKG_CID_TITLE_ID1" in Results \
                    and Pkg_Sfo_Values["TITLE_ID"] != Results["PKG_CID_TITLE_ID1"]:
                        Results["SFO_PKG_TID_DIFFER"] = True
                ## -->
                if "CONTENT_ID" in Pkg_Sfo_Values:
                    Results["SFO_CONTENT_ID"] = Pkg_Sfo_Values["CONTENT_ID"]
                    Results["SFO_CID_TITLE_ID1"] = Results["SFO_CONTENT_ID"][7:16]
                    Results["SFO_CID_TITLE_ID2"] = Results["SFO_CONTENT_ID"][20:]
                    if "PKG_CONTENT_ID" in Results \
                    and Pkg_Sfo_Values["CONTENT_ID"] != Results["PKG_CONTENT_ID"]:
                        Results["SFO_PKG_CID_DIFFER"] = True
                    if "TITLE_ID" in Pkg_Sfo_Values \
                    and Pkg_Sfo_Values["TITLE_ID"] != Results["SFO_CID_TITLE_ID1"]:
                        Results["SFO_TID_DIFFER"] = True
                ## --> Firmware PS3
                if "PS3_SYSTEM_VER" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["PS3_SYSTEM_VER"]:
                    Results["SFO_MIN_VER"] = float(Pkg_Sfo_Values["PS3_SYSTEM_VER"])
                ## --> Firmware PSP
                if "PSP_SYSTEM_VER" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["PSP_SYSTEM_VER"]:
                    Results["SFO_MIN_VER"] = float(Pkg_Sfo_Values["PSP_SYSTEM_VER"])
                ## --> Firmware PS Vita
                if "PSP2_DISP_VER" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["PSP2_DISP_VER"]:
                    Results["SFO_MIN_VER"] = float(Pkg_Sfo_Values["PSP2_DISP_VER"])
                ## --> Firmware PS4
                if "SYSTEM_VER" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["SYSTEM_VER"]:
                    Results["SFO_MIN_VER"] = float("{:02x}.{:02x}".format((Pkg_Sfo_Values["SYSTEM_VER"] >> 24) & 0xff, (Pkg_Sfo_Values["SYSTEM_VER"] >> 16) & 0xff))
                ## -->
                if "CATEGORY" in Pkg_Sfo_Values:
                    Results["SFO_CATEGORY"] = Pkg_Sfo_Values["CATEGORY"]
                ## -->
                if "DISC_VERSION" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["DISC_VERSION"]:
                    Results["SFO_VERSION"] = float(Pkg_Sfo_Values["DISC_VERSION"])
                if "VERSION" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["VERSION"]:
                    Results["SFO_VERSION"] = float(Pkg_Sfo_Values["VERSION"])
                ## -->
                if "APP_VER" in Pkg_Sfo_Values \
                and Pkg_Sfo_Values["APP_VER"]:
                    Results["SFO_APP_VER"] = float(Pkg_Sfo_Values["APP_VER"])
                ## -->
                if "PUBTOOLINFO" in Pkg_Sfo_Values:
                    try:
                        Results["SFO_CREATION_DATE"] = Pkg_Sfo_Values["PUBTOOLINFO"][7:15]
                        Results["SFO_SDK_VER"] = int(Pkg_Sfo_Values["PUBTOOLINFO"][24:32]) / 1000000
                    except:
                        pass
                #
                if not "TITLE_ID" in Results \
                and "SFO_TITLE_ID" in Results \
                and Results["SFO_TITLE_ID"].strip():
                    Results["TITLE_ID"] = Results["SFO_TITLE_ID"].strip()
                #
                if not "CONTENT_ID" in Results \
                and "SFO_CONTENT_ID" in Results \
                and Results["SFO_CONTENT_ID"].strip():
                    Results["CONTENT_ID"] = Results["SFO_CONTENT_ID"].strip()
                    Results["CID_TITLE_ID1"] = Results["CONTENT_ID"][7:16]
                    Results["CID_TITLE_ID2"] = Results["CONTENT_ID"][20:]
                    if not "TITLE_ID" in Results:
                        Results["TITLE_ID"] = Results["CID_TITLE_ID1"]
            #
            if not "SFO_MIN_VER" in Results:
                Results["SFO_MIN_VER"] = 0.00  ## mandatory value

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
                if Pkg_Sfo_Values \
                and Key in Pkg_Sfo_Values \
                and Pkg_Sfo_Values[Key].strip():
                   if Debug_Level >= 2:
                       dprint("Set international name to", Key)
                   Results["SFO_TITLE"] = Pkg_Sfo_Values[Key].strip()
                   break
            if not "SFO_TITLE" in Results \
            and Pkg_Sfo_Values \
            and "TITLE" in Pkg_Sfo_Values \
            and Pkg_Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set international title to TITLE")
                Results["SFO_TITLE"] = Pkg_Sfo_Values["TITLE"].strip()
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
                Results["SFO_TITLE"] = re.sub(r"\s+", " ", Results["SFO_TITLE"], flags=re.UNICODE).strip()  ## also replaces \u3000
                ## Condense demo information in title to "(DEMO)"
                Results["SFO_TITLE"] = Results["SFO_TITLE"].replace("demo ver.", "(DEMO)").replace("(Demo Version)", "(DEMO)").replace("Demo Version", "(DEMO)").replace("Demo version", "(DEMO)").replace("DEMO Version", "(DEMO)").replace("DEMO version", "(DEMO)").replace("【体験版】", "(DEMO)").replace("(体験版)", "(DEMO)").replace("体験版", "(DEMO)").strip()
                Results["SFO_TITLE"] = re.sub(r"\(demo\)", r"(DEMO)", Results["SFO_TITLE"], flags=re.IGNORECASE|re.UNICODE)
                Results["SFO_TITLE"] = re.sub(r"(^|[^a-z(]{1})demo([^a-z)]{1}|$)", r"\1(DEMO)\2", Results["SFO_TITLE"], flags=re.IGNORECASE|re.UNICODE)
            ## c) Regional title
            if "LANGUAGES" in Results \
            and Results["LANGUAGES"]:
                for Language in Results["LANGUAGES"]:
                    Key = "".join(("TITLE_", Language))
                    if Pkg_Sfo_Values \
                    and Key in Pkg_Sfo_Values \
                    and Pkg_Sfo_Values[Key].strip():
                       if Debug_Level >= 2:
                           dprint("Set regional title to", Key)
                       Results["SFO_TITLE_REGIONAL"] = Pkg_Sfo_Values[Key].strip()
                       break
            if not "SFO_TITLE_REGIONAL" in Results \
            and Pkg_Sfo_Values \
            and "TITLE" in Pkg_Sfo_Values \
            and Pkg_Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set regional title to TITLE")
                Results["SFO_TITLE_REGIONAL"] = Pkg_Sfo_Values["TITLE"].strip()
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
                Results["SFO_TITLE_REGIONAL"] = re.sub(r"\s+", " ", Results["SFO_TITLE_REGIONAL"], flags=re.UNICODE).strip()  ## also replaces \u3000

            ## Determine platform and package type
            ## TODO: Further complete determination (e.g. PS4 content types)
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                if "PKG_CONTENT_TYPE" in Results:
                    ## --> PS3 packages
                    if Results["PKG_CONTENT_TYPE"] == 0x4 \
                    or Results["PKG_CONTENT_TYPE"] == 0xB:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        if 0x0B in Pkg_Meta_Data:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                            Nps_Type = "PS3 UPDATE"
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                            Nps_Type = "PS3 DLC"
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                    elif Results["PKG_CONTENT_TYPE"] == 0x5:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PS3 GAME"
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                    elif Results["PKG_CONTENT_TYPE"] == 0x9:  ## PS3/PSP Themes
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.THEME
                        Nps_Type = "PS3 THEME"
                        #
                        if 0x03 in Pkg_Meta_Data \
                        and Pkg_Meta_Data[0x03]["VALUE"] == bytes.fromhex("0000020c"):
                            Results["PLATFORM"] = CONST_PLATFORM.PSP
                            Nps_Type = "PSP THEME"
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                    elif Results["PKG_CONTENT_TYPE"] == 0xD:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.AVATAR
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PS3 AVATAR"
                    elif Results["PKG_CONTENT_TYPE"] == 0x12:  ## PS2 /SFO_CATEGORY = 2P
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PS2
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PS3 GAME"
                        #
                        if "SFO_TITLE_ID" in Results:
                            Results["PS2_TITLE_ID"] = Results["SFO_TITLE_ID"]
                    ## --> PSX packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x1 \
                    or Results["PKG_CONTENT_TYPE"] == 0x6:
                        Results["PLATFORM"] = CONST_PLATFORM.PSX
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        #
                        Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("pspemu", "PSP", "GAME", Results["PKG_CID_TITLE_ID1"])
                        Results["PKG_EXTRACT_LIC_UX0"] = os.path.join("pspemu", "PSP", "LICENSE", "".join((Results["PKG_CONTENT_ID"], ".rif")))
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSX GAME"
                        #
                        ## Special Case: PCSC80018 "Pocketstation for PS Vita"
                        if Results["TITLE_ID"] == "PCSC80018":
                            Results["PLATFORM"] = CONST_PLATFORM.PSV
                            Results["PKG_SUB_TYPE"] = CONST_PLATFORM.PSX
                            Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("ps1emu", Results["PKG_CID_TITLE_ID1"])
                            Nps_Type = "PSV GAME"
                        #
                        if Results["PKG_CONTENT_TYPE"] == 0x6 \
                        and "MD_TITLE_ID" in Results:
                            Results["PSX_TITLE_ID"] = Results["MD_TITLE_ID"]
                    ## --> PSP packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x7 \
                    or Results["PKG_CONTENT_TYPE"] == 0xE \
                    or Results["PKG_CONTENT_TYPE"] == 0xF \
                    or Results["PKG_CONTENT_TYPE"] == 0x10:
                        Results["PLATFORM"] = CONST_PLATFORM.PSP
                        if 0x0B in Pkg_Meta_Data:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                            Nps_Type = "PSP DLC"
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                            Nps_Type = "PSP GAME"
                        #
                        ## TODO: Verify when ISO and when GAME directory has to be used?
                        Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("pspemu", "PSP", "GAME", Results["PKG_CID_TITLE_ID1"])
                        Results["PKG_EXTRACT_ISOR_UX0"] = os.path.join("pspemu", "ISO")
                        Results["PKG_EXTRACT_ISO_NAME"] = "".join((Results["SFO_TITLE"], " [", Results["PKG_CID_TITLE_ID1"], "]", ".iso"))
                        #
                        if Results["PKG_CONTENT_TYPE"] == 0x7:
                            if "SFO_CATEGORY" in Results \
                            and Results["SFO_CATEGORY"] == "HG":
                                Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_PC_ENGINE
                        elif Results["PKG_CONTENT_TYPE"] == 0xE:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_GO
                        elif Results["PKG_CONTENT_TYPE"] == 0xF:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_MINI
                        elif Results["PKG_CONTENT_TYPE"] == 0x10:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_NEOGEO
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                    ## --> PSV packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x15:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        #
                        if "SFO_CATEGORY" in Results \
                        and Results["SFO_CATEGORY"] == "gp":
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                            Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("patch", Results["CID_TITLE_ID1"])
                            Nps_Type = "PSV UPDATE"
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                            Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("app", Results["CID_TITLE_ID1"])
                            Nps_Type = "PSV GAME"
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                            del Update_Hash
                    elif Results["PKG_CONTENT_TYPE"] == 0x16:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                        #
                        Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("addcont", Results["CID_TITLE_ID1"], Results["CID_TITLE_ID2"])
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSV DLC"
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                            del Update_Hash
                    elif Results["PKG_CONTENT_TYPE"] == 0x1F:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.THEME
                        #
                        Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("theme", "-".join((Results["CID_TITLE_ID1"], Results["CID_TITLE_ID2"])))
                        ## TODO/FUTURE: bgdl
                        ## - find next free xxxxxxxx dir (hex 00000000-FFFFFFFF)
                        ##   Note that Vita has issues with handling more than 32 bgdls at once
                        ## - package sub dir is Results["PKG_CID_TITLE_ID1"] for Game/DLC/Theme
                        ## - create additional d0/d1.pdb and temp.dat files in root dir for Game/Theme
                        ## - create additional f0.pdb for DLC
                        #Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("bgdl", "t", "xxxxxx")
                        #, )))
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSV THEME"
                    ## --> PSM packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x18 \
                    or Results["PKG_CONTENT_TYPE"] == 0x1D:
                        Results["PLATFORM"] = CONST_PLATFORM.PSM
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        #
                        Results["PKG_EXTRACT_ROOT_UX0"] = os.path.join("psm", Results["PKG_CID_TITLE_ID1"])
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSM GAME"
                    ## --> UNKNOWN packages
                    else:
                        eprint("PKG content type {0}/{0:#0x}.".format(Results["PKG_CONTENT_TYPE"]), Input_Stream.getSource(), prefix="[UNKNOWN] ")
                        #
                        Results["PKG_EXTRACT_ROOT_CONT"] = Pkg_Header["CONTENT_ID"][7:]
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Results["PLATFORM"] = CONST_PLATFORM.PS4
                if Results["PKG_CONTENT_TYPE"] == 0x1A:
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"] == "gd":
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        Nps_Type = "PS4 GAME"
                    elif "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"] == "gp":
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                        Nps_Type = "PS4 UPDATE"
                elif Results["PKG_CONTENT_TYPE"] == 0x1B:
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"] == "ac":
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                        Nps_Type = "PS4 DLC"
            ## --> PBP
            elif Pkg_Magic == CONST_PBP_MAGIC:
                pass  ## TODO
                #
                Results["PKG_EXTRACT_ROOT_CONT"] = Results["TITLE_ID"]
            #
            Results["NPS_TYPE"] = Nps_Type

            ## Output results
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
                    JSON_Output["results"]["source"] = Source
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
                    if "PKG_TOTAL_SIZE" in Results \
                    and Results["PKG_TOTAL_SIZE"] > 0:
                        JSON_Output["results"]["pkgTotalSize"] = Results["PKG_TOTAL_SIZE"]
                        JSON_Output["results"]["prettySize"] = prettySize(Results["PKG_TOTAL_SIZE"])
                    if "FILE_SIZE" in Results:
                        JSON_Output["results"]["fileSize"] = Results["FILE_SIZE"]
                    if "TITLE_UPDATE_URL" in Results \
                    and Results["TITLE_UPDATE_URL"].strip():
                        JSON_Output["results"]["titleUpdateUrl"] = Results["TITLE_UPDATE_URL"]
                    JSON_Output["results"]["npsType"] = Results["NPS_TYPE"]
                    if "PLATFORM" in Results:
                        JSON_Output["results"]["pkgPlatform"] = Results["PLATFORM"]
                    if "PKG_TYPE" in Results:
                        JSON_Output["results"]["pkgType"] = Results["PKG_TYPE"]
                    if "PKG_SUB_TYPE" in Results:
                        JSON_Output["results"]["pkgSubType"] = Results["PKG_SUB_TYPE"]
                    #
                    if "TOOL_VERSION" in Results:
                        JSON_Output["results"]["toolVersion"] = Results["TOOL_VERSION"]
                    if "PYTHON_VERSION" in Results:
                        JSON_Output["results"]["pythonVersion"] = Results["PYTHON_VERSION"]
                    if "PKG_CONTENT_ID" in Results \
                    and Results["PKG_CONTENT_ID"].strip():
                        JSON_Output["results"]["pkgContentId"] = Results["PKG_CONTENT_ID"]
                        JSON_Output["results"]["pkgCidTitleId1"] = Results["PKG_CID_TITLE_ID1"]
                        JSON_Output["results"]["pkgCidTitleId2"] = Results["PKG_CID_TITLE_ID2"]
                    if "MD_TITLE_ID" in Results:
                        JSON_Output["results"]["mdTitleId"] = Results["MD_TITLE_ID"]
                        if "MD_TID_DIFFER" in Results:
                           JSON_Output["results"]["mdTidDiffer"] = Results["MD_TID_DIFFER"]
                    if "PKG_SFO_OFFSET" in Results:
                        JSON_Output["results"]["pkgSfoOffset"] = Results["PKG_SFO_OFFSET"]
                    if "PKG_SFO_OFFSET" in Results:
                        JSON_Output["results"]["pkgSfoSize"] = Results["PKG_SFO_SIZE"]
                    if "PKG_DRM_TYPE" in Results:
                        JSON_Output["results"]["pkgDrmType"] = Results["PKG_DRM_TYPE"]
                    if "PKG_CONTENT_TYPE" in Results:
                        JSON_Output["results"]["pkgContentType"] = Results["PKG_CONTENT_TYPE"]
                    if "PKG_TAIL_SIZE" in Results:
                        JSON_Output["results"]["pkgTailSize"] = Results["PKG_TAIL_SIZE"]
                    if "PKG_TAIL_SHA1" in Results:
                        JSON_Output["results"]["pkgTailSha1"] = Results["PKG_TAIL_SHA1"]
                    if "ITEMS_INFO" in Results:
                        JSON_Output["results"]["itemsInfo"] = copy.copy(Results["ITEMS_INFO"])
                        if "ALIGN" in JSON_Output["results"]["itemsInfo"]:
                            del JSON_Output["results"]["itemsInfo"]["ALIGN"]
                    if "SFO_TITLE_ID" in Results:
                        JSON_Output["results"]["sfoTitleId"] = Results["SFO_TITLE_ID"]
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"].strip():
                        JSON_Output["results"]["sfoCategory"] = Results["SFO_CATEGORY"]
                    if "SFO_CONTENT_ID" in Results \
                    and Results["SFO_CONTENT_ID"].strip():
                        JSON_Output["results"]["sfoContentId"] = Results["SFO_CONTENT_ID"]
                        JSON_Output["results"]["sfoCidTitleId1"] = Results["SFO_CID_TITLE_ID1"]
                        JSON_Output["results"]["sfoCidTitleId2"] = Results["SFO_CID_TITLE_ID2"]
                        if "SFO_CID_DIFFER" in Results:
                           JSON_Output["results"]["sfoCidDiffer"] = Results["SFO_CID_DIFFER"]
                        if "SFO_TID_DIFFER" in Results:
                           JSON_Output["results"]["sfoTidDiffer"] = Results["SFO_TID_DIFFER"]
                    #
                    if Output_Format == 98:  ## Analysis JSON Output
                        if Pkg_Header:
                            JSON_Output["pkgHeader"] = copy.copy(Pkg_Header)
                            if "STRUCTURE_DEF" in JSON_Output["pkgHeader"]:
                                del JSON_Output["pkgHeader"]["STRUCTURE_DEF"]
                        if Pkg_Ext_Header:
                            JSON_Output["pkgExtHeader"] = copy.copy(Pkg_Ext_Header)
                            if "STRUCTURE_DEF" in JSON_Output["pkgExtHeader"]:
                                del JSON_Output["pkgExtHeader"]["STRUCTURE_DEF"]
                        if Pkg_Meta_Data:
                            JSON_Output["pkgMetaData"] = copy.copy(Pkg_Meta_Data)
                            if "STRUCTURE_DEF" in JSON_Output["pkgMetaData"]:
                                del JSON_Output["pkgMetaData"]["STRUCTURE_DEF"]
                        if Pkg_Sfo_Values:
                            JSON_Output["pkgParamSfo"] = copy.copy(Pkg_Sfo_Values)
                            if "STRUCTURE_DEF" in JSON_Output["pkgParamSfo"]:
                                del JSON_Output["paramSfo"]["STRUCTURE_DEF"]
                        if Pkg_Item_Entries:
                            JSON_Output["pkgItemEntries"] = copy.deepcopy(Pkg_Item_Entries)
                            for Item_Entry in JSON_Output["pkgItemEntries"]:
                                if "STRUCTURE_DEF" in Item_Entry:
                                    del Item_Entry["STRUCTURE_DEF"]
                                if "ALIGN" in Item_Entry:
                                    del Item_Entry["ALIGN"]
                                if "IS_FILE_OFS" in Item_Entry:
                                    del Item_Entry["IS_FILE_OFS"]
                        if Pkg_File_Table:
                            JSON_Output["pkgFileTable"] = copy.deepcopy(Pkg_File_Table)
                            for File_Entry in JSON_Output["pkgFileTable"]:
                                if "STRUCTURE_DEF" in File_Entry:
                                    del File_Entry["STRUCTURE_DEF"]
                        if Pbp_Header:
                            JSON_Output["pbpHeader"] = copy.copy(Pbp_Header)
                            if "STRUCTURE_DEF" in JSON_Output["pbpHeader"]:
                                del JSON_Output["pbpHeader"]["STRUCTURE_DEF"]
                        if Pbp_Item_Entries:
                            JSON_Output["pbpItemEntries"] = copy.deepcopy(Pbp_Item_Entries)
                            for Item_Entry in JSON_Output["pbpItemEntries"]:
                                if "STRUCTURE_DEF" in Item_Entry:
                                    del Item_Entry["STRUCTURE_DEF"]
                                if "ALIGN" in Item_Entry:
                                    del Item_Entry["ALIGN"]
                                if "IS_FILE_OFS" in Item_Entry:
                                    del Item_Entry["IS_FILE_OFS"]
                    #
                    print(json.dumps(JSON_Output, ensure_ascii=False, indent=2, default=specialToJSON))
                    del JSON_Output
                elif Output_Format == 2 \
                or Output_Format == 99:  ## Results/Analysis Output
                    if Output_Format == 99:  ## Analysis Output
                        if Pkg_Header:
                            dprintFieldsDict(Pkg_Header, "Pkg_Header[{KEY:14}|{INDEX:2}]", 2, None, print_func=print)
                        if Pkg_Ext_Header:
                            dprintFieldsDict(Pkg_Ext_Header, "Pkg_Ext_Header[{KEY:14}|{INDEX:2}]", 2, None, print_func=print)
                        if Pkg_Meta_Data:
                            for Key in Pkg_Meta_Data:
                                print("Pkg_Meta_Data[{:#04x}]:".format(Key), end="")
                                if "DESC" in Pkg_Meta_Data[Key]:
                                    print(" Desc \"", Pkg_Meta_Data[Key]["DESC"], "\"", sep="", end="")
                                if "OFS" in Pkg_Meta_Data[Key]:
                                    print(" Ofs {:#012x}".format(Pkg_Meta_Data[Key]["OFS"]), end="")
                                if "SIZE" in Pkg_Meta_Data[Key]:
                                    print(" Size {:12}".format(Pkg_Meta_Data[Key]["SIZE"]), end="")
                                if "SHA256" in Pkg_Meta_Data[Key]:
                                    print(" SHA256", convertBytesToHexString(Pkg_Meta_Data[Key]["SHA256"], sep=""), end="")
                                if "VALUE" in Pkg_Meta_Data[Key]:
                                    if isinstance(Pkg_Meta_Data[Key]["VALUE"], bytes) \
                                    or isinstance(Pkg_Meta_Data[Key]["VALUE"], bytearray):
                                        print(" Value", convertBytesToHexString(Pkg_Meta_Data[Key]["VALUE"], sep=""), end="")
                                    else:
                                        print(" Value", Pkg_Meta_Data[Key]["VALUE"], end="")
                                if "UNKNOWN" in Pkg_Meta_Data[Key]:
                                    print(" Unknown", convertBytesToHexString(Pkg_Meta_Data[Key]["UNKNOWN"], sep=""), end="")
                                print()
                        if Pkg_Sfo_Values:
                            dprintFieldsDict(Pkg_Sfo_Values, "Pkg_Sfo_Values[{KEY:20}]", 2, None, print_func=print)
                        if Pkg_Item_Entries:
                            Format_String = "".join(("{:", unicode(len(unicode(len(Pkg_Item_Entries)))), "}"))
                            for Item_Entry in Pkg_Item_Entries:
                                print("".join(("Pkg_Item_Entries[", Format_String, "]: Ofs {:#012x} Size {:12}")).format(Item_Entry["INDEX"], Item_Entry["DATAOFS"], Item_Entry["DATASIZE"]), end="")
                                if "FLAGS" in Item_Entry:
                                    print(" Flags {:#010x}".format(Item_Entry["FLAGS"]), end="")
                                if "KEYINDEX" in Item_Entry:
                                    print(" Key Index", Item_Entry["KEYINDEX"], end="")
                                if "NAME" in Item_Entry:
                                    print(" Name \"", Item_Entry["NAME"], "\"", sep="", end="")
                                print()
                        if Pkg_File_Table:
                            Format_String = "".join(("{:", unicode(len(unicode(Pkg_Header["FILECNT"]))), "}"))
                            for File_Entry in Pkg_File_Table:
                                print("".join(("Pkg_File_Table[", Format_String, "]: ID {:#06x} Ofs {:#012x} Size {:12} {}")).format(File_Entry["INDEX"], File_Entry["FILEID"], File_Entry["DATAOFS"], File_Entry["DATASIZE"], "".join(("Name \"", File_Entry["NAME"], "\"")) if "NAME" in File_Entry else ""))
                            dprintFieldsDict(Pkg_File_Table_Map, "Pkg_File_Table_Map[{KEY:#06x}]", 2, None, print_func=print)
                        if Pbp_Header:
                            dprintFieldsDict(Pbp_Header, "Pbp_Header[{KEY:15}|{INDEX:1}]", 2, None, print_func=print)
                        if Pbp_Item_Entries:
                            Format_String = "".join(("{:", unicode(len(unicode(len(Pbp_Item_Entries)))), "}"))
                            for Item_Entry in Pbp_Item_Entries:
                                print("".join(("Pbp_Item_Entries[", Format_String, "]: Ofs {:#012x} Size {:12}")).format(Item_Entry["INDEX"], Item_Entry["DATAOFS"], Item_Entry["DATASIZE"]), end="")
                                if "FLAGS" in Item_Entry:
                                    print(" Flags {:#010x}".format(Item_Entry["FLAGS"]), end="")
                                if "KEYINDEX" in Item_Entry:
                                    print(" Key Index", Item_Entry["KEYINDEX"], end="")
                                if "NAME" in Item_Entry:
                                    print(" Name \"", Item_Entry["NAME"], "\"", sep="", end="")
                                print()
                    dprintFieldsDict(Results, "Results[{KEY:23}]", 2, None, print_func=print, sep="")
            ## --> Ensure that all messages are output
            sys.stdout.flush()
            sys.stderr.flush()

            ## Extract PKG/PBP
            Extractions_Fields["DATAOFS"] = 0
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Extractions_Fields["DATAOFS"] = Pkg_Header["DATAOFS"]
                Extractions_Fields["AES_CTR"] = Pkg_Header["AES_CTR"]
            #
            ## --> PKG3/PBP
            if Pkg_Magic == CONST_PKG3_MAGIC \
            or Pkg_Magic == CONST_PBP_MAGIC:
                ## RAW decrypted PKG3 package
                if Arguments.raw \
                and Pkg_Magic == CONST_PKG3_MAGIC:
                    Extractions[CONST_EXTRACT_RAW] = {}
                    Extract = Extractions[CONST_EXTRACT_RAW]
                    Extract["KEY"] = CONST_EXTRACT_RAW
                    Extract["FUNCTION"] = "Write"
                    Extract["PROCESS"] = False
                    Extract["DIRS"] = False
                    Extract["SEPARATE_FILES"] = False
                    Extract["BYTES_WRITTEN"] = 0
                    Extract["ALIGNED"] = True
                    Extract["DATATYPE"] = CONST_DATATYPE_AS_IS
                    if Pkg_Magic == CONST_PKG3_MAGIC:
                        Extract["DATATYPE"] = CONST_DATATYPE_DECRYPTED
                    #
                    Extract["ROOT"] = Arguments.raw
                    Extract["ROOT_IS_DIR"] = Raw_Is_Dir
                    #
                    if Extract["ROOT_IS_DIR"]:
                        Extract["TARGET"] = os.path.join(Extract["ROOT"], "".join((Input_Stream.getPkgName(), ".decrypted")))
                    else:
                        Extract["TARGET"] = Extract["ROOT"]
                    if Arguments.quiet <= 1:
                        eprint(">>>>> Target File:", Extract["TARGET"], prefix="[{}] ".format(Extract["KEY"]))
                    #
                    Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                    if Extract["TARGET_CHECK"] == 0:
                        Process_Extractions = Extract["PROCESS"] = True
                        #
                        if Pkg_Magic == CONST_PKG3_MAGIC:
                            if Arguments.quiet <= 0:
                                eprint("{} unencrypted PKG3 header data from offset {:#x} and size {}".format(Extract["FUNCTION"], 0, len(Package["HEAD_BYTES"])), prefix="[{}] ".format(Extract["KEY"]))
                            Extract["BYTES_WRITTEN"] += Extract["STREAM"].write(Package["HEAD_BYTES"])
                            #
                            if Arguments.quiet <= 0:
                                eprint("{} {} PKG3 Items Info from offset {:#x} and size {}".format(Extract["FUNCTION"], Extract["DATATYPE"].lower(), Pkg_Items_Info_Bytes["ALIGN"]["OFS"]+Extractions_Fields["DATAOFS"], Pkg_Items_Info_Bytes["ALIGN"]["SIZE"]), prefix="[{}] ".format(Extract["KEY"]))
                            Extract["BYTES_WRITTEN"] += Extract["STREAM"].write(Pkg_Items_Info_Bytes[Extract["DATATYPE"]])
                    #
                    del Extract

                ## UX0 extraction
                if Arguments.ux0 \
                and Pkg_Magic == CONST_PKG3_MAGIC:
                    if "PKG_EXTRACT_ROOT_UX0" in Results:
                        Extractions[CONST_EXTRACT_UX0] = {}
                        Extract = Extractions[CONST_EXTRACT_UX0]
                        Extract["KEY"] = CONST_EXTRACT_UX0
                        Extract["FUNCTION"] = "Extract"
                        Extract["PROCESS"] = False
                        if "PLATFORM" in Results \
                        and (Results["PLATFORM"] == CONST_PLATFORM.PSX \
                             or Results["PLATFORM"] == CONST_PLATFORM.PSP):
                            Extract["DIRS"] = False
                        else:
                            Extract["DIRS"] = True
                        Extract["SEPARATE_FILES"] = True
                        Extract["BYTES_WRITTEN"] = 0
                        Extract["ALIGNED"] = False
                        Extract["DATATYPE"] = CONST_DATATYPE_AS_IS
                        if Pkg_Magic == CONST_PKG3_MAGIC:
                            Extract["DATATYPE"] = CONST_DATATYPE_DECRYPTED
                        Extract["SCESYS_PACKAGE_CREATED"] = False
                        #
                        Extract["TOPDIR"] = Arguments.ux0
                        #
                        Extract["ROOT"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_ROOT_UX0"])
                        if Arguments.quiet <= 1:
                            eprint(">>>>> Extraction Directory:", Extract["ROOT"], prefix="[{}] ".format(Extract["KEY"]))
                        #
                        Extract["PROCESS"] = True
                        #
                        if createDirectory(Extract["ROOT"], "package extraction", Extract["KEY"], True, Arguments.quiet, max(0, Debug_Level)) != 0:
                            Extract["PROCESS"] = False
                        #
                        if "PKG_EXTRACT_ISOR_UX0" in Results:
                            Extract["ROOT_ISO"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_ISOR_UX0"])
                            Extract["NAME_ISO"] = Results["PKG_EXTRACT_ISO_NAME"]
                            #
                            if createDirectory(Extract["ROOT_ISO"], "package iso extraction", Extract["KEY"], True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                Extract["PROCESS"] = False
                        #
                        if Extract["PROCESS"]:
                            Process_Extractions = True
                        #
                        del Extract
                    else:
                        eprint("[{}] Extraction not supported for package type".format(CONST_EXTRACT_UX0), end=" ")
                        if "PLATFORM" in Results:
                            eprint(Results["PLATFORM"], end=" ", prefix=None)
                        if "PKG_TYPE" in Results:
                            eprint(Results["PKG_TYPE"], end=" ", prefix=None)
                        if "PKG_SUB_TYPE" in Results:
                            eprint(Results["PKG_SUB_TYPE"], end=" ", prefix=None)
                        eprint(prefix=None)

                ## CONTENT extraction
                if Arguments.content:
                    if "PKG_EXTRACT_ROOT_CONT" in Results:
                        Extractions[CONST_EXTRACT_CONTENT] = {}
                        Extract = Extractions[CONST_EXTRACT_CONTENT]
                        Extract["KEY"] = CONST_EXTRACT_CONTENT
                        Extract["FUNCTION"] = "Extract"
                        Extract["PROCESS"] = False
                        Extract["DIRS"] = True
                        Extract["SEPARATE_FILES"] = True
                        Extract["BYTES_WRITTEN"] = 0
                        Extract["ALIGNED"] = False
                        Extract["DATATYPE"] = CONST_DATATYPE_AS_IS
                        if Pkg_Magic == CONST_PKG3_MAGIC:
                            Extract["DATATYPE"] = CONST_DATATYPE_DECRYPTED
                        Extract["SCESYS_PACKAGE_CREATED"] = False
                        #
                        Extract["TOPDIR"] = Arguments.content
                        #
                        Extract["ROOT"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_ROOT_CONT"])
                        if Arguments.quiet <= 1:
                            eprint(">>>>> Extraction Directory:", Extract["ROOT"], prefix="[{}] ".format(Extract["KEY"]))
                        #
                        if createDirectory(Extract["ROOT"], "package extraction", Extract["KEY"], True, Arguments.quiet, max(0, Debug_Level)) == 0:
                            Process_Extractions = Extract["PROCESS"] = True
                        #
                        del Extract
                    else:
                        eprint("[{}] Extraction not supported for package type".format(CONST_EXTRACT_CONTENT), end=" ")
                        if "PLATFORM" in Results:
                            eprint(Results["PLATFORM"], end=" ", prefix=None)
                        if "PKG_TYPE" in Results:
                            eprint(Results["PKG_TYPE"], end=" ", prefix=None)
                        if "PKG_SUB_TYPE" in Results:
                            eprint(Results["PKG_SUB_TYPE"], end=" ", prefix=None)
                        eprint(prefix=None)

                ## Extract PKG3 items
                if not Pkg_Item_Entries is None \
                and Process_Extractions:
                    Item_Entries_Sorted = sorted(Pkg_Item_Entries, key=lambda x: (x["IS_FILE_OFS"], x["INDEX"]))
                    for Item_Entry in Item_Entries_Sorted:
                        ## Initialize per-item variables
                        Use_Input_Stream = Input_Stream
                        Item_Data = None
                        Use_Extractions = None
                        #
                        Item_Flags = None
                        if "FLAGS" in Item_Entry:
                            Item_Flags = Item_Entry["FLAGS"] & 0xff
                        Item_Name_Parts = Item_Entry["NAME"].split("/")
                        #
                        if Item_Entry["IS_FILE_OFS"] == -1:
                            ## 0x04: Directory
                            ## 0x12: Directory
                            for Key in Extractions:
                                Extract = Extractions[Key]
                                #
                                if Extract["SEPARATE_FILES"] \
                                and "STREAM" in Extract:
                                    del Extract["STREAM"]
                                if "ITEM_EXTRACT_PATH" in Extract:
                                    del Extract["ITEM_EXTRACT_PATH"]
                                #
                                if not Extract["DIRS"] \
                                or not Extract["PROCESS"]:
                                    continue  ## next extract

                                ## Process item name
                                Name_Parts = copy.copy(Item_Name_Parts)
                                #
                                if (Key == CONST_EXTRACT_UX0 \
                                    or Key == CONST_EXTRACT_CONTENT) \
                                and "PLATFORM" in Results:  ## UX0/CONTENT extraction
                                    ## Process name parts depending on platform
                                    ## --> PS3 extraction
                                    if Results["PLATFORM"] == CONST_PLATFORM.PS3:
                                        pass  ## as-is
                                    ## --> PSX extraction
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSX:
                                        if Key == CONST_EXTRACT_UX0:
                                            ## UX0 PSX extraction = no dirs (safety check only)
                                            Name_Parts = None
                                    ## --> PSP extraction
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSP:
                                        if Key == CONST_EXTRACT_UX0:
                                            ## UX0 PSP extraction = no dirs (safety check only)
                                            Name_Parts = None
                                    ## --> PSV packages
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSV:
                                        ## Check if special dir "sce_sys/package" is created
                                        if not Extract["SCESYS_PACKAGE_CREATED"] \
                                        and len(Name_Parts) >= 2 \
                                        and Name_Parts[0] == "sce_sys" \
                                        and Name_Parts[1] == "package" :
                                            Extract["SCESYS_PACKAGE_CREATED"] = True
                                    ## --> PSM packages
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                        if Key == CONST_EXTRACT_UX0:
                                            ## UX0 PSM extraction: Rename base directory
                                            if len(Name_Parts) > 0 \
                                            and Name_Parts[0] == "contents":
                                                Name_Parts[0] = "RO"

                                ## Build and check item extract path
                                if Name_Parts:
                                    Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                    Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                del Name_Parts
                                #
                                if not "ITEM_EXTRACT_PATH" in Extract \
                                or not Extract["ITEM_EXTRACT_PATH"]:
                                    if "ITEM_EXTRACT_PATH" in Extract:
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next extract

                                ## Create directory
                                Extract["TARGET"] = os.path.join(Extract["ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                #
                                if createDirectory(Extract, "#{} items".format(Item_Entry["INDEX"]), Key, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                    eprint("[{}] ABORT extraction".format(Extract["KEY"]))
                                    Extract["PROCESS"] = False
                                del Extract["ITEM_EXTRACT_PATH"]
                            ## Clean-up
                            del Extract
                            del Key
                            del Item_Name_Parts
                            del Item_Flags
                            #
                            continue  ## next extract
                        else:  ## should all be files
                            ## taken from pkg_dec 1.3.2 from Weaknespase
                            ## 0x00:
                            ## 0x01:
                            ## 0x03: all regular data files have this type
                            ## 0x0E: user-mode executables have this type (eboot.bin, sce_modules contents)
                            ## 0x0F:
                            ## 0x10: keystone have this type
                            ## 0x11: PFS files have this type (files.db, unicv.db, pflist)
                            ## 0x13: temp.bin have this type
                            ## 0x14:
                            ## 0x15: clearsign have this type
                            ## 0x16: right.suprx have this type
                            ## 0x18: digs.bin have this type, unpack encrypted
                            for Key in Extractions:
                                Extract = Extractions[Key]
                                #
                                if Extract["SEPARATE_FILES"] \
                                and "STREAM" in Extract:
                                    del Extract["STREAM"]
                                if "ITEM_EXTRACT_PATH" in Extract:
                                    del Extract["ITEM_EXTRACT_PATH"]
                                #
                                if not Extract["PROCESS"]:
                                    continue  ## next extract

                                ## Process item name
                                Name_Parts = copy.copy(Item_Name_Parts)
                                #
                                if Key == CONST_EXTRACT_UX0 \
                                or Key == CONST_EXTRACT_CONTENT:  ## UX0/CONTENT extraction
                                    Extract["ITEM_DATATYPE"] = Extract["DATATYPE"]

                                    ## Process name parts depending on platform
                                    if "PLATFORM" in Results:
                                        ## --> PS3 extraction
                                        if Results["PLATFORM"] == CONST_PLATFORM.PS3:
                                            pass  ## as-is
                                        ## --> PSX extraction
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSX:
                                            if Key == CONST_EXTRACT_UX0:
                                                ## UX0 PSX extraction
                                                if len(Name_Parts) == 3 \
                                                and Name_Parts[0] == "USRDIR" \
                                                and Name_Parts[1] == "CONTENT" \
                                                and (Name_Parts[2] == "DOCUMENT.DAT" \
                                                     or Name_Parts[2] == "EBOOT.PBP"):
                                                    del Name_Parts[1]
                                                    del Name_Parts[0]
                                                else:
                                                    Name_Parts = None  ## skip file
                                        ## --> PSP extraction
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSP:
                                            if Key == CONST_EXTRACT_UX0:
                                                ## UX0 PSP extraction
                                                if len(Name_Parts) == 3 \
                                                and Name_Parts[0] == "USRDIR" \
                                                and Name_Parts[1] == "CONTENT" \
                                                and (Name_Parts[2] == "EBOOT.PBP" \
                                                     or Name_Parts[2] == "PSP-KEY.EDAT" \
                                                     or Name_Parts[2] == "CONTENT.DAT"):
                                                    if Name_Parts[2] == "EBOOT.PBP":
                                                        ## https://www.psdevwiki.com/ps3/Eboot.PBP
                                                        ## TODO:
                                                        ## a) pkg decrypt
                                                        ## b) EBOOT header
                                                        ## c) psp decrypt & uncompress .psar
                                                        ## - unpack USRDIR/CONTENT/EBOOT.PBP as iso/cso to pspemu/ISO/<title> [%.9s<id>].%s
                                                        #os.path.join(Extract["ROOT_ISO"], Extract["NAME_ISO"])
                                                        Name_Parts = None  ## TODO: replace
                                                    elif Name_Parts[2] == "PSP-KEY.EDAT":
                                                        ## TODO:
                                                        ## - unpack USRDIR/CONTENT/PSP-KEY.EDAT to pspemu/PSP/GAME/%.9s<id>/
                                                        Name_Parts = None  ## TODO: replace
                                                    elif Name_Parts[2] == "CONTENT.DAT":
                                                        del Name_Parts[1]
                                                        del Name_Parts[0]
                                                else:
                                                    Name_Parts = None  ## skip file
                                        ## --> PSV packages
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSV:
                                            ## Special case: PSV encrypted sce_sys/package/digs.bin as body.bin
                                            if len(Name_Parts) == 3 \
                                            and Name_Parts[0] == "sce_sys" \
                                            and Name_Parts[1] == "package" \
                                            and Name_Parts[2] == "digs.bin":  ## Item_Flags == 0x18
                                                Extract["ITEM_DATATYPE"] = CONST_DATATYPE_AS_IS
                                                Name_Parts[2] = "body.bin"
                                        ## --> PSM packages
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                            if Key == CONST_EXTRACT_UX0:  ## UX0-only PSM extraction
                                                ## UX0 extraction: Rename base directory
                                                if len(Name_Parts) > 0 \
                                                and Name_Parts[0] == "contents":
                                                    Name_Parts[0] = "RO"

                                ## Build and check item extract path
                                if Name_Parts:
                                    Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                    Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                del Name_Parts
                                #
                                ## Special case: always write for RAW decrypted PKG3 package
                                if Key == CONST_EXTRACT_RAW:
                                    if "STREAM" in Extract \
                                    and Item_Entry["DATASIZE"] > 0:
                                        pass  ## write
                                    else:
                                        continue  ## next extract
                                elif not "ITEM_EXTRACT_PATH" in Extract \
                                or not Extract["ITEM_EXTRACT_PATH"]:
                                    if "ITEM_EXTRACT_PATH" in Extract:
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next extract

                                ## Display item extract path
                                if Arguments.quiet <= 0:
                                    if Extract["ITEM_NAME"].strip():
                                        Item_Name = "#{} \"{}\"".format(Item_Entry["INDEX"], Extract["ITEM_NAME"])
                                    else:
                                        Item_Name = "#{} unnamed item".format(Item_Entry["INDEX"], Item_Entry["INDEX"])
                                    if Extract["ALIGNED"]:
                                        Values = ["aligned ", Extractions_Fields["DATAOFS"]+Item_Entry["ALIGN"]["OFS"], Item_Entry["ALIGN"]["SIZE"]]
                                    else:
                                        Values = ["", Extractions_Fields["DATAOFS"]+Item_Entry["DATAOFS"], Item_Entry["DATASIZE"]]
                                    eprint("{} {} {} from {}offset {:#x} and size {}".format(Extract["FUNCTION"], Item_Name, Extract["ITEM_DATATYPE"].lower(), *Values), prefix="[{}] ".format(Extract["KEY"]))
                                    del Values
                                    del Item_Name

                                if Key != CONST_EXTRACT_RAW:
                                    ## Build and check target path
                                    Extract["TARGET"] = os.path.join(Extract["ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                    Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                                    if Extract["TARGET_CHECK"] != 0:
                                        if Extract["TARGET_CHECK"] < 0:
                                            eprint("[{}] BROKEN extraction".format(Extract["KEY"]))
                                        del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next extract
                                #
                                if "STREAM" in Extract:
                                    Use_Extractions = Extractions
                            ## Clean-up
                            del Extract
                            del Key
                            del Item_Name_Parts
                            del Item_Flags
                        #
                        if not Use_Extractions:
                            continue  ## next item

                        ## Process item data
                        if Item_Entry["DATASIZE"] > 0:
                            ## --> Special cases: already read data
                            if Sfo_Item_Data \
                            and "NAME" in Item_Entry \
                            and Pkg_Header \
                            and Item_Entry["NAME"] == Pkg_Header["PARAM.SFO"]:
                                Use_Input_Stream = None
                                Item_Data = Sfo_Item_Data
                            #
                            processPkg3Item(Extractions_Fields, Item_Entry, Use_Input_Stream, Item_Data, Use_Extractions, max(0, Debug_Level))

                        ## Close streams
                        for Key in Extractions:
                            Extract = Extractions[Key]
                            #
                            if Extract["SEPARATE_FILES"] \
                            and "STREAM" in Extract:
                                Extract["STREAM"].close()
                                del Extract["STREAM"]
                            if "ITEM_EXTRACT_PATH" in Extract:
                                del Extract["ITEM_EXTRACT_PATH"]
                        del Extract
                        del Key
                    #
                    del Use_Extractions
                    del Item_Data
                    del Use_Input_Stream
                    #
                    del Item_Entry
                    del Item_Entries_Sorted

                ## Special cases: additional items, clean-up, etc.
                if Process_Extractions:
                    for Key in Extractions:
                        Extract = Extractions[Key]
                        #
                        if Extract["SEPARATE_FILES"] \
                        and "STREAM" in Extract:
                            del Extract["STREAM"]
                        if "ITEM_EXTRACT_PATH" in Extract:
                            del Extract["ITEM_EXTRACT_PATH"]
                        #
                        if not Extract["PROCESS"]:
                            continue  ## next extract

                        if (Key == CONST_EXTRACT_UX0 \
                            or Key == CONST_EXTRACT_CONTENT) \
                        and "PLATFORM" in Results:  ## UX0/CONTENT extraction
                            ## --> PSV packages
                            if Results["PLATFORM"] == CONST_PLATFORM.PSV:
                                ## Dirs
                                Dirs = []
                                if not Extract["SCESYS_PACKAGE_CREATED"]:
                                    Dirs.append(["sce_sys", "package"])
                                #
                                Name_Parts = None
                                for Name_Parts in Dirs:
                                    ## Build and check item extract path
                                    if Name_Parts:
                                        Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                        Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                    #
                                    if not "ITEM_EXTRACT_PATH" in Extract \
                                    or not Extract["ITEM_EXTRACT_PATH"]:
                                        if "ITEM_EXTRACT_PATH" in Extract:
                                            del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next dir

                                    ## Create directory
                                    if createDirectory(Extract, "items", Key, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                        eprint("[{}] ABORT extraction".format(Extract["KEY"]))
                                        Extract["PROCESS"] = False
                                    del Extract["ITEM_EXTRACT_PATH"]
                                #
                                del Name_Parts
                                del Dirs
                                #
                                if not Extract["PROCESS"]:
                                    continue  ## next extract

                                ## Files
                                File_Number = 0
                                for Name_Parts in [["sce_sys", "package", "head.bin"], ["sce_sys", "package", "tail.bin"], ["sce_sys", "package", "stat.bin"], ["sce_sys", "package", "work.bin"]]:
                                    File_Number += 1

                                    ## Build and check item extract path
                                    if Name_Parts:
                                        Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                        Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                    #
                                    if not "ITEM_EXTRACT_PATH" in Extract \
                                    or not Extract["ITEM_EXTRACT_PATH"]:
                                        if not "ITEM_EXTRACT_PATH" in Extract:
                                            del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next file

                                    ## Display item extract path
                                    if Arguments.quiet <= 0:
                                        Values = None
                                        if File_Number == 1:  ## head.bin
                                            Values = [Extract["FUNCTION"], "\"{}\"".format(Extract["ITEM_NAME"]), "unencrypted head + encrypted items info", "", "offset {:#x}".format(0), len(Package["HEAD_BYTES"])+len(Pkg_Items_Info_Bytes[CONST_DATATYPE_AS_IS])]
                                        elif File_Number == 2:  ## tail.bin
                                            if not "TAIL_BYTES" in Package:
                                                ## Data not available
                                                eprint("MISSING tail data, maybe this is only the first file of a multi-part package or it is a head.bin", prefix="[{}] ".format(Extract["KEY"]))
                                                del Extract["ITEM_EXTRACT_PATH"]
                                                continue  ## next file
                                            else:
                                                Values = [Extract["FUNCTION"], "\"{}\"".format(Extract["ITEM_NAME"]), "unencrypted tail", "", "offset {:#x}".format(Extractions_Fields["DATAOFS"]+Pkg_Header["DATASIZE"]), len(Package["TAIL_BYTES"])]
                                        elif File_Number == 3:  ## stat.bin
                                            Values = ["Write", "\"{}\"".format(Extract["ITEM_NAME"]), "fake data", "", "zeroes", 0x300]
                                        elif File_Number == 4:  ## work.bin
                                            if Results["PKG_TYPE"] == CONST_PKG_TYPE.PATCH:
                                                ## Patches do not not need a license file
                                                del Extract["ITEM_EXTRACT_PATH"]
                                                continue  ## next file
                                            elif not Results["PKG_CONTENT_ID"] in Rifs:
                                                eprint("MISSING zrif license for package content id", Results["PKG_CONTENT_ID"], prefix="[{}] ".format(Extract["KEY"]))
                                                del Extract["ITEM_EXTRACT_PATH"]
                                                continue  ## next file
                                            #
                                            Values = ["Write", "\"{}\"".format(Extract["ITEM_NAME"]), "license", "", "zrif", len(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])]
                                        eprint("{} {} {} from {}{} and size {}".format(*Values), prefix="[{}] ".format(Extract["KEY"]))
                                        del Values

                                    ## Build and check target path
                                    Extract["TARGET"] = os.path.join(Extract["ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                    Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                                    if Extract["TARGET_CHECK"] != 0:
                                        if Extract["TARGET_CHECK"] < 0:
                                            eprint("[{}] BROKEN extraction".format(Extract["KEY"]))
                                        del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next file

                                    ## Write data
                                    if File_Number == 1:  ## head.bin
                                        Extract["STREAM"].write(Package["HEAD_BYTES"])
                                        Extract["STREAM"].write(Pkg_Items_Info_Bytes[CONST_DATATYPE_AS_IS])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    elif File_Number == 2:  ## tail.bin
                                        Extract["STREAM"].write(Package["TAIL_BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    elif File_Number == 3:  ## stat.bin
                                        Extract["STREAM"].write(bytearray(0x300))
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    elif File_Number == 4:  ## work.bin
                                        Extract["STREAM"].write(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    del Extract["ITEM_EXTRACT_PATH"]
                                #
                                del Name_Parts
                                del File_Number
                            ## --> PSM packages
                            elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                if Key == CONST_EXTRACT_UX0:  ## UX0-only PSM extraction
                                    ## Dirs
                                    Dirs = [["RW", "Documents"], ["RW", "Temp"], ["RW", "System"], ["RO", "License"]]
                                    #
                                    for Name_Parts in Dirs:
                                        ## Build and check item extract path
                                        if Name_Parts:
                                            Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                            Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                        #
                                        if not "ITEM_EXTRACT_PATH" in Extract \
                                        or not Extract["ITEM_EXTRACT_PATH"]:
                                            if "ITEM_EXTRACT_PATH" in Extract:
                                                del Extract["ITEM_EXTRACT_PATH"]
                                            continue  ## next dir

                                        ## Create directory
                                        if createDirectory(Extract, "PSM RW", Key, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                            eprint("[{}] ABORT extraction".format(Extract["KEY"]))
                                            Extract["PROCESS"] = False
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    #
                                    del Name_Parts
                                    del Dirs
                                    #
                                    if not Extract["PROCESS"]:
                                        continue  ## next extract

                                    ## Files
                                    File_Number = 0
                                    for Name_Parts in [["RW", "System", "content_id"], ["RW", "System", "pm.dat"], ["RO", "License", "FAKE.rif"]]:
                                        File_Number += 1

                                        ## Build and check item extract path
                                        if Name_Parts:
                                            Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                            Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                        #
                                        if not "ITEM_EXTRACT_PATH" in Extract \
                                        or not Extract["ITEM_EXTRACT_PATH"]:
                                            if not "ITEM_EXTRACT_PATH" in Extract:
                                                del Extract["ITEM_EXTRACT_PATH"]
                                            continue  ## next file

                                        ## Display item extract path
                                        if Arguments.quiet <= 0:
                                            Values = None
                                            if File_Number == 1:  ## content_id
                                                Values = [Extract["FUNCTION"], "\"{}\"".format(Extract["ITEM_NAME"]), "content id", "", "offset {:#x}".format(CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]), CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["SIZE"]]
                                            elif File_Number == 2:  ## pm.dat
                                                Values = ["Write", "\"{}\"".format(Extract["ITEM_NAME"]), "fake data", "", "zeroes", 0x10000]
                                            elif File_Number == 3:  ## FAKE.rif
                                                if not Results["PKG_CONTENT_ID"] in Rifs:
                                                    eprint("MISSING zrif license for package content id", Results["PKG_CONTENT_ID"], prefix="[{}] ".format(Extract["KEY"]))
                                                    del Extract["ITEM_EXTRACT_PATH"]
                                                    continue  ## next file
                                                #
                                                Values = ["Write", "\"{}\"".format(Extract["ITEM_NAME"]), "license", "", "zrif", len(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])]
                                            eprint("{} {} {} from {}{} and size {}".format(*Values), prefix="[{}] ".format(Extract["KEY"]))
                                            del Values

                                        ## Build and check target path
                                        Extract["TARGET"] = os.path.join(Extract["ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                        Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                                        if Extract["TARGET_CHECK"] != 0:
                                            if Extract["TARGET_CHECK"] < 0:
                                                eprint("[{}] BROKEN extraction".format(Extract["KEY"]))
                                            del Extract["ITEM_EXTRACT_PATH"]
                                            continue  ## next file

                                        ## Write data
                                        if File_Number == 1:  ## content_id
                                            Extract["STREAM"].write(Package["HEAD_BYTES"][CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]:CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]+CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["SIZE"]])
                                            Extract["STREAM"].close()
                                            del Extract["STREAM"]
                                        elif File_Number == 2:  ## pm.dat
                                            Extract["STREAM"].write(bytearray(0x10000))
                                            Extract["STREAM"].close()
                                            del Extract["STREAM"]
                                        elif File_Number == 3:  ## FAKE.rif
                                            Extract["STREAM"].write(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])
                                            Extract["STREAM"].close()
                                            del Extract["STREAM"]
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    #
                                    del Name_Parts
                                    del File_Number
                        #
                        elif Key == CONST_EXTRACT_RAW:
                            ## Write PKG3 unencrypted tail data
                            if Arguments.quiet <= 0:
                                eprint("{} unencrypted PKG3 tail data from offset {:#x} and size {}".format(Extract["FUNCTION"], Extractions_Fields["DATAOFS"]+Pkg_Header["DATASIZE"], Results["PKG_TAIL_SIZE"]), prefix="[{}] ".format(Extract["KEY"]))
                            if not "TAIL_BYTES" in Package:
                                ## Data not available
                                eprint("MISSING tail data, maybe this is only the first file of a multi-part package or it is a head.bin", prefix="[{}] ".format(Extract["KEY"]))
                                del Extract["ITEM_EXTRACT_PATH"]
                                continue  ## next file
                            else:
                                Extract["BYTES_WRITTEN"] += Extract["STREAM"].write(Package["TAIL_BYTES"])
                            Extract["STREAM"].close()
                            del Extract["STREAM"]

                            ## Check written package size
                            if ("PKG_TOTAL_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["PKG_TOTAL_SIZE"]) \
                            or ("FILE_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["FILE_SIZE"]):
                                eprint("Written size {} of unencrypted/decrypted data from".format(Extract["BYTES_WRITTEN"]), Input_Stream.getSource())
                                if "PKG_TOTAL_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["PKG_TOTAL_SIZE"]:
                                    eprint("mismatches package total size of", Results["PKG_TOTAL_SIZE"])
                                if "FILE_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["FILE_SIZE"]:
                                    eprint("mismatches file size of", Results["FILE_SIZE"])
                                eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
                    ## Clean-up
                    del Extract
                    del Key
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                pass  ## TODO: PS4 extraction not supported yet

            ## Close input stream
            Input_Stream.close(Debug_Level)

            ## Output additional results
            for Output_Format in Arguments.format:
                if Output_Format == 50:  ## Additional debugging Output
                    if Extractions:
                        dprintFieldsDict(Extractions, "extractions[{KEY:9}]", 2, None, print_func=print, sep="")
            ## --> Ensure that all messages are output
            sys.stdout.flush()
            sys.stderr.flush()

            ## Clean-Up
            del Package
            del Sfo_Item_Data
            del Sfo_Bytes
            del Pkg_Items_Info_Bytes
    except SystemExit:
        raise  ## re-raise/throw up (let Python handle it)
    except:
        print_exc_plus()
