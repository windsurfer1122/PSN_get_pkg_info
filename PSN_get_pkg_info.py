#!/usr/bin/env python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PSN_get_pky_info.py (c) 2018-2020 by "windsurfer1122"
### Extract package information from header and PARAM.SFO of PS3/PSX/PSP/PSV/PSM and PS4 packages.
### Use at your own risk!
###
### For options execute: PSN_get_pkg_info.py -h and read the README.md
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
## see https://www.python.org/dev/peps/pep-0440/
__version__ = "2020.01.00.beta6"
__author__ = "https://github.com/windsurfer1122/PSN_get_pkg_info"
__license__ = "GPL"
__copyright__ = "Copyright 2018-2020, windsurfer1122"


## Imports
import sys
import struct
import io
import collections
import locale
import os
import argparse
import re
import traceback
import json
import random
import copy
import zlib
import base64
import xml.etree.ElementTree
import math
import datetime

## pip install requests
## https://pypi.org/project/requests/
import requests

## pip install aenum
## https://pypi.org/project/aenum/
import aenum

## pip install fastxor
## https://pypi.org/project/fastxor/
import fastxor

## pip install pycryptodomex
## https://pypi.org/project/pycryptodomex/
## https://www.pycryptodome.org/en/latest/src/installation.html
import Cryptodome.Cipher.AES
import Cryptodome.Util.Counter
import Cryptodome.Hash

## pip install packaging
## https://pypi.org/project/packaging/
import packaging.version

## pip install ecdsa
## https://pypi.org/project/ecdsa/
import ecdsa.ecdsa
import ecdsa.ellipticcurve


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

### pycryptodomex <3.7.2 CMAC error workaround
### https://github.com/Legrandin/pycryptodome/issues/238
if packaging.version.parse(Cryptodome.__version__) >= packaging.version.parse("3.7.2"):
    dprint("pycryptodomex", Cryptodome.__version__, "(>= 3.7.2) is good")
    ### https://www.pycryptodome.org/en/latest/src/hash/cmac.html
    def newCMAC(key):
        return Cryptodome.Hash.CMAC.new(key, ciphermod=Cryptodome.Cipher.AES)
    def getCMACDigest(self):
        return self.digest()
else:
    dprint("pycryptodomex", Cryptodome.__version__, "(< 3.7.2) has an error in CMAC copying, therefore switching to module cryptography for CMAC hashing")
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.cmac
    import cryptography.hazmat.primitives.ciphers.algorithms
    ### https://cryptography.io/en/latest/hazmat/primitives/mac/cmac/
    def newCMAC(key):
        return cryptography.hazmat.primitives.cmac.CMAC(cryptography.hazmat.primitives.ciphers.algorithms.AES(key), backend=cryptography.hazmat.backends.default_backend())
    def getCMACDigest(self):
        return self.finalize()

## Python 2/3 shortcoming: older zlib modules do not support compression dictionaries
Zrif_Support = False
try:
    Decompress_Object = zlib.decompressobj(wbits=8, zdict=bytes(2^8))
    del Decompress_Object
    Zrif_Support = True
except TypeError:
    pass


def convertBytesToHexString(data, format_string="", sep=" "):
    if isinstance(data, int):
        data = struct.pack(format_string, data)
    ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
    if isinstance(data, str):
        data = bytearray(data)
    #
    return sep.join(["%02x" % b for b in data])


## Generic Definitions
PYTHON_VERSION = ".".join(map(unicode, sys.version_info[0:3]))
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
CONST_AES_EMPTY_IV = bytes(Cryptodome.Cipher.AES.block_size)
#
CONST_REGEX_HEX_DIGITS = re.compile("^[0-9a-fA-F]+$", flags=re.UNICODE|re.IGNORECASE)
#
CONST_READ_SIZE = random.randint(50,100) * 0x100000  ## Read in 50-100 MiB chunks to reduce memory usage and swapping
CONST_READ_AHEAD_SIZE = 128 * 0x400 ## Read first 128 KiB to reduce read requests (fits header of known PS3/PSX/PSP/PSV/PSM packages; Kib/Mib = 0x400/0x100000; biggest header + Items Info found was 2759936 = 0x2a1d00 = ~2.7 MiB)
#
CONST_USER_AGENT_PS3 = "Mozilla/5.0 (PLAYSTATION 3; 4.85)"
#CONST_USER_AGENT_PSP = ""
CONST_USER_AGENT_PSV = " libhttp/3.73 (PS Vita)"
CONST_USER_AGENT_PS4 = "Download/1.00 libhttp/7.02 (PlayStation 4)"
#
CONST_EXTRACT_RAW = "RAW"
CONST_EXTRACT_UX0 = "UX0"
CONST_EXTRACT_CONTENT = "CNT"
#
CONST_DATATYPE_AS_IS = "AS-IS"
CONST_DATATYPE_DECRYPTED = "DECRYPTED"
CONST_DATATYPE_UNENCRYPTED = "UNENCRYPTED"
#
CONST_ZRIF_COMPRESSION_DICTIONARY = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003030303039000000000000000000000030303030363030303037303030303800303030303330303030343030303035305f30302d414444434f4e5430303030322d5043534730303030303030303030312d504353453030302d504353463030302d504353433030302d504353443030302d504353413030302d504353423030300001000100010002efcdab8967452301")

## Generic PKG Definitions
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

    __ordered__ = "GAME DLC PATCH THEME AVATAR LIVEAREA"
    GAME = "Game"
    DLC = "DLC"
    PATCH = "Update"
    THEME = "Theme"
    AVATAR = "Avatar"
    LIVEAREA = "Livearea"
## --> Package Sub Types
class CONST_PKG_SUB_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = "PSP_PC_ENGINE PSP_GO PSP_MINI PSP_NEOGEO PS2_CLASSIC PSP_REMASTER"
    PSP_PC_ENGINE = "PSP PC Engine"
    PSP_GO = "PSP Go"
    PSP_MINI = "PSP Mini"
    PSP_NEOGEO = "PSP NeoGeo"
    PS2_CLASSIC = "PS2 Classic"
    PSP_REMASTER = "PSP Remaster"

##
## PKG3 Definitions
##
#
CONST_PKG3_XML_ROOT = "hfs_manifest"
## --> Header
CONST_PKG3_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PKG3_MAGIC = bytes.fromhex("7f504b47")  ## "\x7fPKG"
CONST_PKG3_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
    ( "REV",          { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "MDOFS",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Data Offset", }, ),
    ( "MDCNT",        { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Data Count", }, ),
    ( "HDRSIZE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Header [Additional] Size incl. PS3 0x40 Digest [and Extensions]", }, ),
    ( "ITEMCNT",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Item Count", }, ),
    ( "TOTALSIZE",    { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Total Size", }, ),
    ( "DATAOFS",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Offset", }, ),
    ( "DATASIZE",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "CONV": 0x0204, "DEBUG": 1, "DESC": "Content ID", "SEP": "", }, ),
    ( "DIGEST",       { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Digest", "SEP": "", }, ),
    ( "DATARIV",      { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Data RIV", "SEP": "", }, ),
    #
    ( "KEYINDEX",     { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Key Index for Decryption of Item Entries Table", }, ),
    ( "AES_CTR",      { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Retail AES CTR", }, ),
    ( "XOR_CTR",      { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Debug XOR CTR", }, ),
    ( "PARAM.SFO",    { "VIRTUAL": -1, "DEBUG": 1, "DESC": "PARAM.SFO Item Name", }, ),
    ( "MDSIZE",       { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Meta Data Size", }, ),
    ( "DEBUG_PKG",    { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Debug Package", }, ),
])
## --> PS3 0x40 Digest
CONST_PKG3_PS3_DIGEST_FIELDS = collections.OrderedDict([ \
    ( "CMACHASH",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "CMAC Hash", }, ),
    ( "NPDRMSIG",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 40, "DEBUG": 1, "DESC": "NpDrm Signature", }, ),
    ( "SHA1HASH",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 8, "DEBUG": 1, "DESC": "SHA1 Hash", }, ),
])
## --> Extended Header
CONST_PKG3_EXT_MAGIC = bytes.fromhex("7f657874")  ## "\x7fext"
CONST_PKG3_EXT_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
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
## --> Content PKG3 Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_CONTENT_KEYS = {
    0: { "KEY": "Lntx18nJoU6jIh8YiCi4+A==", "DESC": "PS3", },
    1: { "KEY": "B/LGgpC1DSwzgY1wm2DmKw==", "DESC": "PSX/PSP", },
    2: { "KEY": "4xpwyc4d1yvzwGIpY/Lsyw==", "DESC": "PSV",          "DERIVE": True, },
    3: { "KEY": "QjrKOivVZJ+Whqutb9iAHw==", "DESC": "PSV Livearea", "DERIVE": True, },
    4: { "KEY": "rwf9WWUlJ7rxM4lmixfZ6g==", "DESC": "PSM",          "DERIVE": True, },
}
for Key, Values in CONST_PKG3_CONTENT_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("PKG3 Content Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("PKG3 Content Key #{}:".format(Key), Value)
        del Value
del Values
del Key
## --> PKG3 Update Keys
CONST_PKG3_UPDATE_KEYS = {
    2: { "KEY": "5eJ4qh7jQIKgiCecg/m7yAaCHFLyq10rSr2ZVFA1URQ=", "DESC": "PSV", },
    3: { "KEY": "2Nvtdm6rzWjUfdvtnTyoJYN96Kp4m3/5LZoVlPzY6sQ=", "DESC": "PSV Livearea", },
}
for Key, Values in CONST_PKG3_UPDATE_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("PKG3 Update Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("PKG3 Update Key #{}:".format(Key), Value)
        del Value
del Values
del Key
## --> RAP Keys
CONST_RAP_PBOX = ( 0x0c, 0x03, 0x06, 0x04, 0x01, 0x0b, 0x0f, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0a, 0x0e, 0x0d, 0x09 )
CONST_RAP_KEYS = {
    0: { "KEY": "hp93RcE/2JDM8pGI48w+3w==", "DESC": "RAP_KEY", },
    1: { "KEY": "qT4f1nxVoym3X92mKpXHpQ==", "DESC": "RAP_E1", },
    2: { "KEY": "Z9RdoyltAGpOfFN79VOMdA==", "DESC": "RAP_E2", },
}
for Key, Values in CONST_RAP_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("RAP Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("RAP Key #{}:".format(Key), Value)
        del Value
del Values
del Key
## --> RIF
## https://github.com/weaknespase/PkgDecrypt/blob/master/rif.h
## https://github.com/TheOfficialFloW/NoNpDrm/blob/master/main.c
## https://github.com/frangarcj/NoPsmDrm/blob/master/src/main.c
CONST_RIF_FAKE_AID = 0xefcdab8967452301  ## LE = 0x0123456789abcdef
CONST_RIF_TYPE_OFFSET = 0x04
#
CONST_PS3_RIF_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PS3_RIF_FIELDS = collections.OrderedDict([ \
    ## Size has to be taken into account to determine RIF version
    ( "VERSION",      { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version", }, ),
    ( "VERSION_FLAG", { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version Flag", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "FLAGS",        { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Flags", }, ),
    #
    ( "AID",          { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Account ID", }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", "SEP": "", }, ),
    ( "KEY_TABLE",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key Table", "SEP": "", }, ),
    ( "KEY",          { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key", "SEP": "", }, ),
    ( "START_TIME",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Start Time", }, ),
    ( "EXPIRE_TIME",  { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Expiration Time", }, ),
    ( "ECDSA_SIG",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x28, "DEBUG": 1, "DESC": "ECDSA Signature", "SEP": "", }, ),
    #
    ( "LIC_TYPE",   { "VIRTUAL": -1, "DEBUG": 1, "DESC": "License Type", }, ),
])
#
CONST_PSV_RIF_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_PSV_RIF_FIELDS = collections.OrderedDict([ \
    ## Size has to be taken into account to determine RIF version
    ( "VERSION",      { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version", }, ),
    ( "VERSION_FLAG", { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Version Flag", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "FLAGS",        { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Flags", }, ),
    #
    ( "AID",          { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Account ID", }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", "SEP": "", }, ),
    ( "KEY_TABLE",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key Table", "SEP": "", }, ),
    ( "KEY",          { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x10, "DEBUG": 1, "DESC": "Key", "SEP": "", }, ),
    ( "START_TIME",   { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Start Time", }, ),
    ( "EXPIRE_TIME",  { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Expiration Time", }, ),
    ( "ECDSA_SIG",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 0x28, "DEBUG": 1, "DESC": "ECDSA Signature", "SEP": "", }, ),
    ## Extension to PS3 RIF
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
CONST_PSM_RIF_ENDIAN = CONST_FMT_BIG_ENDIAN
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
    ( "CONTENT_ID",  { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", "SEP": "", }, ),
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
CONST_PKG4_MAGIC = bytes.fromhex("7f434e54")  ## "\x7fCNT"
CONST_PKG4_MAIN_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
    ( "REV",          { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Revision", }, ),
    ( "TYPE",         { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Type", }, ),
    ( "UNKNOWN1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
    ( "FILECNT",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "File Count", }, ),
    ( "ENTCNT",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Entry Count (or is this METACNT?)", }, ),
    ( "SCENTCNT",     { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "SC Entry Count", }, ),
    ( "METACNT",      { "FORMAT": CONST_FMT_UINT16, "DEBUG": 1, "DESC": "Meta Table Count (same as ENTCNT)", }, ),
    ( "METATBLOFS",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Table Offset", }, ),
    ( "ENTSIZE",      { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Ent Data Size", }, ),
    ( "BODYOFS",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Body Offset", }, ),
    ( "BODYSIZE",     { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Body Size", }, ),
    ( "PADDING1",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    ( "CONTENT_ID",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "DEBUG": 1, "CONV": 0x0204, "DESC": "Content ID", "SEP": "", }, ),
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
    #
    ( "DIGESTTABL",   { "FORMAT": CONST_FMT_CHAR, "SUBCOUNT": 24, "SUBSIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 2, "DESC": "Digest Table", "SEP": "", }, ),
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
    ( "PFSIMGDIG",    { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Image Digest", "SEP": "", }, ),
    ( "PFSSIGNDIG",   { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_SHA256_HASH_SIZE, "DEBUG": 1, "DESC": "PFS Signed Digest", "SEP": "", }, ),
    ( "PFSSPLITNTH0", { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Split NTH 0", }, ),
    ( "PFSSPLITNTH1", { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "PFS Split NTH 1", }, ),
## <<< Could be 136 bytes structure
## >>> Could be 2x 136 bytes structure from before
    ( "UNKNOWN5",     { "FORMAT": CONST_FMT_CHAR, "SIZE": -0x5a0, "DEBUG": 3, "DESC": "Unknown", "SKIP": True, }, ),
## <<< Could be 2x 136 bytes structure from before
## real size looks like it is 0x2000
])
#
## --> Meta Entry Table
CONST_PKG4_META_ENTRY_FIELDS = collections.OrderedDict([ \
    ( "METAID",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Meta Entry ID", }, ),
    ( "NAMERELOFS", { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Name Table Offset", }, ),
    ( "FLAGS1",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags 1", }, ),
    ( "FLAGS2",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags 2", }, ),
    ( "DATAOFS",    { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "PKG Data Offset", }, ),
    ( "DATASIZE",   { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Data Size", }, ),
    ( "PADDING1",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 8, "DEBUG": 3, "DESC": "Padding", "SKIP": True, }, ),
    #
    ( "NAME",       { "VIRTUAL": -1, "DEBUG": 1, "DESC": "File Name", }, ),
    ( "ENCRYPTED",  { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Entry is encrypted", }, ),
    ( "KEYINDEX",   { "VIRTUAL": -1, "DEBUG": 1, "DESC": "Entry Decryption Key", }, ),
])
#
## --> Name Table
##     Name Table is 0-indexed, index 0 is an empty name
CONST_PKG4_META_ENTRY_ID_DIGEST_TABLE = 0x0001
CONST_PKG4_META_ENTRY_ID_ENTRY_KEYS   = 0x0010
CONST_PKG4_META_ENTRY_ID_IMAGE_KEY    = 0x0020
CONST_PKG4_META_ENTRY_ID_GENERAL_DIGESTS = 0x0080
CONST_PKG4_META_ENTRY_ID_META_TABLE   = 0x0100
CONST_PKG4_META_ENTRY_ID_NAME_TABLE   = 0x0200
CONST_PKG4_META_ENTRY_ID_PARAM_SFO    = 0x1000
#
CONST_PKG4_META_ENTRY_NAME_MAP = {
    CONST_PKG4_META_ENTRY_ID_DIGEST_TABLE: ".digests",
    CONST_PKG4_META_ENTRY_ID_ENTRY_KEYS: ".entry_keys",
    CONST_PKG4_META_ENTRY_ID_IMAGE_KEY: ".image_key",
    CONST_PKG4_META_ENTRY_ID_GENERAL_DIGESTS: ".general_digests",
    CONST_PKG4_META_ENTRY_ID_META_TABLE: ".metatable",
    CONST_PKG4_META_ENTRY_ID_NAME_TABLE: ".nametable",

    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat",
    0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat",

    CONST_PKG4_META_ENTRY_ID_PARAM_SFO: "param.sfo",
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
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "icon0_{:02}.png".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1241-0x125f: pic1_<nn>.png
for Count in range(0x1f):
    Key = 0x1241 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "pic1_{:02}.png".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1261-0x127f: pic1_<nn>.png
for Count in range(0x1f):
    Key = 0x1261 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "changeinfo/changeinfo_{:02}.xml".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1281-0x129f: icon0_<nn>.dds
for Count in range(0x1f):
    Key = 0x1281 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "icon0_{:02}.dds".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x12c1-0x12df: pic1_<nn>.dds
for Count in range(0x1f):
    Key = 0x12c1 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "pic1_{:02}.dds".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1400-0x1463: trophy/trophy<nn>.dds
for Count in range(0x64):
    Key = 0x1400 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "trophy/trophy{:02}.trp".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1600-0x1609: keymap_rp/<nn>.png
for Count in range(0x0a):
    Key = 0x1600 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "keymap_rp/{:03}.png".format(Count)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
## 0x1610-0x17f9: keymap_rp/<nn>/<nnn>.png
for Count in range(0x01ea):
    Key = 0x1610 + Count
    CONST_PKG4_META_ENTRY_NAME_MAP[Key] = "keymap_rp/{:02}/{:03}.png".format(Count >> 4, Count & 0xf)
    if Debug_Level >= 4:
        dprint("Add ID {:#06x} Name \"{}\"".format(Key, CONST_PKG4_META_ENTRY_NAME_MAP[Key]))
#
CONST_PKG4_META_ENTRY_NAME_MAP = collections.OrderedDict(sorted(CONST_PKG4_META_ENTRY_NAME_MAP.items()))
## Clean-up
del Key
del Count
## --> PKG4 Update Keys
CONST_PKG4_UPDATE_KEYS = {
    0: { "KEY": "rWLjf5BeBrwZWTFCKBwRLOwOfsPpfv3K7826r6Y3jYQ=", "DESC": "PS4", },
}
for Key, Values in CONST_PKG4_UPDATE_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("PKG4 Update Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("PKG4 Update Key #{}:".format(Key), Value)
        del Value
del Values
del Key

##
## PARAM.SFO Definitions
##
#
## --> Header
CONST_PARAM_SFO_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PARAM_SFO_MAGIC = bytes.fromhex("00505346")  ## "\x00PSF"
CONST_PARAM_SFO_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",        { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
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
#
CONST_REGEX_PBP_SUFFIX = re.compile(r"\.PBP$", flags=re.UNICODE|re.IGNORECASE)
CONST_REGEX_EDAT_SUFFIX = re.compile(r"\.(edat|EDAT)$", flags=re.UNICODE|re.IGNORECASE)
## --> Header
CONST_PBP_HEADER_ENDIAN = CONST_FMT_LITTLE_ENDIAN
CONST_PBP_MAGIC = bytes.fromhex("00504250")  ## "\x00PBP"
CONST_PBP_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",         { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
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

##
## EDAT/SDAT (NPD) Definitions
##
#
## --> Header
CONST_EDAT_HEADER_ENDIAN = CONST_FMT_BIG_ENDIAN
CONST_EDAT_MAGIC = bytes.fromhex("4E504400")  ## "NPD\x00"
CONST_EDAT_HEADER_FIELDS = collections.OrderedDict([ \
    ( "MAGIC",         { "FORMAT": CONST_FMT_CHAR, "SIZE": 4, "DEBUG": 1, "DESC": "Magic", "SEP": "", }, ),
    ( "VERSION",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Version", }, ),  ## 1-4
    ( "LICENSE",       { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "License Type", }, ),  ## 0=debug, 1=network, 2=local, 3=free
    ( "TYPE",          { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Application Type", }, ),
    ( "CONTENT_ID",    { "FORMAT": CONST_FMT_CHAR, "SIZE": CONST_CONTENT_ID_SIZE, "CONV": 0x0204, "DEBUG": 1, "DESC": "Content ID", "SEP": "", }, ),
    ( "DIGEST",        { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Digest", "SEP": "", }, ),
    ( "CID_FN_HASH",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Hash of CID+FN", "SEP": "", }, ),
    ( "HEADER_HASH",   { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Header Hash", "SEP": "", }, ),
    ## --> extended header
    ( "VALID_FROM",    { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "Start validity period", }, ),
    ( "VALID_TO",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "End validity period", }, ),
    ( "FLAGS",         { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Flags", }, ),
    ( "BLOCKSIZE",     { "FORMAT": CONST_FMT_UINT32, "DEBUG": 1, "DESC": "Block Size", }, ),
    ( "FILESIZE",      { "FORMAT": CONST_FMT_UINT64, "DEBUG": 1, "DESC": "File Size", }, ),
    ( "META_HASH",     { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Meta Data Hash", "SEP": "", }, ),
    ( "EXT_HDR_HASH",  { "FORMAT": CONST_FMT_CHAR, "SIZE": 16, "DEBUG": 1, "DESC": "Extended Header Hash", "SEP": "", }, ),
    ( "META_ECDSA",    { "FORMAT": CONST_FMT_CHAR, "SIZE": 40, "DEBUG": 1, "DESC": "Meta Data ECDSA", "SEP": "", }, ),
    ( "EXT_HDR_ECDSA", { "FORMAT": CONST_FMT_CHAR, "SIZE": 40, "DEBUG": 1, "DESC": "Extended Header ECDSA", "SEP": "", }, ),
    #
    ( "DEBUG_PKG",     { "VIRTUAL": 1, "DEBUG": 1, "DESC": "Debug Package", }, ),
])
CONST_EDAT_SDAT_FLAG = 0x01000000
CONST_EDAT_ENCRYPTED_KEY = 0x00000008
## --> SDAT Keys
CONST_SDAT_KEYS = {
    0: { "KEY": "DWVe+OZ0qYq4UFz6fQEpMw==", "DESC": "SDAT Key 0", },
}
for Key, Values in CONST_SDAT_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("SDAT Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("SDAT Key #{}:".format(Key), Value)
        del Value
del Key
## --> EDAT Keys
CONST_EDAT_KEYS = {
    0: { "KEY": "vpWcqDCN76Ll4YDGNxKprg==", "DESC": "EDAT Key 0", },
    1: { "KEY": "TKnBSwHJUwmWm+xoqgvAgQ==", "DESC": "EDAT Key 1", },
}
for Key, Values in CONST_EDAT_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("EDAT Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("EDAT Key #{}:".format(Key), Value)
        del Value
del Key
## --> Dev KLicensee Keys
CONST_KLICENSEE_KEYS = {
    0: { "KEY": "AAAAAAAAAAAAAAAAAAAAAA==", "DESC": "None", },
    1: { "KEY": "cvmQeI+c/3RXJfCOTBKDhw==", "DESC": "NPDRM_OMAC_KEY_1", },
    2: { "KEY": "a6Updu/aFu88M5+ylx4law==", "DESC": "NPDRM_OMAC_KEY_2", },
    3: { "KEY": "m1Ff6s91BkmBqmBNkaVOlw==", "DESC": "NPDRM_OMAC_KEY_3", },
    4: { "KEY": "8vvKenWwTtwTkGOMzf3R7g==", "DESC": "NPDRM_KLIC_KEY", },
    5: { "KEY": "UsC1ynbWE0u0X8ZspjfywQ==", "DESC": "NPDRM_PSX_KEY", },
    6: { "KEY": "Kmr7z0PRV599c4dBoTvULg==", "DESC": "NPDRM_PSP_KEY_1", },
    7: { "KEY": "DbhXMjZs1zT8h550M0O7Tw==", "DESC": "NPDRM_PSP_KEY_2", },
}
for Key, Values in CONST_KLICENSEE_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        eprint("Dev KLicensee Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
    #
    if Debug_Level >= 3:
        Value = convertBytesToHexString(Values["KEY"], sep="")
        dprint("Dev KLicensee Key #{}:".format(Key), Value)
        del Value
del Key

##
## VSH Definitions
##
#
## --> ECDSA Curves
CONST_ECDSA_VSH_CURVES = {
    1: {
         "DESC": "VSH #1",
         "N":    { "INT": "//////////8AAbXGF/KQ6uHbrY8=", "DESC": "VSH #1 Order N/Q", },
         "P":    { "INT": "//////////8AAAAB//////////8=", "DESC": "VSH #1 P", },
         "A":    { "INT": "//////////8AAAAB//////////w=", "DESC": "VSH #1 A", },
         "B":    { "INT": "ZdFIjANZ4jStyVvTkIAUvZGlJfk=", "DESC": "VSH #1 B", },
         "GX":   { "INT": "Ilms7hVInLCWqILwrhz5/Y7l+Po=", "DESC": "VSH #1 Gx", },
         "GY":   { "INT": "YENYRW0KHLKQjekPJ9dcgr7BCMA=", "DESC": "VSH #1 Gy", },
    },
    2: {
         "DESC": "VSH #2",
         "N":    { "INT": "//////////7//7WuPFI+Y5RPISc=", "DESC": "VSH #2 Order N/Q", },
         "P":    { "INT": "//////////8AAAAB//////////8=", "DESC": "VSH #2 P", },
         "A":    { "INT": "//////////8AAAAB//////////w=", "DESC": "VSH #2 A", },
         "B":    { "INT": "povtwzQYApwdPOM7mjIfzLueDws=", "DESC": "VSH #2 B", },
         "GX":   { "INT": "Eo7EJWSH/Y/fZOJDe8Ch9tWv3iw=", "DESC": "VSH #2 Gx", },
         "GY":   { "INT": "WVhVfrHbABJgQlUk28N51axfSt8=", "DESC": "VSH #2 Gy", },
    },
}
for Number, Curve in CONST_ECDSA_VSH_CURVES.items():
    Bit_Len = None
    Size = None
    for Key in Curve:
        Show_Convert = False
        if isinstance(Curve[Key], dict) \
        and "INT" in Curve[Key]:
            if isinstance(Curve[Key]["INT"], unicode):
                Curve[Key]["INT"] = base64.standard_b64decode(Curve[Key]["INT"])
            elif isinstance(Curve[Key]["INT"], bytes) \
            or isinstance(Curve[Key]["INT"], bytearray):
                eprint("VSH ECDSA Curve #{}.{}:".format(Number, Key), base64.standard_b64encode(Curve[Key]["INT"]), prefix="[CONVERT] ")
            elif isinstance(Curve[Key]["INT"], int):
                Show_Convert = True
            #
            if isinstance(Curve[Key]["INT"], bytes) \
            or isinstance(Curve[Key]["INT"], bytearray):
                Curve[Key]["INT"] = int.from_bytes(Curve[Key]["INT"], byteorder="big")
            #
            if Key == "N":
                Bit_Len = Curve["N"]["INT"].bit_length()
                Size = math.ceil(Bit_Len / 8.0)
                if Debug_Level >= 3:
                    dprint("VSH ECDSA Curve #{} BITLEN:".format(Number), Bit_Len)
            #
            if Show_Convert:
                eprint("VSH ECDSA Curve #{}.{}:".format(Number, Key), base64.standard_b64encode(Curve[Key]["INT"].to_bytes(Size, byteorder="big")), prefix="[CONVERT] ")
        #
        if Debug_Level >= 3:
            if isinstance(Curve[Key], dict) \
            and "INT" in Curve[Key]:
                Value = "{:#x}".format(Curve[Key]["INT"])
            else:
                Value = Curve[Key]
            dprint("VSH ECDSA Curve #{} {:2}:".format(Number, Key), Value)
            del Value
    Curve["BITLEN"] = Bit_Len
    Curve["SIZE"] = Size
    # --> Point Jacobi specialities
    if not "GZ" in Curve:
        Curve["GZ"] = {}
    if not "INT" in Curve["GZ"] \
    or Curve["GZ"]["INT"] is None:
        Curve["GZ"]["INT"] = 1  ## equal to 1 when converting from affine coordinates
    # --> Build Curve
    Curve["CURVE"] = ecdsa.ellipticcurve.CurveFp(Curve["P"]["INT"], Curve["A"]["INT"], Curve["B"]["INT"])
    Curve["POINT"] = ecdsa.ellipticcurve.PointJacobi(Curve["CURVE"], Curve["GX"]["INT"], Curve["GY"]["INT"], Curve["GZ"]["INT"], order=Curve["N"]["INT"], generator=False)
del Key
del Size
del Bit_Len
del Curve
del Number
## --> ECDSA Public Key
CONST_ECDSA_VSH_PUBKEYS = {
    0: {
         "DESC": "VSH KLicensee PubKey",
         "CURVE": 2,
         "X": { "INT": "YiewCgKFb7BBCIdnGeCgGDKR7rk=", "DESC": "VSH KLicensee PubKey X", },
         "Y": { "INT": "bnNqv4H3DukWGw3esCZ2Gv97yFs=", "DESC": "VSH KLicensee PubKey Y", },
    },
    1: {
         "DESC": "VSH NPDRM PubKey",
         "CURVE": 2,
         "X": { "INT": "5nkuRGzronvK3zdLmVBP2OgK3+s=", "DESC": "VSH NPDRM PubKey X", },
         "Y": { "INT": "Pmbec//ljTKRIhxlAYwDjTgiw8k=", "DESC": "VSH NPDRM PubKey Y", },
    },
}
for Number, PubKey in CONST_ECDSA_VSH_PUBKEYS.items():
    Size = CONST_ECDSA_VSH_CURVES[PubKey["CURVE"]]["SIZE"]
    for Key in PubKey:
        if isinstance(PubKey[Key], dict) \
        and "INT" in PubKey[Key]:
            if isinstance(PubKey[Key]["INT"], unicode):
                PubKey[Key]["INT"] = base64.standard_b64decode(PubKey[Key]["INT"])
            elif isinstance(PubKey[Key]["INT"], bytes) \
            or isinstance(PubKey[Key]["INT"], bytearray):
                eprint("VSH ECDSA {} PubKey {}:".format(Number, Key), base64.standard_b64encode(PubKey[Key]["INT"]), prefix="[CONVERT] ")
            elif isinstance(PubKey[Key]["INT"], int):
                eprint("VSH ECDSA {} PubKey {}:".format(Number, Key), base64.standard_b64encode(PubKey[Key]["INT"].to_bytes(Size, byteorder="big")), prefix="[CONVERT] ")
            #
            if isinstance(PubKey[Key]["INT"], bytes) \
            or isinstance(PubKey[Key]["INT"], bytearray):
                PubKey[Key]["INT"] = int.from_bytes(PubKey[Key]["INT"], byteorder="big")
        #
        if Debug_Level >= 3:
            if isinstance(PubKey[Key], dict) \
            and "INT" in PubKey[Key]:
                Value = "{:#x}".format(PubKey[Key]["INT"])
            else:
                Value = PubKey[Key]
            dprint("VSH ECDSA {} PubKey {}:".format(Number, Key), Value)
            del Value
    # --> Build Public Key
    PubPoint = ecdsa.ellipticcurve.Point(CONST_ECDSA_VSH_CURVES[PubKey["CURVE"]]["CURVE"], PubKey["X"]["INT"], PubKey["Y"]["INT"], order=CONST_ECDSA_VSH_CURVES[PubKey["CURVE"]]["N"]["INT"])
    PubKey["PUBKEY"] = ecdsa.ecdsa.Public_key(CONST_ECDSA_VSH_CURVES[PubKey["CURVE"]]["POINT"], PubPoint, verify=True)
del PubPoint
del Key
del Size
del PubKey
del Number


##
## Special Case Definitions
##
CONST_TITLE_ID_PSV_POCKETSTATION = "PCSC80018"


def currenttime():
    ## UTC time
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def prettySize(n, power=0, b=1024, u="B", pre=[""]+[p+"i"for p in "KMGTPEZY"]):
    power, n = min(int(math.log(max(n*b**power, 1), b)), len(pre)-1), n*b**power
    return "%%.%if %%s%%s" % abs(power % (-power-1)) % (n/b**float(power), pre[power], u)


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
    if isinstance(python_object, (datetime.datetime, datetime.date)):
        return python_object.isoformat()
    if isinstance(python_object, bytes) \
    or isinstance(python_object, bytearray):
        return {"__class__": "bytes",
                "__value__": convertBytesToHexString(python_object, sep="")}
    if isinstance(python_object, PkgAesCtrCounter):
        return unicode(python_object)
    if isinstance(python_object, PkgXorSha1Counter):
        return unicode(python_object)
    if isinstance(python_object, aenum.Enum):
        return unicode(python_object)
    raise TypeError("".join((repr(python_object), " is not JSON serializable")))


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
    def __init__(self, source, function_debug_level=0):
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
        self._headers = {"User-Agent": CONST_USER_AGENT_PS3}  ## Default to PS3 headers (fits PS3/PSX/PSP/PSV packages, but not PSM packages for PSV)

        ## Check for multipart package
        ## --> XML
        if self._source.endswith(".xml"):
            input_stream = None
            xml_root = None
            xml_element = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL XML data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream:
                        if input_stream.url != self._source:
                            eprint("[INPUT] Redirected URL", input_stream.url)
                        eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    eprint("", prefix=None)
                    raise  ## re-raise
                if input_stream.status_code != requests.codes.ok:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream.url != self._source:
                        eprint("[INPUT] Redirected URL", input_stream.url)
                    eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    raise input_stream.raise_for_status()
                if function_debug_level >= 3:
                    if input_stream.url != self._source:
                        dprint("[INPUT] Redirected URL", input_stream.url)
                    dprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    dprint("[INPUT] Response headers:", input_stream.headers)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.text)
                input_stream.close()
            else:
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE XML data stream")
                try:
                    input_stream = io.open(self._source, mode="rt", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    raise  ## re-raise
                xml_root = xml.etree.ElementTree.fromstring(input_stream.read())
                input_stream.close()
            del input_stream
            #
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
                if function_debug_level >= 2:
                    dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
            del file_part
            del offset
            #
            del xml_element
            del xml_root
        ## --> JSON
        elif self._source.endswith(".json"):
            self._headers = {"User-Agent": CONST_USER_AGENT_PS4}  ## Switch to PS4 headers
            input_stream = None
            json_data = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL JSON data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream:
                        if input_stream.url != self._source:
                            eprint("[INPUT] Redirected URL", input_stream.url)
                        eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    eprint("", prefix=None)
                    raise  ## re-raise
                if input_stream.status_code != requests.codes.ok:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream.url != self._source:
                        eprint("[INPUT] Redirected URL", input_stream.url)
                    eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    raise input_stream.raise_for_status()
                if function_debug_level >= 3:
                    if input_stream.url != self._source:
                        dprint("[INPUT] Redirected URL", input_stream.url)
                    dprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    dprint("[INPUT] Response headers:", input_stream.headers)
                json_data = input_stream.json()
                input_stream.close()
            else:
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE JSON data stream")
                try:
                    input_stream = io.open(self._source, mode="rt", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    raise  ## re-raise
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
                    if function_debug_level >= 2:
                        dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
                del file_part
                del count
            #
            del json_data
        else:
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Using source as URL PKG data stream")
                self._pkg_name = os.path.basename(requests.utils.urlparse(self._source).path).strip()
            else:
                if function_debug_level >= 2:
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
            if function_debug_level >= 2:
                dprint("[INPUT] Pkg Part #{} Offset {:#012x} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["url"]))
            del file_part
            #
            self.open(self._parts[0], function_debug_level=max(0,function_debug_level))
            if "SIZE" in self._parts[0]:
                self._size = self._parts[0]["SIZE"]

        read_size = CONST_READ_AHEAD_SIZE
        if read_size > self._size:
            read_size = self._size
        if read_size > 0:
            self._buffer = self.read(0, read_size, function_debug_level=max(0,function_debug_level))
            self._buffer_size = len(self._buffer)
            if function_debug_level >= 2:
                dprint("[INPUT] Buffered first {} bytes of package".format(self._buffer_size), "(max {})".format(CONST_READ_AHEAD_SIZE) if self._buffer_size != CONST_READ_AHEAD_SIZE else "")

    def getSize(self, function_debug_level=0):
        return self._size

    def getSource(self, function_debug_level=0):
        return self._source

    def getPkgName(self, function_debug_level=0):
        return self._pkg_name

    def open(self, file_part, function_debug_level=0):
        ## Check if already opened
        if "STREAM" in file_part:
            return

        part_size = None
        response = None
        if file_part["url"].startswith("http:") \
        or file_part["url"].startswith("https:"):
            if function_debug_level >= 2:
                dprint("[INPUT] Opening Pkg Part #{} as URL PKG data stream".format(file_part["INDEX"]))
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            file_part["STREAM_TYPE"] = "requests"
            try:
                file_part["STREAM"] = requests.Session()
            except:
                eprint("[INPUT] Could not create HTTP/S session for PKG URL", file_part["url"])
                eprint("", prefix=None)
                raise  ## re-raise
            #
            file_part["STREAM"].headers = self._headers
            try:
                response = file_part["STREAM"].head(file_part["url"], allow_redirects=True, timeout=60)
            except:
                eprint("[INPUT] Could not open URL", file_part["url"])
                if response:
                    if response.url != file_part["url"]:
                        eprint("[INPUT] Redirected URL", response.url)
                    eprint("[INPUT]", response.status_code, response.reason)
                eprint("", prefix=None)
                raise  ## re-raise
            if response.status_code != requests.codes.ok:
                eprint("[INPUT] Could not open URL", file_part["url"])
                if response.url != file_part["url"]:
                    eprint("[INPUT] Redirected URL", response.url)
                eprint("[INPUT]", response.status_code, response.reason)
                raise response.raise_for_status()
            if function_debug_level >= 3:
                if response.url != file_part["url"]:
                    dprint("[INPUT] Redirected URL", response.url)
                dprint("[INPUT]", response.status_code, response.reason)
                dprint("[INPUT] Response headers:", response.headers)
            if "content-length" in response.headers:
                part_size = int(response.headers["content-length"])
        else:
            if function_debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as FILE PKG data stream".format(file_part["INDEX"]))
            #
            file_part["STREAM_TYPE"] = "file"
            try:
                file_part["STREAM"] = io.open(file_part["url"], mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("[INPUT] Could not open PKG FILE", file_part["url"])
                eprint("", prefix=None)
                raise  ## re-raise
            #
            file_part["STREAM"].seek(0, io.SEEK_END)
            part_size = file_part["STREAM"].tell()

        ## Check file size
        if not part_size is None:
            if not "SIZE" in file_part:
                file_part["SIZE"] = part_size
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
            else:
                if part_size != file_part["SIZE"]:
                    if not response is None:
                        eprint("[INPUT]", response.status_code, response.reason)
                        eprint("[INPUT] Response headers:", response.headers)
                    eprint("[INPUT] File size differs from XML/JSON meta data ({} <> {})".format(part_size, file_part["SIZE"]))
                    eprint("", prefix=None)
                    sys.exit(2)

        if function_debug_level >= 3:
            dprint("[INPUT] Data stream is of class", file_part["STREAM"].__class__.__name__)

    def read(self, offset, size, function_debug_level=0):
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
            if function_debug_level >= 3:
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
            if function_debug_level >= 3:
                dprint("[INPUT] Read offset {:#012x} size {}/{} bytes from Pkg Part #{} Offset {:#012x}".format(read_offset, read_buffer_size, size, file_part["INDEX"], file_offset))
            #
            self.open(file_part, function_debug_level=max(0,function_debug_level))
            #
            if file_part["STREAM_TYPE"] == "file":
                file_part["STREAM"].seek(file_offset, io.SEEK_SET)
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
                response = file_part["STREAM"].get(file_part["url"], headers=reqheaders, timeout=60)
                result.extend(response.content)
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        return result

    def close(self, function_debug_level=0):
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
        self._key_bits = Cryptodome.Cipher.AES.key_size[0] * 8  ## Key length 16 bytes = 128 bits
        if isinstance(iv, bytes) \
        or isinstance(iv, bytearray):
            self._iv = int.from_bytes(iv, byteorder="big")
        elif isinstance(iv, int):
            self._iv = iv
        self._block_offset = -1
        self._block_size = Cryptodome.Cipher.AES.block_size

    def _setOffset(self, offset):
        if offset == self._block_offset:
            return
        #
        start_counter = self._iv
        self._block_offset = 0
        count = offset // self._block_size
        if count > 0:
            start_counter += count
            self._block_offset += count * self._block_size
        #
        if hasattr(self, "_aes"):
            del self._aes
        counter = Cryptodome.Util.Counter.new(self._key_bits, initial_value=start_counter)
        self._aes = Cryptodome.Cipher.AES.new(self._key, Cryptodome.Cipher.AES.MODE_CTR, counter=counter)

    def decrypt(self, offset, data):
        self._setOffset(offset)
        self._block_offset += len(data)
        ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
        decrypted_data = bytearray(self._aes.decrypt(bytes(data)))
        return decrypted_data


class PkgXorSha1Counter():
    def __str__(self):
        return convertBytesToHexString(self._iv.to_bytes(0x40, byteorder="big"), sep="")

    def __init__(self, iv):
        if isinstance(iv, bytes) \
        or isinstance(iv, bytearray):
            self._iv = int.from_bytes(iv, byteorder="big")
        elif isinstance(iv, int):
            self._iv = iv
        self._counter = self._iv
        self._block_offset = 0
        self._block_size = 0x10

    def _setOffset(self, offset):
        if offset == self._block_offset:
            return
        #
        self._counter = self._iv
        self._block_offset = 0
        count = offset // self._block_size
        if count > 0:
            self._counter += count
            self._block_offset += count * self._block_size

    def decrypt(self, offset, encrypted_data):
        self._setOffset(offset)
        self._block_offset += len(encrypted_data)
        #
        decrypted_data = bytearray()
        for _i in range(0, len(encrypted_data), self._block_size):
            xor_bytes = Cryptodome.Hash.SHA1.new(self._counter.to_bytes(0x40, byteorder="big")).digest()
            decrypted_bytes = encrypted_data[_i:_i+self._block_size]
            fastxor.fast_xor_inplace(decrypted_bytes, bytearray(xor_bytes[0:self._block_size]))
            ## Python standard xor implementation (slightly slower than fastxor)
            #xor_int = int.from_bytes(xor_bytes[0:self._block_size], byteorder=sys.byteorder)
            ##
            #encrypted_int = int.from_bytes(encrypted_data[_i:_i+self._block_size], byteorder=sys.byteorder)
            ##
            #decrypted_int = encrypted_int ^ xor_int
            #decrypted_bytes = decrypted_int.to_bytes(self._block_size, byteorder=sys.byteorder)
            decrypted_data.extend(decrypted_bytes)
            #
            self._counter += 1
        #
        return decrypted_data


def convertRapkeyToRifkey(rapkey_bytes):
    aes = Cryptodome.Cipher.AES.new(CONST_RAP_KEYS[0]["KEY"], Cryptodome.Cipher.AES.MODE_CBC, iv=CONST_AES_EMPTY_IV)
    ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
    temp_bytes = bytearray(aes.decrypt(bytes(rapkey_bytes)))
    #
    for _ in range(5):
        fastxor.fast_xor_inplace(temp_bytes, bytearray(CONST_RAP_KEYS[1]["KEY"]))
        #
        for _i in range(Cryptodome.Cipher.AES.block_size-1,0,-1):
            pos1 = CONST_RAP_PBOX[_i]
            pos2 = CONST_RAP_PBOX[_i-1]
            temp_bytes[pos1] ^= temp_bytes[pos2]
        #
        carryover = 0
        for _i in range(Cryptodome.Cipher.AES.block_size):
            pos1 = CONST_RAP_PBOX[_i]
            new_byte = temp_bytes[pos1] - carryover - CONST_RAP_KEYS[2]["KEY"][pos1]
            if new_byte < 0x00:
                carryover = 1
            else:
                carryover = 0
            temp_bytes[pos1] = new_byte & 0xff
    #
    return bytes(temp_bytes)


def convertRifkeyToRapkey(rifkey_bytes):
    temp_bytes = bytearray(rifkey_bytes)
    #
    for _ in range(5):
        carryover = 0
        for _i in range(Cryptodome.Cipher.AES.block_size):
            pos1 = CONST_RAP_PBOX[_i]
            new_byte = temp_bytes[pos1] + carryover + CONST_RAP_KEYS[2]["KEY"][pos1]
            if new_byte > 0xff:
                carryover = 1
            else:
                carryover = 0
            temp_bytes[pos1] = new_byte & 0xff
        #
        for _i in range(1,Cryptodome.Cipher.AES.block_size):
            pos1 = CONST_RAP_PBOX[_i]
            pos2 = CONST_RAP_PBOX[_i-1]
            temp_bytes[pos1] ^= temp_bytes[pos2]
        #
        fastxor.fast_xor_inplace(temp_bytes, bytearray(CONST_RAP_KEYS[1]["KEY"]))
    #
    aes = Cryptodome.Cipher.AES.new(CONST_RAP_KEYS[0]["KEY"], Cryptodome.Cipher.AES.MODE_CBC, iv=CONST_AES_EMPTY_IV)
    ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
    temp_bytes = aes.encrypt(bytes(temp_bytes))
    #
    return bytes(temp_bytes)


def getRegion(region_code):
    ## For definition see http://www.psdevwiki.com/ps3/Productcode
    ##                    http://www.psdevwiki.com/ps3/PARAM.SFO#TITLE_ID
    ##                    http://www.psdevwiki.com/ps4/Regioning
    ##
    ##                    https://playstationdev.wiki/psvitadevwiki/index.php?title=Languages
    ##                    http://www.psdevwiki.com/ps3/Languages
    ##                    http://www.psdevwiki.com/ps3/PARAM.SFO#TITLE
    ##                    http://www.psdevwiki.com/ps4/Languages
    if region_code == "A":
        return "ASIA", ["09", "11", "10", "00"]
    elif region_code == "E":
        return "EU", ["01", "18"]
    elif region_code == "H":
        return "ASIA(HKG)", ["11", "10"]
    elif region_code == "I":
        return "INT", ["01", "18"]
    elif region_code == "J":
        return "JP", ["00"]
    elif region_code == "K":
        return "ASIA(KOR)", ["09"]
    elif region_code == "U":
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
            output = format_string.format(field_def["INDEX"], field_def["OFFSET"], field_def["SIZE"], field_def["DESC"], convertBytesToHexString(temp_fields[field_def["INDEX"]], format_string="".join((CONST_STRUCTURE_ENDIAN, field_format)), sep=sep))
            #
            if "CONV" in field_def:
                if field_def["CONV"] == 0x0004 \
                or field_def["CONV"] == 0x0204:  ## UTF-8 not and NUL-terminated
                    value = convertUtf8BytesToString(temp_fields[field_def["INDEX"]], field_def["CONV"])
                    output = "".join((output, " => ", value))
            elif CONST_STRUCTURE_ENDIAN == CONST_FMT_LITTLE_ENDIAN \
            and (field_format == CONST_FMT_UINT16 \
                 or field_format == CONST_FMT_UINT32 \
                 or field_format == CONST_FMT_UINT64):
                output = "".join((output, " => ", convertBytesToHexString(temp_fields[field_def["INDEX"]], format_string="".join((CONST_FMT_BIG_ENDIAN, field_format)), sep=sep)))
            #
            dprint(output)


def dprintField(key, field, field_def, format_string, parent_debug_level, parent_prefix, print_func=dprint, sep=" "):
    if isinstance(key, unicode):
        key = "".join(("\"", key, "\""))
    if parent_prefix is None:
        format_values = {}
        format_values["KEY"] = key
        if field_def:
            if "INDEX" in field_def:
                format_values["INDEX"] = field_def["INDEX"]
            if "DESC" in field_def:
                format_values["DESC"] = field_def["DESC"]
        prefix = format_string.format(**format_values)
    else:
        prefix = "".join((parent_prefix, "[", format_string.format(key), "]"))
    #
    if field_def \
    and "SEP" in field_def:
        sep = field_def["SEP"]
    #
    if isinstance(field, list) \
    or isinstance(field, tuple):  ## indexed list
        dprintFieldsList(field, format_string, parent_debug_level, prefix, print_func=print_func, sep=sep)
    elif isinstance(field, dict):  ## dictionary
        dprintFieldsDict(field, format_string, parent_debug_level, prefix, print_func=print_func, sep=sep)
    else:
        if isinstance(field, bytes) \
        or isinstance(field, bytearray):
            value = convertBytesToHexString(field, sep=sep)
        elif isinstance(field, bool):  ## special case of int
            value = field
        elif isinstance(field, int):
            if field_def \
            and "HEXSIZE" in field_def:
                value = "".join(("{0:#0", unicode(field_def["HEXSIZE"]), "x} = {0}")).format(field)
            else:
                value = "{0:#x} = {0}".format(field)
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
            elif field_format == CONST_FMT_UINT8 \
            or field_format == CONST_FMT_UINT16 \
            or field_format == CONST_FMT_UINT32 \
            or field_format == CONST_FMT_UINT64:
                field_def["SIZE"] = struct.calcsize("".join((CONST_STRUCTURE_ENDIAN, field_format)))
                field_def["HEXSIZE"] = 2 + (field_def["SIZE"]*2)
                field_def["BINSIZE"] = 2 + (field_def["SIZE"]*8)
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
    meta_cnt_len = unicode(len(unicode(header_fields["METACNT"]-1)))
    meta_cnt_format_string = "".join(("{:", meta_cnt_len, "}"))

    ## Retrieve PKG4 Meta Entry Table from input stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Meta Entry Table:")
    pkg_meta_table_size = header_fields["METACNT"] * CONST_PKG4_META_ENTRY_FIELDS["STRUCTURE_SIZE"]
    if function_debug_level >= 2:
        dprint("Get PKG4 meta entry table from offset {:#x} with count {} and size {}".format(header_fields["METATBLOFS"], header_fields["METACNT"], pkg_meta_table_size))
    temp_bytes = bytearray()
    try:
        temp_bytes.extend(input_stream.read(header_fields["METATBLOFS"], pkg_meta_table_size, function_debug_level=max(0, function_debug_level)))
    except:
        input_stream.close(function_debug_level)
        eprint("Could not get PKG4 meta table at offset {:#x} with size {} from".format(header_fields["METATBLOFS"], pkg_meta_table_size), input_stream.getSource())
        eprint("", prefix=None)
        raise  ## re-raise

    ## Parse PKG4 Meta Entry Table Data
    meta_table = []
    meta_table_map = collections.OrderedDict()
    offset = 0
    #
    for _i in range(header_fields["METACNT"]):  ## 0 to <meta entry count - 1>
        temp_fields = struct.unpack(CONST_PKG4_META_ENTRY_FIELDS["STRUCTURE_UNPACK"], temp_bytes[offset:offset+CONST_PKG4_META_ENTRY_FIELDS["STRUCTURE_SIZE"]])
        if function_debug_level >= 2:
            dprintBytesStructure(CONST_PKG4_META_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, temp_fields, "".join(("PKG4 Meta Entry[", meta_cnt_format_string.format(_i), "][{:2}]: [{:#04x}|{:2}] {} = {}")), function_debug_level)
        temp_fields = convertFieldsToOrdDict(CONST_PKG4_META_ENTRY_FIELDS, temp_fields)
        temp_fields["INDEX"] = _i
        temp_fields["ENCRYPTED"] = (temp_fields["FLAGS1"] & 0x80000000) != 0
        temp_fields["KEYINDEX"] = (temp_fields["FLAGS2"] & 0xf000) >> 12
        meta_table.append(temp_fields)
        #
        meta_table_map[temp_fields["METAID"]] = _i
        #
        del temp_fields
        #
        offset += CONST_PKG4_META_ENTRY_FIELDS["STRUCTURE_SIZE"]
    #
    del temp_bytes

    ## Check if Meta Table size fits exactly the meta entry count
    meta_entry = meta_table[meta_table_map[CONST_PKG4_META_ENTRY_ID_META_TABLE]]
    if pkg_meta_table_size != meta_entry["DATASIZE"]:
        eprint("Determined Meta Table size {:#} <> {:#} from meta table #{} ID {:#06x}.".format(pkg_meta_table_size, meta_entry["DATASIZE"], meta_table_map[CONST_PKG4_META_ENTRY_ID_META_TABLE], CONST_PKG4_META_ENTRY_ID_META_TABLE), input_stream.getSource())
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")

    ## Retrieve PKG4 Name Table from input stream
    if function_debug_level >= 2:
        dprint(">>>>> PKG4 Name Table:")
    name_table = None
    if not CONST_PKG4_META_ENTRY_ID_NAME_TABLE in meta_table_map:
        dprint("Not present!")
    else:
        meta_entry = meta_table[meta_table_map[CONST_PKG4_META_ENTRY_ID_NAME_TABLE]]
        if function_debug_level >= 2:
                dprint("Get PKG4 name table from offset {:#x} with size {}".format(meta_entry["DATAOFS"], meta_entry["DATASIZE"]))
        name_table = bytearray()
        try:
            name_table.extend(input_stream.read(meta_entry["DATAOFS"], meta_entry["DATASIZE"], function_debug_level))
        except:
            input_stream.close(function_debug_level)
            eprint("Could not get PKG4 name table at offset {:#x} with size {} from".format(meta_entry["DATAOFS"], meta_entry["DATASIZE"]), input_stream.getSource())
            eprint("", prefix=None)
            raise  ## re-raise

    ## Parse PKG4 Name Table Data for Meta Entries
    if function_debug_level >= 2:
        dprint("Parse PKG4 Name Table for Meta Entry Names")
    #
    name_offset_end = None
    for _i in range(header_fields["METACNT"]):  ## 0 to <meta entry count - 1>
        meta_entry = meta_table[_i]
        #
        if name_table \
        and meta_entry["NAMERELOFS"] > 0:
            meta_entry["NAME"] = convertUtf8BytesToString(name_table[meta_entry["NAMERELOFS"]:], 0x0204)
            #
            if name_offset_end is None \
            or meta_entry["NAMERELOFS"] >= name_offset_end:
                name_offset_end = meta_entry["NAMERELOFS"] + len(meta_entry["NAME"]) + 1
        elif meta_entry["METAID"] in CONST_PKG4_META_ENTRY_NAME_MAP:
            meta_entry["NAME"] = CONST_PKG4_META_ENTRY_NAME_MAP[meta_entry["METAID"]]
        #
        if "NAME" in meta_entry \
        and function_debug_level >= 2:
            dprint("".join(("PKG4 Meta Entry[", meta_cnt_format_string, "]: ID {:#06x} Name Offset {:#03x} =")).format(_i, meta_entry["METAID"], meta_entry["NAMERELOFS"]), meta_entry["NAME"])
        #
        if print_unknown \
        and not meta_entry["METAID"] in CONST_PKG4_META_ENTRY_NAME_MAP:
            eprint("".join(("PKG4 Meta Entry[", meta_cnt_format_string, "]: ID {:#06x} Name Offset {:#03x} =")).format(_i, meta_entry["METAID"], meta_entry["NAMERELOFS"]), meta_entry["NAME"], prefix="[UNKNOWN] ")

    ## Check if Name Table size fits exactly the name offsets + length
    if CONST_PKG4_META_ENTRY_ID_NAME_TABLE in meta_table_map:
        meta_entry = meta_table[meta_table_map[CONST_PKG4_META_ENTRY_ID_NAME_TABLE]]
        if name_offset_end != meta_entry["DATASIZE"]:
            eprint("Determined Name Table size {:#} <> {:#} from meta table #{} ID {:#06x}.".format(name_offset_end, meta_entry["DATASIZE"], meta_table_map[CONST_PKG4_META_ENTRY_ID_NAME_TABLE], CONST_PKG4_META_ENTRY_ID_NAME_TABLE), input_stream.getSource())
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")

    ## Debug print results
    dprint(">>>>> parsePkg4Header results:")
    dprintFieldsDict(header_fields, "pkgheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsList(meta_table, "".join(("pkgmetatable[{KEY:", meta_cnt_len, "}]")), function_debug_level, None)
    if function_debug_level >= 2:
        dprintFieldsDict(meta_table_map, "pkgmetatablemap[{KEY:#06x}]", function_debug_level, None)
        dprint("pkgnametable:", name_table)

    return header_fields, meta_table, meta_table_map


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
        raise  ## re-raise

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
            eprint("Not a known PKG3 Extended Main Header ({} <> {})".format(convertBytesToHexString(ext_header_fields["MAGIC"], sep=""), convertBytesToHexString(CONST_PKG3_EXT_MAGIC, sep="")), input_stream.getSource())
            eprint("", prefix=None)
            sys.exit(2)

    ## Determine debug package
    header_fields["DEBUG_PKG"] = (header_fields["REV"] & 0x8000) == 0

    ## Extract fields from PKG3 Main Header Meta Data
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Meta Data:")
    meta_data = collections.OrderedDict()
    meta_data["STRUCTURE_DEF"] = collections.OrderedDict()
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
        meta_data["STRUCTURE_DEF"][md_entry_type] = {}
        meta_data["STRUCTURE_DEF"][md_entry_type]["INDEX"] = _i
        ## (1) DRM Type
        ## (2) Content Type
        if md_entry_type == 0x01 \
        or md_entry_type == 0x02:
            if md_entry_type == 0x01:
                meta_data[md_entry_type]["DESC"] = "DRM Type"
            elif md_entry_type == 0x02:
                meta_data[md_entry_type]["DESC"] = "Content Type"
            meta_data[md_entry_type]["VALUE"] = getInteger32BitBE(temp_bytes, 0)
            meta_data["STRUCTURE_DEF"][md_entry_type]["SIZE"] = 4
            meta_data["STRUCTURE_DEF"][md_entry_type]["HEXSIZE"] = 2 + (meta_data["STRUCTURE_DEF"][md_entry_type]["SIZE"]*2)
            meta_data["STRUCTURE_DEF"][md_entry_type]["BINSIZE"] = 2 + (meta_data["STRUCTURE_DEF"][md_entry_type]["SIZE"]*8)
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
            if md_entry_type == 0x0E:
                meta_data[md_entry_type]["UNKNOWN1"] = temp_bytes[0x08:0x08+4]
                meta_data[md_entry_type]["FIRMWARE"] = temp_bytes[0x0c:0x0c+4]
                meta_data[md_entry_type]["UNKNOWN2"] = temp_bytes[0x10:md_entry_size - 0x20]
            else:
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
            elif header_fields["KEYINDEX"] == 3:
                if not 0x02 in meta_data \
                or meta_data[0x02]["VALUE"] != 0x17:  ## PSV Livarea
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
    #
    pkg_key = bytearray(0x40)
    pkg_key[0x00:0x08] = header_fields["DIGEST"][0x00:0x08]
    pkg_key[0x08:0x10] = header_fields["DIGEST"][0x00:0x08]
    if Arguments.arcade:
        pkg_key[0x10:0x18] = header_fields["DIGEST"][0x00:0x08]
    else:
        pkg_key[0x10:0x18] = header_fields["DIGEST"][0x08:0x10]
    pkg_key[0x18:0x20] = header_fields["DIGEST"][0x08:0x10]
    if Arguments.arcade:
        for _i in range(0x20,0x38):
            pkg_key[_i] = 0xa0
    header_fields["XOR_CTR"] = PkgXorSha1Counter(pkg_key)
    if function_debug_level >= 2:
        dprint("Debug XOR IV from DIGEST: {}".format(convertBytesToHexString(pkg_key, sep="")))
    del pkg_key

    ## Debug print results
    dprint(">>>>> parsePkg3Header results:")
    dprintFieldsDict(header_fields, "pkgheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    if ext_header_fields:
        dprintFieldsDict(ext_header_fields, "pkgextheaderfields[{KEY:14}|{INDEX:2}]", function_debug_level, None)
    dprintFieldsDict(meta_data, "pkgmetadata[{KEY:#04x}]", function_debug_level, None)

    return header_fields, ext_header_fields, meta_data, unencrypted_bytes


def parsePbpHeader(head_bytes, input_stream, file_size, function_debug_level=0):
    if function_debug_level >= 2:
        dprint(">>>>> PBP Header:")

    ## For definition see http://www.psdevwiki.com/ps3/Eboot.PBP

    ## Extract fields from PBP Header
    temp_fields = struct.unpack(CONST_PBP_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_PBP_HEADER_FIELDS, CONST_PBP_HEADER_ENDIAN, temp_fields, "PBP Header[{:1}]: [{:#04x}|{:1}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    pbp_header_fields = convertFieldsToOrdDict(CONST_PBP_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Retrieve PKG3 Unencrypted Data from input stream
    if not input_stream is None:
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
            raise  ## re-raise

    ## Determine key index for data
    pass  ## TODO

    ## Build item entries
    item_entries = []
    item_index = 0
    last_item = None
    #
    for key in ("PARAM_SFO_OFS", "ICON0_PNG_OFS", "ICON1_PMF_OFS", "PIC0_PNG_OFS", "PIC1_PNG_OFS", "SND0_AT3_OFS", "DATA_PSP_OFS", "DATA_PSAR_OFS"):
        item_entry = collections.OrderedDict()
        item_entry["INDEX"] = item_index
        item_entry["STRUCTURE_DEF"] = CONST_PKG3_ITEM_ENTRY_FIELDS
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


def parseEdatHeader(head_bytes, function_debug_level):
    if function_debug_level >= 2:
        dprint(">>>>> EDAT/SDAT Header:")

    ## For definition see https://www.psdevwiki.com/ps3/EDAT_files

    ## Extract fields from NPD Header
    temp_fields = struct.unpack(CONST_EDAT_HEADER_FIELDS["STRUCTURE_UNPACK"], head_bytes)
    ## --> Debug print all
    if function_debug_level >= 2:
        dprintBytesStructure(CONST_EDAT_HEADER_FIELDS, CONST_EDAT_HEADER_ENDIAN, temp_fields, "EDAT/SDAT Header[{:2}]: [{:#04x}|{:2}] {} = {}", function_debug_level)

    ## Convert to dictionary (associative array)
    header_fields = convertFieldsToOrdDict(CONST_EDAT_HEADER_FIELDS, temp_fields)
    del temp_fields

    ## Check header version
    if header_fields["VERSION"] > 4:
        eprint("EDAT/SDAT Version {}".format(header_fields["LICENSE"]), prefix="[UNKNOWN] ")
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")

    ## Determine debug edat
    header_fields["DEBUG_PKG"] = (header_fields["FLAGS"] & 0x80000000) != 0

    ## Check license type for EDAT/SDAT
    if header_fields["FLAGS"] & CONST_EDAT_SDAT_FLAG:
        if header_fields["LICENSE"] != 0:
            eprint("SDAT License Type {}".format(header_fields["LICENSE"]), prefix="[UNKNOWN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")
    else:
        if header_fields["LICENSE"] == 0:
            eprint("EDAT License Type {} is for SDAT".format(header_fields["LICENSE"]), prefix="[UNKNOWN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")
        elif header_fields["LICENSE"] > 3:
            eprint("EDAT License Type {}".format(header_fields["LICENSE"]), prefix="[UNKNOWN] ")
            eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")

    ## Debug print results
    dprint(">>>>> parseEdatHeader results:")
    dprintFieldsDict(header_fields, "edatheaderfields[{KEY:15}|{INDEX:2}]", function_debug_level, None)

    return header_fields


def checkEdatHeader(header_fields, header_bytes, results, function_debug_level):
    ## Determine EDAT/SDAT
    if header_fields["FLAGS"] & CONST_EDAT_SDAT_FLAG:
        results["EDAT_TYPE"] = "SDAT"
    else:
        results["EDAT_TYPE"] = "EDAT"

    ## Verify header data ECDSA signature (prerequisite for DevKlic/RAP/RIF verification)
    ## --> Signature
    size = CONST_ECDSA_VSH_CURVES[CONST_ECDSA_VSH_PUBKEYS[0]["CURVE"]]["SIZE"]
    signature_r = int.from_bytes(header_fields["EXT_HDR_ECDSA"][:size], byteorder="big")
    signature_s = int.from_bytes(header_fields["EXT_HDR_ECDSA"][size:], byteorder="big")
    del size
    signature = ecdsa.ecdsa.Signature(signature_r, signature_s)
    del signature_s
    del signature_r
    ## --> sha1
    ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
    sha1 = Cryptodome.Hash.SHA1.new(bytes(header_bytes[:header_fields["STRUCTURE_DEF"]["EXT_HDR_ECDSA"]["OFFSET"]])).digest()
    sha1_int = int.from_bytes(sha1, byteorder="big")
    del sha1
    ## --> verify
    results["EXT_HDR_ECDSA"] = CONST_ECDSA_VSH_PUBKEYS[0]["PUBKEY"].verifies(sha1_int, signature)
    del sha1_int
    del signature
    #
    if not results["EXT_HDR_ECDSA"]:
        eprint("ECDSA verification failed for EDAT/SDAT Extended Header.", end="")
        if Raps:
            eprint(" RAP/RIF verification not trustworthy.", end="", prefix=None)
        if Arguments.devklickey:
            eprint(" Dev KLicensee verification not trustworthy.", end="", prefix=None)
        eprint(prefix=None)
        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")

    ## Check CMAC hash of (main) header (Dev KLicensee Key verification)
    results["HEADER_HASH"] = False
    buffer = header_bytes[:header_fields["STRUCTURE_DEF"]["HEADER_HASH"]["OFFSET"]]
    #
    for key_number, klicensee in CONST_KLICENSEE_KEYS.items():
        if key_number == 0:
            continue
        #
        key = bytearray(klicensee["KEY"])
        fastxor.fast_xor_inplace(key, bytearray(CONST_KLICENSEE_KEYS[2]["KEY"]))
        #
        ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
        hash = newCMAC(bytes(key))
        hash.update(bytes(buffer))
        #
        if getCMACDigest(hash) == header_fields["HEADER_HASH"]:
            results["HEADER_HASH"] = True
            results["DEV_KLICENSEE_KEY"] = klicensee["KEY"]
            break  ## found valid Dev KLicensee key
    del buffer
    #
    if Arguments.devklickey \
    and not "DEV_KLICENSEE_KEY" in results:
        results["DEV_KLICENSEE_KEY"] = False

    ## Select SDAT/EDAT key for license
    header_fields["KEY"] = None
    if header_fields["LICENSE"] == 0:  ## Type 0: Use header hash (SDAT)
        results["RAP_VERIFY"] = "NOT REQUIRED"
        header_fields["KEY"] = {}
        header_fields["KEY"][0] = {}
        header_fields["KEY"][0]["TYPE"] = "Header Hash"
        header_fields["KEY"][0]["RIFKEY"] = bytearray(header_fields["HEADER_HASH"])
        fastxor.fast_xor_inplace(header_fields["KEY"][0]["RIFKEY"], bytearray(CONST_SDAT_KEYS[0]["KEY"]))
    elif header_fields["LICENSE"] == 1 \
    or header_fields["LICENSE"] == 2:  ## Types 1/2: Use RIF key
        if Raps:
            results["RAP_VERIFY"] = None
            header_fields["KEY"] = Raps
        else:
            eprint("EDAT License Type {} needs a RAP/RIF key!".format(header_fields["LICENSE"]))
    elif header_fields["LICENSE"] == 3:  ## Type 3: Use Dev Klicensee key
        results["RAP_VERIFY"] = "NOT REQUIRED"
        if "DEV_KLICENSEE_KEY" in results \
        and results["DEV_KLICENSEE_KEY"] != False:
            header_fields["KEY"] = {}
            header_fields["KEY"][0] = {}
            header_fields["KEY"][0]["TYPE"] = "Dev KLicensee Key"
            header_fields["KEY"][0]["RIFKEY"] = results["DEV_KLICENSEE_KEY"]
        else:
            eprint("EDAT License Type {} needs a Dev KLicensee key!".format(header_fields["LICENSE"]))

    ## Check CMAC hash of extended header (DevKLicensee/RIF/RAP verification)
    if not header_fields["KEY"] is None:
        results["EXT_HDR_HASH"] = False
        buffer = header_bytes[:header_fields["STRUCTURE_DEF"]["EXT_HDR_HASH"]["OFFSET"]]
        #
        decrypt_key = None
        if header_fields["FLAGS"] & CONST_EDAT_ENCRYPTED_KEY:  ## Encrypted CMAC key
            if header_fields["VERSION"] >= 4:
                decrypt_key = CONST_EDAT_KEYS[1]["KEY"]
            else:
                decrypt_key = CONST_EDAT_KEYS[0]["KEY"]
        #
        for key_number, key in header_fields["KEY"].items():
            ## Determine CMAC hash key
            if not decrypt_key is None:
                key_aes = Cryptodome.Cipher.AES.new(decrypt_key, Cryptodome.Cipher.AES.MODE_CBC, iv=CONST_AES_EMPTY_IV)
                ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
                hash_key = bytes(key_aes.decrypt(key["RIFKEY"]))
                del key_aes
            else:
                hash_key = key["RIFKEY"]
            #
            ## Python 2 workaround: must use bytes() for AES's .new()/.encrypt()/.decrypt() and hash's .update()
            hash = newCMAC(hash_key)
            hash.update(bytes(buffer))
            #
            if getCMACDigest(hash) == header_fields["EXT_HDR_HASH"]:
                results["EXT_HDR_HASH"] = True
                results["RIF_KEY_TYPE"] = key["TYPE"]
                results["RIF_KEY"] = key["RIFKEY"]
                if results["RAP_VERIFY"] is None:
                    results["RAP_VERIFY"] = key["RAPKEY"]
                    break  ## found valid RIF/RAP key
        del decrypt_key
        del buffer
        #
        if results["RAP_VERIFY"] is None \
        and Raps:
            results["RAP_VERIFY"] = False

    ## Debug print results
    if function_debug_level >= 1:
        dprint(">>>>> checkEdatHeader results:")
        dprint("checkedatheader[\"EDAT_TYPE\"]:", results["EDAT_TYPE"])
        dprint("checkedatheader[\"EXT_HDR_ECDSA\"]:", results["EXT_HDR_ECDSA"])
        dprint("checkedatheader[\"HEADER_HASH\"]:", results["HEADER_HASH"])
        if "DEV_KLICENSEE_KEY" in results:
            value = results["DEV_KLICENSEE_KEY"]
            if isinstance(value, bytes) \
            or isinstance(value, bytearray):
                value = convertBytesToHexString(value, sep="")
            dprint("checkedatheader[\"DEV_KLICENSEE_KEY\"]:", value)
        if "EXT_HDR_HASH" in results:
            dprint("checkedatheader[\"EXT_HDR_HASH\"]:", results["EXT_HDR_HASH"])
        if "RIF_KEY_TYPE" in results:
            dprint("checkedatheader[\"RIF_KEY_TYPE\"]:", results["RIF_KEY_TYPE"])
        if "RIF_KEY" in results:
            dprint("checkedatheader[\"RIF_KEY\"]:", convertBytesToHexString(results["RIF_KEY"], sep=""))
        if "RAP_VERIFY" in results:
            value = results["RAP_VERIFY"]
            if isinstance(value, bytes) \
            or isinstance(value, bytearray):
                value = convertBytesToHexString(value, sep="")
            dprint("checkedatheader[\"RAP_VERIFY\"]:", value)
            del value

    return


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
        dprint("Get PKG3 Items Info/Item Entries from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} and count {} and size {}+{}={}".format(items_info_bytes["OFS"], items_info_bytes["ALIGN"]["OFSDELTA"], header_fields["DATAOFS"], header_fields["DATAOFS"]+items_info_bytes["ALIGN"]["OFS"], header_fields["ITEMCNT"], items_info_bytes["SIZE"], items_info_bytes["ALIGN"]["SIZEDELTA"], items_info_bytes["ALIGN"]["SIZE"]))
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
        raise  ## re-raise

    ## Decrypt PKG3 Item Entries
    if header_fields["DEBUG_PKG"]:
        items_info_bytes[CONST_DATATYPE_DECRYPTED] = header_fields["XOR_CTR"].decrypt(items_info_bytes["ALIGN"]["OFS"], items_info_bytes[CONST_DATATYPE_AS_IS])
    else:
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
            print_exc_plus()
            return None, None
            #raise  ## re-raise
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
        if header_fields["DEBUG_PKG"]:
            items_info_bytes[CONST_DATATYPE_DECRYPTED][offset:offset+align["SIZE"]] = header_fields["XOR_CTR"].decrypt(align["OFS"], items_info_bytes[CONST_DATATYPE_AS_IS][offset:offset+align["SIZE"]])
        else:
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
    if function_debug_level >= 2:
        dprint(">>>>> parsePkg3ItemsInfo results:")
        dprintFieldsList(item_entries, "".join(("pkgitementries[{KEY:", item_cnt_len, "}]")), function_debug_level, None)

    return item_entries, items_info_bytes


def processPkg3Item(extractions_fields, item_entry, input_stream, item_data, size=None, extractions=None, function_debug_level=0):
    if function_debug_level >= 2:
        dprint(">>>>> PKG3 Body Item Entry #{} {}:".format(item_entry["INDEX"], item_entry["NAME"]))

    ## Prepare dictionaries
    item_data_usable = 0
    add_item_data = False
    if not item_data is None:
        if "ADD" in item_data \
        and item_data["ADD"]:
            add_item_data = True
            #
            if not CONST_DATATYPE_AS_IS in item_data:
                item_data[CONST_DATATYPE_AS_IS] = bytearray()
            if not CONST_DATATYPE_DECRYPTED in item_data:
                item_data[CONST_DATATYPE_DECRYPTED] = bytearray()
        #
        if CONST_DATATYPE_AS_IS in item_data:
            item_data_usable = len(item_data[CONST_DATATYPE_AS_IS])
    #
    if extractions:
        for key in extractions:
            extract = extractions[key]
            extract["ITEM_BYTES_WRITTEN"] = 0
        del extract
        del key

    ## Retrieve PKG3 Item Data from input stream
    if size is None:
        size = item_entry["DATASIZE"]
        align = item_entry["ALIGN"]
    else:
        align = calculateAesAlignedOffsetAndSize(item_entry["DATAOFS"], size)
    #
    if function_debug_level >= 2:
        dprint("Get PKG3 item data from encrypted data with offset {:#x}-{:#x}+{:#x}={:#x} and size {}{}+{}={}{}".format(item_entry["DATAOFS"], align["OFSDELTA"], extractions_fields["DATAOFS"], extractions_fields["DATAOFS"]+align["OFS"], size, "(/{})".format(item_entry["DATASIZE"]) if item_entry["DATASIZE"] != size else "", align["SIZEDELTA"], align["SIZE"], " (already read {})".format(item_data_usable) if item_data_usable > 0 else ""))
    #
    data_offset = align["OFS"]
    file_offset = extractions_fields["DATAOFS"] + data_offset
    rest_size = align["SIZE"]
    #
    encrypted_bytes = None
    decrypted_bytes = None
    block_data_ofs = align["OFSDELTA"]
    block_data_size_delta = 0
    while rest_size > 0:
        ## Calculate next data block
        if item_data_usable > 0:
            block_size = item_data_usable
        else:
            block_size = min(rest_size, CONST_READ_SIZE)
        #
        if rest_size <= block_size:  ## final block
            block_data_size_delta = align["SIZEDELTA"] - align["OFSDELTA"]
        #
        block_data_size = block_size - block_data_ofs - block_data_size_delta

        ## Get and process encrypted data block
        if item_data_usable > 0:
            encrypted_bytes = item_data[CONST_DATATYPE_AS_IS]
        else:
            ## Read encrypted data block
            try:
                encrypted_bytes = input_stream.read(file_offset, block_size, function_debug_level)
            except:
                input_stream.close(function_debug_level)
                eprint("Could not get PKG3 encrypted data at offset {:#x} with size {} from".format(extractions_fields["DATAOFS"]+align["OFS"], align["SIZE"]), input_stream.getSource())
                eprint("", prefix=None)
                raise  ## re-raise
            #
            if add_item_data:
                item_data[CONST_DATATYPE_AS_IS].extend(encrypted_bytes)
        #
        #if enc_hashes:
        #    hash encrypted_bytes

        ## Get and process decrypted data block
        if item_data_usable > 0:
            decrypted_bytes = item_data[CONST_DATATYPE_DECRYPTED]
        else:
            if extractions_fields["DEBUG_PKG"]:
                decrypted_bytes = extractions_fields["XOR_CTR"].decrypt(data_offset, encrypted_bytes)
            elif "KEYINDEX" in item_entry \
            and "AES_CTR" in extractions_fields:
                    decrypted_bytes = extractions_fields["AES_CTR"][item_entry["KEYINDEX"]].decrypt(data_offset, encrypted_bytes)
            #
            if add_item_data:
                item_data[CONST_DATATYPE_DECRYPTED].extend(decrypted_bytes)
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
        item_data_usable = 0
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


def retrieveParamSfo(package, results, input_stream, function_debug_level=0):
    if function_debug_level >= 1:
        dprint(">>>>> PARAM.SFO (from unencrypted data):")
    if function_debug_level >= 2:
        dprint("Get PARAM.SFO from unencrypted data with offset {:#x} with size {}".format(results["PKG_SFO_OFFSET"], results["PKG_SFO_SIZE"]), end=" ")

    sfo_bytes = bytearray()
    if len(package["HEAD_BYTES"]) >= (results["PKG_SFO_OFFSET"]+results["PKG_SFO_SIZE"]):
        if function_debug_level >= 2:
            dprint("from head data", prefix=None)
        sfo_bytes.extend(package["HEAD_BYTES"][results["PKG_SFO_OFFSET"]:results["PKG_SFO_OFFSET"]+results["PKG_SFO_SIZE"]])
    else:
        if function_debug_level >= 2:
            dprint("from input stream", prefix=None)
        try:
            sfo_bytes.extend(input_stream.read(results["PKG_SFO_OFFSET"], results["PKG_SFO_SIZE"], function_debug_level))
        except:
            input_stream.close(function_debug_level)
            eprint("Could not get PARAM.SFO at offset {:#x} with size {} from".format(results["PKG_SFO_OFFSET"], results["PKG_SFO_SIZE"]), input_stream.getSource())
            eprint("", prefix=None)
            raise  ## re-raise

    return sfo_bytes


def checkSfoMagic(sfo_magic, input_stream, function_debug_level=0):
    ## Check for known PARAM.SFO data
    if sfo_magic != CONST_PARAM_SFO_MAGIC:
        input_stream.close(function_debug_level)
        eprint("Not a known PARAM.SFO structure ({} <> {})".format(convertBytesToHexString(sfo_magic, sep=""), convertBytesToHexString(CONST_PARAM_SFO_MAGIC, sep="")), input_stream.getSource())
        eprint("", prefix=None)
        sys.exit(2)


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
    sfo_values["STRUCTURE_DEF"] = collections.OrderedDict()

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
        sfo_values["STRUCTURE_DEF"][key_name] = {}
        sfo_values["STRUCTURE_DEF"][key_name]["INDEX"] = _i
        data = sfo_bytes[header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]:header_fields["DATATBLOFS"]+temp_fields["DATAOFS"]+temp_fields["DATAUSEDSIZE"]]
        if function_debug_level >= 2:
            dprint(format_string.format(_i, "Key Name", key_name))
            data_desc = "Data Used (Fmt {:#0x})".format(temp_fields["DATAFORMAT"])
            dprint(format_string.format(_i, data_desc, convertBytesToHexString(data)))
        data_format = temp_fields["DATAFORMAT"]
        if data_format == 0x0004 \
        or data_format == 0x0204:  ## UTF-8 not and NUL-terminated
            data = convertUtf8BytesToString(data, data_format)
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
        elif data_format == 0x0404:
            data = getInteger32BitLE(data, 0x00)
            sfo_values["STRUCTURE_DEF"][key_name]["SIZE"] = 4
            sfo_values["STRUCTURE_DEF"][key_name]["HEXSIZE"] = 2 + (sfo_values["STRUCTURE_DEF"][key_name]["SIZE"]*2)
            sfo_values["STRUCTURE_DEF"][key_name]["BINSIZE"] = 2 + (sfo_values["STRUCTURE_DEF"][key_name]["SIZE"]*8)
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
        target = extract["TARGET"] = os.path.join(extract["ITEM_EXTRACT_ROOT"], extract["ITEM_EXTRACT_PATH"])
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
        eprint("[{}] Target file path already exists and is A DIRECTORY.".format(extract["KEY"]), extract["TARGET"] if quiet <= 1 else "")
    elif extract["TARGET_EXISTS"] \
    and not overwrite:
        result = 1
        eprint("[{}] Target file already exists and will *NOT* be overwritten.".format(extract["KEY"]), extract["TARGET"] if quiet <= 1 else "")
    else:
        result = 0

        if extract["TARGET_EXISTS"] \
        and overwrite \
        and function_debug_level >= 1:
            dprint("[{}] Target file already exists and will be OVERWRITTEN.".format(extract["KEY"]), extract["TARGET"] if quiet <= 1 else "")

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
    help_pathpattern = "For content style extraction to extract only paths that fit the regex pattern.\n\
  The pattern is checked against the full item name including directories."
    help_nosubdirs = "For content style extraction to avoid creation of subdirectories. Useful for pathpattern option."
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
    ## --> RAP
    help_rapkey = "To verify RAP key for EDAT file of PS3/PSX/PSP package."
    ## --> RIF
    help_rifkey = "To verify RIF key for EDAT file of PS3/PSX/PSP package."
    ## --> Dev Klicensee Key
    help_devklickey = "To verify Dev Klicensee Key for EDAT file of PS3/PSX/PSP package."
    ## --> Arcade
    help_arcade = "Use different key creation for debug packages of arcade systems."
    ## --> Unclean
    help_unclean = "".join(("Do not clean up international/english tile, except for condensing\n\
multiple white spaces incl. new line to a single space.\n\
Default is to clean up by replacing ", unicode(Replace_List), "\nand condensing demo information to just \"(DEMO)\"."))
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
    description = "%(prog)s {version}\n{copyright}\n{author}\n\
Extract package information and/or files from PS3/PSX/PSP/PSV/PSM and PS4 packages.".format(version=__version__, copyright=__copyright__, author=__author__)
    ## Create epilog
    epilog = "It is recommended to place \"--\" before the PKG/XML/JSON sources to avoid them being used as targets,\nthen wrong option usage like \"%(prog)s --raw -- 01.pkg 02.pkg\" will not overwrite \"01.pkg\".\n\
If you state URLs then only the necessary bytes are downloaded into memory.\nNote that the extract options download the complete(!) package just once\nwithout storing the original data on the file system."

    ## Build Arg Parser
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("source", metavar="SOURCE", nargs="+", help="Path or URL to PKG/XML/JSON file")
    parser.add_argument("--format", "-f", metavar="CODE", type=int, action="append", choices=choices_format, help=help_format)
    parser.add_argument("--raw", metavar="TARGETPATH", help=help_raw)
    parser.add_argument("--ux0", metavar="TOPDIR", help=help_ux0)
    parser.add_argument("--content", metavar="TOPDIR", help=help_content)
    parser.add_argument("--pathpattern", metavar="REGEX", help=help_pathpattern)
    parser.add_argument("--nosubdirs", action="store_true", help=help_nosubdirs)
    parser.add_argument("--overwrite", action="store_true", help=help_overwrite)
    parser.add_argument("--quiet", metavar="LEVEL", type=int, default=0, help=help_quiet)
    parser.add_argument("--zrif", metavar="LICENSE", action="append", help=help_zrif)
    parser.add_argument("--rapkey", metavar="RAPKEY", action="append", help=help_rapkey)
    parser.add_argument("--rifkey", metavar="RIFKEY", action="append", help=help_rifkey)
    parser.add_argument("--devklickey", metavar="DEVKLICKEY", action="append", help=help_devklickey)
    parser.add_argument("--arcade", action="store_true", help=help_arcade)
    parser.add_argument("--unclean", action="store_true", help=help_unclean)
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
        ## Global Debug [Verbosity] Level: can be set via '--debug='/'-d'
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
        finalizeBytesStructure(CONST_PKG3_MAIN_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Main Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:10} = {}", Debug_Level)
        ## --> PKG3 PS3 0x40 Digest
        finalizeBytesStructure(CONST_PKG3_PS3_DIGEST_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 PS3 0x40 Digest", "{}[{:1}]: ofs {:#04x} size {:2} key {:8} = {}", Debug_Level)
        ## --> PKG3 Extended Header
        finalizeBytesStructure(CONST_PKG3_EXT_HEADER_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Ext Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:12} = {}", Debug_Level)
        ## --> PKG3 Item Entry
        finalizeBytesStructure(CONST_PKG3_ITEM_ENTRY_FIELDS, CONST_PKG3_HEADER_ENDIAN, "PKG3 Item Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:12} = {}", Debug_Level)
        ## --> PKG4 Main Header
        finalizeBytesStructure(CONST_PKG4_MAIN_HEADER_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 Main Header", "{}[{:2}]: ofs {:#05x} size {:3} key {:12} = {}", Debug_Level)
        ## --> PKG4 Meta Entry
        finalizeBytesStructure(CONST_PKG4_META_ENTRY_FIELDS, CONST_PKG4_HEADER_ENDIAN, "PKG4 Meta Entry", "{}[{:1}]: ofs {:#04x} size {:1} key {:10} = {}", Debug_Level)
        ## --> PARAM.SFO Header
        finalizeBytesStructure(CONST_PARAM_SFO_HEADER_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Header", "{}[{:1}]: ofs {:#04x} size {:1} key {:10} = {}", Debug_Level)
        ## --> PARAM.SFO Index Entry
        finalizeBytesStructure(CONST_PARAM_SFO_INDEX_ENTRY_FIELDS, CONST_PARAM_SFO_ENDIAN, "SFO Index Entry", "{}[{:1}]: ofs {:#03x} size {:1} key {:12} = {}", Debug_Level)
        ## --> PBP Header
        finalizeBytesStructure(CONST_PBP_HEADER_FIELDS, CONST_PBP_HEADER_ENDIAN, "PBP Header", "{}[{:1}]: ofs {:#04x} size {:1} key {:13} = {}", Debug_Level)
        ## --> RIF PS3
        finalizeBytesStructure(CONST_PS3_RIF_FIELDS, CONST_PS3_RIF_ENDIAN, "PS3 RIF", "{}[{:2}]: ofs {:#05x} size {:2} key {:12} = {}", Debug_Level)
        ## --> RIF PSP/PSV
        finalizeBytesStructure(CONST_PSV_RIF_FIELDS, CONST_PSV_RIF_ENDIAN, "PSP/PSV RIF", "{}[{:2}]: ofs {:#05x} size {:3} key {:12} = {}", Debug_Level)
        ## --> RIF PSM
        finalizeBytesStructure(CONST_PSM_RIF_FIELDS, CONST_PSM_RIF_ENDIAN, "PSM RIF", "{}[{:2}]: ofs {:#05x} size {:3} key {:11} = {}", Debug_Level)
        ## --> EDAT/SDAT Header
        finalizeBytesStructure(CONST_EDAT_HEADER_FIELDS, CONST_EDAT_HEADER_ENDIAN, "EDAT/SDAT Header", "{}[{:2}]: ofs {:#04x} size {:2} key {:13} = {}", Debug_Level)

        ## Prepare RAP/RIF keys
        Raps = collections.OrderedDict()
        Rap_Number = 0
        Rap = None
        Rap_Bytes = None
        Rap_Size = None
        Rif_Number = 0
        ## --> RAP
        if Arguments.rapkey:
            for Rap in Arguments.rapkey:
                Rap_Number += 1
                if Debug_Level >= 3:
                    dprint(">>>>> EDAT RAP #{}:".format(Rap_Number), Rap)
                #
                Rap_Bytes = bytearray()
                #
                Rap_Size = len(Rap)
                if Rap_Size == (Cryptodome.Cipher.AES.block_size*2) \
                and not CONST_REGEX_HEX_DIGITS.match(Rap) is None:
                    if Debug_Level >= 3:
                        dprint("Assuming RAP hex digits")
                    Rap_Bytes.extend(bytes.fromhex(Rap))
                else:
                    if Debug_Level >= 3:
                        dprint("Assuming RAP binary file")
                    try:
                        Input_Stream = io.open(Rap, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    except:
                        eprint("[INPUT] Could not open RAP FILE", Rap)
                        eprint("", prefix=None)
                        raise  ## re-raise
                    #
                    Rap_Bytes.extend(Input_Stream.read())
                    Input_Stream.close()
                    del Input_Stream
                #
                Rap_Size = len(Rap_Bytes)
                if Debug_Level >= 3:
                    dprint(Rap_Size, convertBytesToHexString(Rap_Bytes, sep=""))
                #
                if Rap_Size != Cryptodome.Cipher.AES.block_size:
                    eprint("EDAT RAP #{}:".format(Rap_Number), "Invalid RAP size {}".format(Rap_Size))
                    eprint("Input:", Rap)
                    eprint("Bytes:", convertBytesToHexString(Rap_Bytes, sep=""))
                    continue
                #
                Raps[Rap_Number] = {}
                Raps[Rap_Number]["TYPE"] = "RAP"
                Raps[Rap_Number]["RAPKEY"] = bytes(Rap_Bytes)
                Raps[Rap_Number]["RIFKEY"] = convertRapkeyToRifkey(Raps[Rap_Number]["RAPKEY"])

                ## Output additional results
                if 50 in Arguments.format:  ## Additional debugging Output
                    print(">>>>> EDAT RAP #{}".format(Rap_Number))
                    dprintFieldsDict(Raps[Rap_Number], "rap[{KEY:8}]", 3, None, print_func=print, sep="")
        ## --> RIF Keys
        if Arguments.rifkey:
            for Rap in Arguments.rifkey:
                Rif_Number += 1
                Rap_Number += 1
                if Debug_Level >= 3:
                    dprint(">>>>> EDAT RIF/RAP #{}/{}:".format(Rif_Number, Rap_Number), Rap)
                #
                Rap_Bytes = bytearray()
                #
                Rap_Size = len(Rap)
                if Rap_Size == (Cryptodome.Cipher.AES.block_size*2) \
                and not CONST_REGEX_HEX_DIGITS.match(Rap) is None:
                    if Debug_Level >= 3:
                        dprint("Assuming RIF hex digits")
                    Rap_Bytes.extend(bytes.fromhex(Rap))
                else:
                    if Debug_Level >= 3:
                        dprint("Assuming RIF binary file")
                    try:
                        Input_Stream = io.open(Rap, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    except:
                        eprint("[INPUT] Could not open RIF FILE", Rap)
                        eprint("", prefix=None)
                        raise  ## re-raise
                    #
                    Rap_Bytes.extend(Input_Stream.read())
                    Input_Stream.close()
                    del Input_Stream
                #
                Rap_Size = len(Rap_Bytes)
                if Debug_Level >= 3:
                    dprint(Rap_Size, convertBytesToHexString(Rap_Bytes, sep=""))
                #
                if Rap_Size != Cryptodome.Cipher.AES.block_size:
                    eprint("EDAT RIF/RAP #{}/{}:".format(Rif_Number, Rap_Number), "Invalid RIF size {}".format(Rap_Size))
                    eprint("Input:", Rap)
                    eprint("Bytes:", convertBytesToHexString(Rap_Bytes, sep=""))
                    continue
                #
                Raps[Rap_Number] = {}
                Raps[Rap_Number]["TYPE"] = "RIF"
                Raps[Rap_Number]["RIFKEY"] = bytes(Rap_Bytes)
                Raps[Rap_Number]["RAPKEY"] = convertRifkeyToRapkey(Raps[Rap_Number]["RIFKEY"])

                ## Output additional results
                if 50 in Arguments.format:  ## Additional debugging Output
                    print(">>>>> EDAT RIF/RAP #{}/{}".format(Rif_Number, Rap_Number))
                    dprintFieldsDict(Raps[Rap_Number], "rif[{KEY:8}]", 3, None, print_func=print, sep="")
        #
        del Rif_Number
        del Rap_Size
        del Rap_Bytes
        del Rap
        del Rap_Number

        ## Prepare Dev KLicensee keys
        if Arguments.devklickey:
            Klic_Number = len(CONST_KLICENSEE_KEYS) - 1
            Klic = None
            Klic_Bytes = None
            Klic_Size = None
            for Klic in Arguments.devklickey:
                Klic_Number += 1
                if Debug_Level >= 3:
                    dprint(">>>>> EDAT Dev KLicensee Key #{}:".format(Klic_Number), Klic)
                #
                Klic_Bytes = bytearray()
                #
                Klic_Size = len(Klic)
                if Klic_Size == (Cryptodome.Cipher.AES.block_size*2) \
                and not CONST_REGEX_HEX_DIGITS.match(Klic) is None:
                    if Debug_Level >= 3:
                        dprint("Assuming Dev KLicensee Key hex digits")
                    Klic_Bytes.extend(bytes.fromhex(Klic))
                else:
                    if Debug_Level >= 3:
                        dprint("Assuming Dev KLicensee Key binary file")
                    try:
                        Input_Stream = io.open(Klic, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                    except:
                        eprint("[INPUT] Could not open Dev KLicensee Key file", Klic)
                        eprint("", prefix=None)
                        raise  ## re-raise
                    #
                    Klic_Bytes.extend(Input_Stream.read())
                    Input_Stream.close()
                    del Input_Stream
                #
                Klic_Size = len(Klic_Bytes)
                if Debug_Level >= 3:
                    dprint(Klic_Size, convertBytesToHexString(Klic_Bytes, sep=""))
                #
                if Klic_Size != Cryptodome.Cipher.AES.block_size:
                    eprint("EDAT Dev KLicensee Key #{}:".format(Klic_Number), "Invalid Dev KLicensee Key size {}".format(Klic_Size))
                    eprint("Input:", Klic)
                    eprint("Bytes:", convertBytesToHexString(Klic_Bytes, sep=""))
                    continue
                #
                CONST_KLICENSEE_KEYS[Klic_Number] = {}
                CONST_KLICENSEE_KEYS[Klic_Number]["DESC"] = "From command line"
                CONST_KLICENSEE_KEYS[Klic_Number]["KEY"] = bytes(Klic_Bytes)
            #
            del Klic_Size
            del Klic_Bytes
            del Klic
            del Klic_Number

        ## Prepare ZRIF licenses
        Rifs = collections.OrderedDict()
        if Zrif_Support and Arguments.zrif:
            Rif_Number = 0
            #
            Zrif = None
            Rif_Bytes = None
            Rif_Size = None
            Temp_Fields = None
            Rif_Fields = None
            Key = None
            for Zrif in Arguments.zrif:
                Rif_Number += 1
                if Debug_Level >= 3:
                    dprint(">>>>> zRIF #{}:".format(Rif_Number), Zrif)
                #
                Rif_Bytes = bytearray()
                #
                if Zrif.startswith("KO"):
                    Zrif_Bytes = bytes(base64.b64decode(Zrif.encode("ascii")))
                    if Debug_Level >= 3:
                        dprint(len(Zrif_Bytes), convertBytesToHexString(Zrif_Bytes, sep=""))
                    #
                    Decompress_Object = zlib.decompressobj(wbits=10, zdict=bytes(CONST_ZRIF_COMPRESSION_DICTIONARY))
                    Rif_Bytes.extend(Decompress_Object.decompress(Zrif_Bytes))
                    Rif_Bytes.extend(Decompress_Object.flush())
                    #
                    del Decompress_Object
                    del Zrif_Bytes
                else:
                    Rif_Bytes.extend(bytes.fromhex(Zrif))
                #
                Rif_Size = len(Rif_Bytes)
                if Debug_Level >= 3:
                    dprint(Rif_Size, convertBytesToHexString(Rif_Bytes, sep=""))
                #
                Temp_Fields = None
                Rif_Fields = None
                Rif_Type = getInteger16BitBE(Rif_Bytes, CONST_RIF_TYPE_OFFSET)
                if Rif_Type == 0:  ## PSM license
                    Temp_Fields = struct.unpack(CONST_PSM_RIF_FIELDS["STRUCTURE_UNPACK"], Rif_Bytes)
                    Rif_Fields = convertFieldsToOrdDict(CONST_PSM_RIF_FIELDS, Temp_Fields)
                    Rif_Fields["LIC_TYPE"] = "PSM license type"
                    #
                    if Rif_Fields["AID"] == CONST_RIF_FAKE_AID:
                        Rif_Fields["LIC_TYPE"] = " / ".join((Rif_Fields["LIC_TYPE"], "NoPsmDrm fake"))
                    else:
                        Rif_Fields["LIC_TYPE"] = " / ".join((Rif_Fields["LIC_TYPE"], "*NOT* a fake"))
                elif Rif_Type == 1:  ## PS3/PSP/PSV license
                    if Rif_Size == CONST_PS3_RIF_FIELDS["STRUCTURE_SIZE"]:
                        Temp_Fields = struct.unpack(CONST_PS3_RIF_FIELDS["STRUCTURE_UNPACK"], Rif_Bytes)
                        Rif_Fields = convertFieldsToOrdDict(CONST_PS3_RIF_FIELDS, Temp_Fields)
                        Rif_Fields["LIC_TYPE"] = "PS3 license type"
                    elif Rif_Size == CONST_PSV_RIF_FIELDS["STRUCTURE_SIZE"]:
                        Temp_Fields = struct.unpack(CONST_PSV_RIF_FIELDS["STRUCTURE_UNPACK"], Rif_Bytes)
                        Rif_Fields = convertFieldsToOrdDict(CONST_PSV_RIF_FIELDS, Temp_Fields)
                        Rif_Fields["LIC_TYPE"] = "PSP/PSV license type"
                    else:
                        eprint("zRIF #{}:".format(Rif_Number), "Unknown RIF size {} for type {:#06x}".format(Rif_Size, Rif_Type))
                        eprint("Input:", Zrif)
                        eprint("Bytes:", convertBytesToHexString(Rif_Bytes, sep=""))
                        continue
                    #
                    if Rif_Fields["AID"] == CONST_RIF_FAKE_AID:
                        Rif_Fields["LIC_TYPE"] = " / ".join((Rif_Fields["LIC_TYPE"], "NoNpDrm fake"))
                    else:
                        Rif_Fields["LIC_TYPE"] = " / ".join((Rif_Fields["LIC_TYPE"], "*NOT* a fake"))
                else:
                    eprint("zRIF #{}:".format(Rif_Number), "Unknown RIF type {:#06x} with size {}".format(Rif_Type, Rif_Size))
                    eprint("Input:", Zrif)
                    eprint("Bytes:", convertBytesToHexString(Rif_Bytes, sep=""))
                    continue
                #
                Key = Rif_Fields["CONTENT_ID"]
                Rifs[Key] = Rif_Fields
                Rifs[Key]["BYTES"] = Rif_Bytes

                ## Output additional results
                if 50 in Arguments.format:  ## Additional debugging Output
                    print(">>>>> RIF #{} \"{}\" ({})".format(Rif_Number, Key, Rif_Fields["LIC_TYPE"]))
                    dprintFieldsDict(Rif_Fields, "rif[{KEY:8}]", 3, None, print_func=print)
            #
            del Key
            del Temp_Fields
            del Rif_Fields
            del Rif_Size
            del Rif_Bytes
            del Zrif
            del Rif_Number

        ## Process paths and URLs
        for Source in Arguments.source:
            ## Special cases
            if Source == "dummy":
                continue

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
            Pkg_Sfo_Values = None
            Pkg_Item_Entries = None
            Pkg_Meta_Table = None
            Pkg_Meta_Table_Map = None
            Item_Sfo_Values = None
            Pbp_Header = None
            Pbp_Item_Entries = None
            Pbp_Sfo_Values = None
            Nps_Type = "UNKNOWN"
            #
            Main_Sfo_Values = None
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
            try:
                Input_Stream = PkgInputReader(Source, function_debug_level=max(0, Debug_Level))
            except requests.exceptions.HTTPError:
                continue
            Results["FILE_SIZE"] = Input_Stream.getSize(function_debug_level=max(0, Debug_Level))
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
                Package["HEAD_BYTES"].extend(Input_Stream.read(0, 4, function_debug_level=max(0, Debug_Level)))
            except:
                Input_Stream.close(function_debug_level=max(0, Debug_Level))
                eprint("Could not get PKG magic at offset {:#x} with size {} from".format(0, 4), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                eprint("", prefix=None)
                raise  ## re-raise
            Pkg_Magic = Package["HEAD_BYTES"][0:4]
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
            ## --> EDAT/SDAT (NPD)
            elif Pkg_Magic == CONST_EDAT_MAGIC:
                Header_Size = CONST_EDAT_HEADER_FIELDS["STRUCTURE_SIZE"]
                dprint("Detected EDAT/SDAT (NPD)")
            else:
                Input_Stream.close(function_debug_level=max(0, Debug_Level))
                eprint("Not a known PKG/PBP file ({} <> {}|{}|{})".format(convertBytesToHexString(Pkg_Magic, sep=""), convertBytesToHexString(CONST_PKG3_MAGIC, sep=""), convertBytesToHexString(CONST_PKG4_MAGIC, sep=""), convertBytesToHexString(CONST_PBP_MAGIC, sep="")), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                eprint("", prefix=None)
                sys.exit(2)

            ## Get rest of PKG main header from input stream
            if Debug_Level >= 2:
                dprint("Get main header from offset {:#x} with size {}".format(0, Header_Size))
            try:
                Package["HEAD_BYTES"].extend(Input_Stream.read(4, Header_Size-4, function_debug_level=max(0, Debug_Level)))
            except:
                Input_Stream.close(function_debug_level=max(0, Debug_Level))
                eprint("Could not get rest of main header at offset {:#x} with size {} from".format(4, Header_Size-4), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                eprint("", prefix=None)
                raise  ## re-raise

            ## Process PKG main header data
            ## --> PKG3
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Package["ITEMS_INFO_BYTES"] = {}
                Package["ITEM_BYTES"] = {}
                #
                Pkg_Header, Pkg_Ext_Header, Pkg_Meta_Data, Package["HEAD_BYTES"] = parsePkg3Header(Package["HEAD_BYTES"], Input_Stream, max(0, Debug_Level))
                ## --> Size of package (=file size)
                if "TOTALSIZE" in Pkg_Header:
                    Results["PKG_TOTAL_SIZE"] = Pkg_Header["TOTALSIZE"]
                ## --> Package content id
                if "CONTENT_ID" in Pkg_Header:
                    Results["PKG_CONTENT_ID"] = Pkg_Header["CONTENT_ID"]
                    Results["PKG_CID_TITLE_ID1"] = Results["PKG_CONTENT_ID"][7:16]
                    Results["PKG_CID_TITLE_ID2"] = Results["PKG_CONTENT_ID"][20:]
                ## --> PARAM.SFO offset + size
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
                        eprint("Items Info start offset inside encrypted data {:#0x} <> 0x0.".format(Pkg_Meta_Data[0x0D]["OFS"]), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)), prefix="[UNKNOWN] ")
                        eprint("Please report this unknown case at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")
                    ## b) size
                    if Pkg_Meta_Data[0x0D]["SIZE"] < (Pkg_Header["ITEMCNT"]*CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]):
                        eprint("Items Info size {} from meta data 0x0D is too small for {} Item Entries with total size of {}.".format(Pkg_Meta_Data[0x0D]["SIZE"], Pkg_Header["ITEMCNT"], Pkg_Header["ITEMCNT"]*CONST_PKG3_ITEM_ENTRY_FIELDS["STRUCTURE_SIZE"]), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                        eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
                ## Retrieve PKG3 PARAM.SFO from unencrypted data if present
                if "PKG_SFO_OFFSET" in Results \
                and Results["PKG_SFO_OFFSET"] > 0:
                    Sfo_Bytes = retrieveParamSfo(Package, Results, Input_Stream, function_debug_level=max(0, Debug_Level))
                    ## Process PARAM.SFO if present
                    if Sfo_Bytes:
                        ## Check for known PARAM.SFO data
                        checkSfoMagic(Sfo_Bytes[0:4], Input_Stream, function_debug_level=max(0, Debug_Level))
                        ## Process PARAM.SFO data
                        Pkg_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                    del Sfo_Bytes
                ## Process PKG3 encrypted item entries
                if not Pkg_Header["KEYINDEX"] is None:
                    Pkg_Item_Entries, Package["ITEMS_INFO_BYTES"] = parsePkg3ItemsInfo(Pkg_Header, Pkg_Meta_Data, Input_Stream, max(0, Debug_Level))
                    #
                    if not Pkg_Item_Entries is None:
                        Results["ITEMS_INFO"] = copy.copy(Package["ITEMS_INFO_BYTES"])
                        if CONST_DATATYPE_AS_IS in Results["ITEMS_INFO"]:
                            del Results["ITEMS_INFO"][CONST_DATATYPE_AS_IS]
                        if CONST_DATATYPE_DECRYPTED in Results["ITEMS_INFO"]:
                            del Results["ITEMS_INFO"][CONST_DATATYPE_DECRYPTED]
                #
                Results["DEBUG_PKG"] = Pkg_Header["DEBUG_PKG"]
                #
                if not Pkg_Item_Entries is None:
                    ## Search PARAM.SFO in encrypted data
                    Retrieve_Encrypted_Param_Sfo = False
                    if "PARAM.SFO" in Pkg_Header \
                    and Pkg_Header["PARAM.SFO"].strip():
                        Retrieve_Encrypted_Param_Sfo = True
                    #
                    Item_Entry = None
                    for Item_Entry in Pkg_Item_Entries:
                        if not "NAME" in Item_Entry \
                        or Item_Entry["DATASIZE"] <= 0:
                            continue
                        #
                        Item_Index = Item_Entry["INDEX"]
                        #
                        if Retrieve_Encrypted_Param_Sfo \
                        and Item_Entry["NAME"] == Pkg_Header["PARAM.SFO"]:
                            ## Retrieve PARAM.SFO
                            if Debug_Level >= 1:
                                dprint(">>>>> {} (from encrypted data):".format(Item_Entry["NAME"]))
                            Package["ITEM_BYTES"][Item_Index] = {}
                            Package["ITEM_BYTES"][Item_Index]["ADD"] = True
                            processPkg3Item(Pkg_Header, Item_Entry, Input_Stream, Package["ITEM_BYTES"][Item_Index], function_debug_level=max(0, Debug_Level))
                            del Package["ITEM_BYTES"][Item_Index]["ADD"]
                            ## Process PARAM.SFO
                            Sfo_Bytes = Package["ITEM_BYTES"][Item_Index][CONST_DATATYPE_DECRYPTED][Item_Entry["ALIGN"]["OFSDELTA"]:Item_Entry["ALIGN"]["OFSDELTA"]+Item_Entry["DATASIZE"]]
                            ## --> Check for known PARAM.SFO data
                            checkSfoMagic(Sfo_Bytes[0:4], Input_Stream, function_debug_level=max(0, Debug_Level))
                            ## --> Process PARAM.SFO data
                            Item_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                            del Sfo_Bytes
                        elif CONST_REGEX_PBP_SUFFIX.search(Item_Entry["NAME"]):
                            ## Retrieve PBP header
                            if Debug_Level >= 1:
                                dprint(">>>>> {} (from encrypted data):".format(Item_Entry["NAME"]))
                            Package["ITEM_BYTES"][Item_Index] = {}
                            Package["ITEM_BYTES"][Item_Index]["ADD"] = True
                            processPkg3Item(Pkg_Header, Item_Entry, Input_Stream, Package["ITEM_BYTES"][Item_Index], size=min(2048, Item_Entry["DATASIZE"]), function_debug_level=max(0, Debug_Level))
                            ## Process PBP header
                            Pbp_Bytes = Package["ITEM_BYTES"][Item_Index][CONST_DATATYPE_DECRYPTED][Item_Entry["ALIGN"]["OFSDELTA"]:Item_Entry["ALIGN"]["OFSDELTA"]+CONST_PBP_HEADER_FIELDS["STRUCTURE_SIZE"]]
                            Pbp_Header, Pbp_Item_Entries = parsePbpHeader(Pbp_Bytes, None, Item_Entry["DATASIZE"], function_debug_level=max(0, Debug_Level))
                            del Pbp_Bytes
                            ## Retrieve PBP PARAM.SFO
                            if Debug_Level >= 1:
                                dprint(">>>>> PARAM.SFO (from PBP):")
                            processPkg3Item(Pkg_Header, Item_Entry, Input_Stream, Package["ITEM_BYTES"][Item_Index], size=Pbp_Header["ICON0_PNG_OFS"], function_debug_level=max(0, Debug_Level))
                            del Package["ITEM_BYTES"][Item_Index]["ADD"]
                            ## Process PARAM.SFO
                            Sfo_Bytes = Package["ITEM_BYTES"][Item_Index][CONST_DATATYPE_DECRYPTED][Item_Entry["ALIGN"]["OFSDELTA"]+Pbp_Item_Entries[0]["DATAOFS"]:Item_Entry["ALIGN"]["OFSDELTA"]+Pbp_Item_Entries[0]["DATAOFS"]+Pbp_Item_Entries[0]["DATASIZE"]]
                            ## --> Check for known PARAM.SFO data
                            checkSfoMagic(Sfo_Bytes[0:4], Input_Stream, function_debug_level=max(0, Debug_Level))
                            ## --> Process PARAM.SFO data
                            Pbp_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                            del Sfo_Bytes
                        elif CONST_REGEX_EDAT_SUFFIX.search(Item_Entry["NAME"]):
                            ## Retrieve EDAT/SDAT header
                            if Debug_Level >= 1:
                                dprint(">>>>> {} (from encrypted data):".format(Item_Entry["NAME"]))
                            Package["ITEM_BYTES"][Item_Index] = {}
                            Package["ITEM_BYTES"][Item_Index]["ADD"] = True
                            processPkg3Item(Pkg_Header, Item_Entry, Input_Stream, Package["ITEM_BYTES"][Item_Index], size=min(CONST_EDAT_HEADER_FIELDS["STRUCTURE_SIZE"], Item_Entry["DATASIZE"]), function_debug_level=max(0, Debug_Level))
                            ## Process EDAT/SDAT header
                            Edat_Bytes = Package["ITEM_BYTES"][Item_Index][CONST_DATATYPE_DECRYPTED][Item_Entry["ALIGN"]["OFSDELTA"]:Item_Entry["ALIGN"]["OFSDELTA"]+CONST_EDAT_HEADER_FIELDS["STRUCTURE_SIZE"]]
                            Item_Entry["EDAT"] = parseEdatHeader(Edat_Bytes, function_debug_level=max(0, Debug_Level))
                            ## Check EDAT/SDAT header
                            if Arguments.rapkey \
                            or Arguments.rifkey \
                            or Arguments.devklickey:
                                Item_Entry["EDAT"]["RESULTS"] = {}
                                checkEdatHeader(Item_Entry["EDAT"], Edat_Bytes, Item_Entry["EDAT"]["RESULTS"], function_debug_level=max(0, Debug_Level))
                                #
                                if "DEV_KLICENSEE_KEY" in Item_Entry["EDAT"]["RESULTS"]:
                                    if not "DEV_KLICENSEE_KEY" in Results:
                                        Results["DEV_KLICENSEE_KEY"] = {}
                                    Results["DEV_KLICENSEE_KEY"][Item_Entry["EDAT"]["RESULTS"]["DEV_KLICENSEE_KEY"]] = True
                                if "RAP_VERIFY" in Item_Entry["EDAT"]["RESULTS"]:
                                    if not "RAP_VERIFY" in Results:
                                        Results["RAP_VERIFY"] = {}
                                    Results["RAP_VERIFY"][Item_Entry["EDAT"]["RESULTS"]["RAP_VERIFY"]] = True
                            #
                            del Edat_Bytes
                    del Item_Entry
                #
                if Pkg_Sfo_Values is None \
                and not Item_Sfo_Values is None:
                    Pkg_Sfo_Values = Item_Sfo_Values
                    Item_Sfo_Values = None
                Main_Sfo_Values = Pkg_Sfo_Values
                #
                if "DEV_KLICENSEE_KEY" in Results:
                    New_Dict = {}
                    Number = -1
                    for Key in Results["DEV_KLICENSEE_KEY"]:
                        Number += 1
                        New_Dict[Number] = Key
                    Results["DEV_KLICENSEE_KEY"] = New_Dict
                    del Number
                    del New_Dict
                #
                if "RAP_VERIFY" in Results:
                    New_Dict = {}
                    Number = -1
                    for Key in Results["RAP_VERIFY"]:
                        Number += 1
                        New_Dict[Number] = Key
                    Results["RAP_VERIFY"] = New_Dict
                    del Number
                    del New_Dict
                ## Get PKG3 unencrypted tail data
                if Debug_Level >= 2:
                    dprint(">>>>> PKG3 Tail:")
                    dprint("Get PKG3 unencrypted tail data from offset {:#x} with size {}".format(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"])))
                try:
                    Package["TAIL_BYTES"] = Input_Stream.read(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"]), function_debug_level=max(0, Debug_Level))
                except:
                    Input_Stream.close(function_debug_level=max(0, Debug_Level))
                    eprint("Could not get PKG3 unencrypted tail at offset {:#x} size {} from".format(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"], Pkg_Header["TOTALSIZE"]-(Pkg_Header["DATAOFS"]+Pkg_Header["DATASIZE"])), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                    eprint("", prefix=None)
                #
                if Package["TAIL_BYTES"]:  ## may not be present or have failed, e.g. when analyzing a head.bin file, a broken download or only thje first file of a multi-part package
                    Results["PKG_TAIL_SIZE"] = len(Package["TAIL_BYTES"])
                    Results["PKG_TAIL_SHA1"] = Package["TAIL_BYTES"][-0x20:-0x0c]
            ## <-- PKG3
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                Pkg_Header, Pkg_Meta_Table, Pkg_Meta_Table_Map = parsePkg4Header(Package["HEAD_BYTES"], Input_Stream, max(0, Debug_Level), print_unknown=Arguments.unknown)
                ## --> Size of package (=file size)
                if "PKGSIZE" in Pkg_Header:
                    Results["PKG_TOTAL_SIZE"] = Pkg_Header["PKGSIZE"]
                ## --> Package content id
                if "CONTENT_ID" in Pkg_Header:
                    Results["PKG_CONTENT_ID"] = Pkg_Header["CONTENT_ID"]
                    Results["PKG_CID_TITLE_ID1"] = Results["PKG_CONTENT_ID"][7:16]
                    Results["PKG_CID_TITLE_ID2"] = Results["PKG_CONTENT_ID"][20:]
                ## --> DRM Type
                if "DRMTYPE" in Pkg_Header:
                    Results["PKG_DRM_TYPE"] = Pkg_Header["DRMTYPE"]
                ## --> Content Type
                if "CONTTYPE" in Pkg_Header:
                    Results["PKG_CONTENT_TYPE"] = Pkg_Header["CONTTYPE"]
                ## --> PARAM.SFO offset + size
                if CONST_PKG4_META_ENTRY_ID_PARAM_SFO in Pkg_Meta_Table_Map:
                    Meta_Entry = Pkg_Meta_Table[Pkg_Meta_Table_Map[CONST_PKG4_META_ENTRY_ID_PARAM_SFO]]
                    Results["PKG_SFO_OFFSET"] = Meta_Entry["DATAOFS"]
                    Results["PKG_SFO_SIZE"] = Meta_Entry["DATASIZE"]
                    ## Retrieve PKG4 PARAM.SFO from unencrypted data
                    Sfo_Bytes = retrieveParamSfo(Package, Results, Input_Stream, function_debug_level=max(0, Debug_Level))
                    ## Process PARAM.SFO if present
                    if Sfo_Bytes:
                        ## Check for known PARAM.SFO data
                        checkSfoMagic(Sfo_Bytes[0:4], Input_Stream, function_debug_level=max(0, Debug_Level))
                        ## Process PARAM.SFO data
                        Pkg_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                    del Sfo_Bytes
                    #
                    Main_Sfo_Values = Pkg_Sfo_Values
            ## <-- PKG4
            ## --> PBP
            elif Pkg_Magic == CONST_PBP_MAGIC:
                Pbp_Header, Pbp_Item_Entries = parsePbpHeader(Package["HEAD_BYTES"], Input_Stream, Results["FILE_SIZE"], function_debug_level=max(0, Debug_Level))
                ## --> PARAM.SFO offset + size
                if len(Pbp_Item_Entries) >= 1 \
                and Pbp_Item_Entries[0]["DATASIZE"] > 0:
                    Results["PKG_SFO_OFFSET"] = Pbp_Item_Entries[0]["DATAOFS"]
                    Results["PKG_SFO_SIZE"] = Pbp_Item_Entries[0]["DATASIZE"]
                    ## Retrieve PBP PARAM.SFO from unencrypted data
                    Sfo_Bytes = retrieveParamSfo(Package, Results, Input_Stream, function_debug_level=max(0, Debug_Level))
                    ## Process PARAM.SFO if present
                    if Sfo_Bytes:
                        ## Check for known PARAM.SFO data
                        checkSfoMagic(Sfo_Bytes[0:4], Input_Stream, function_debug_level=max(0, Debug_Level))
                        ## Process PARAM.SFO data
                        Pbp_Sfo_Values = parseSfo(Sfo_Bytes, max(0, Debug_Level))
                    del Sfo_Bytes
                    #
                    Main_Sfo_Values = Pbp_Sfo_Values
            ## <-- PBP
            ## --> EDAT/SDAT (NPD)
            elif Pkg_Magic == CONST_EDAT_MAGIC:
                Pkg_Header = parseEdatHeader(Package["HEAD_BYTES"], function_debug_level=max(0, Debug_Level))
                ## --> Package content id
                if "CONTENT_ID" in Pkg_Header:
                    Results["PKG_CONTENT_ID"] = Pkg_Header["CONTENT_ID"]
                    Results["PKG_CID_TITLE_ID1"] = Results["PKG_CONTENT_ID"][7:16]
                    Results["PKG_CID_TITLE_ID2"] = Results["PKG_CONTENT_ID"][20:]
                ## --> DevKLicensee/RIF/RAP verification
                if Arguments.rapkey \
                or Arguments.rifkey \
                or Arguments.devklickey:
                    checkEdatHeader(Pkg_Header, Package["HEAD_BYTES"], Results, function_debug_level=max(0, Debug_Level))
                    #
                    if "DEV_KLICENSEE_KEY" in Results:
                        New_Dict = {}
                        New_Dict[0] = Results["DEV_KLICENSEE_KEY"]
                        Results["DEV_KLICENSEE_KEY"] = New_Dict
                        del New_Dict
                    #
                    if "RAP_VERIFY" in Results:
                        New_Dict = {}
                        New_Dict[0] = Results["RAP_VERIFY"]
                        Results["RAP_VERIFY"] = New_Dict
                        del New_Dict
            ## <-- EDAT/SDAT (NPD)
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

            ## Process main PARAM.SFO if present
            if not Main_Sfo_Values is None:
                ## -->
                if "DISC_ID" in Main_Sfo_Values:
                    Results["SFO_TITLE_ID"] = Main_Sfo_Values["DISC_ID"]
                if "TITLE_ID" in Main_Sfo_Values:
                    Results["SFO_TITLE_ID"] = Main_Sfo_Values["TITLE_ID"]
                    if "PKG_CID_TITLE_ID1" in Results \
                    and Main_Sfo_Values["TITLE_ID"] != Results["PKG_CID_TITLE_ID1"]:
                        Results["SFO_PKG_TID_DIFFER"] = True
                ## -->
                if "CONTENT_ID" in Main_Sfo_Values:
                    Results["SFO_CONTENT_ID"] = Main_Sfo_Values["CONTENT_ID"]
                    Results["SFO_CID_TITLE_ID1"] = Results["SFO_CONTENT_ID"][7:16]
                    Results["SFO_CID_TITLE_ID2"] = Results["SFO_CONTENT_ID"][20:]
                    if "PKG_CONTENT_ID" in Results \
                    and Main_Sfo_Values["CONTENT_ID"] != Results["PKG_CONTENT_ID"]:
                        Results["SFO_PKG_CID_DIFFER"] = True
                    if "TITLE_ID" in Main_Sfo_Values \
                    and Main_Sfo_Values["TITLE_ID"] != Results["SFO_CID_TITLE_ID1"]:
                        Results["SFO_TID_DIFFER"] = True
                ## -->
                if "CATEGORY" in Main_Sfo_Values:
                    Results["SFO_CATEGORY"] = Main_Sfo_Values["CATEGORY"]
                ## -->
                if "PUBTOOLINFO" in Main_Sfo_Values:
                    try:
                        Results["SFO_CREATION_DATE"] = Main_Sfo_Values["PUBTOOLINFO"][7:15]
                        Results["SFO_SDK_VER"] = int(Main_Sfo_Values["PUBTOOLINFO"][24:32]) / 1000000
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

            ## Determine some derived variables
            if Debug_Level >= 1:
                dprint(">>>>> Results:")
            ## a) Region and related languages
            if "CONTENT_ID" in Results \
            and Results["CONTENT_ID"].strip():
                Results["REGION"], Results["LANGUAGES"] = getRegion(Results["CONTENT_ID"][0])
                if Results["REGION"] == "???" \
                or Results["LANGUAGES"] is None:
                    if Arguments.unknown:
                        eprint("Region/Languages couldn't be determined for", Results["CONTENT_ID"], Input_Stream.getSource(function_debug_level=max(0, Debug_Level)), prefix="[UNKNOWN] ")
                        eprint("If not homebrew, then please report this unknown case at https://github.com/windsurfer1122/PSN_get_pkg_info", prefix="[UNKNOWN] ")
            ## b) International/English title
            for Language in ["01", "18"]:
                Key = "".join(("TITLE_", Language))
                if Main_Sfo_Values \
                and Key in Main_Sfo_Values \
                and Main_Sfo_Values[Key].strip():
                    if Debug_Level >= 2:
                        dprint("Set international name to", Key)
                    Results["SFO_TITLE"] = Main_Sfo_Values[Key].strip()
                    break
            if not "SFO_TITLE" in Results \
            and Main_Sfo_Values \
            and "TITLE" in Main_Sfo_Values \
            and Main_Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set international title to TITLE")
                Results["SFO_TITLE"] = Main_Sfo_Values["TITLE"].strip()
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
                    if Main_Sfo_Values \
                    and Key in Main_Sfo_Values \
                    and Main_Sfo_Values[Key].strip():
                        if Debug_Level >= 2:
                            dprint("Set regional title to", Key)
                        Results["SFO_TITLE_REGIONAL"] = Main_Sfo_Values[Key].strip()
                        break
            if not "SFO_TITLE_REGIONAL" in Results \
            and Main_Sfo_Values \
            and "TITLE" in Main_Sfo_Values \
            and Main_Sfo_Values["TITLE"].strip():
                if Debug_Level >= 2:
                    dprint("Set regional title to TITLE")
                Results["SFO_TITLE_REGIONAL"] = Main_Sfo_Values["TITLE"].strip()
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
            ## d) Determine platform and package type
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
                            if not "SFO_TITLE" in Results \
                            and 0x03 in Pkg_Meta_Data \
                            and Pkg_Meta_Data[0x03]["VALUE"] == bytes.fromhex("0000048c"):
                                for Item_Entry in Pkg_Item_Entries:
                                    if not "NAME" in Item_Entry \
                                    or Item_Entry["DATASIZE"] <= 0:
                                        continue
                                    #
                                    if Item_Entry["NAME"].endswith(".edat") \
                                    and not Item_Entry["NAME"].endswith(".p3t.edat"):
                                        Results["SFO_TITLE"] = " ".join((Results["TITLE_ID"], "- Unlock Key"))
                                        break
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Results["TITLE_UPDATE_URL"] = "https://a0.ww.np.dl.playstation.net/tpl/np/{0}/{0}-ver.xml".format(Results["TITLE_ID"].strip())
                    elif Results["PKG_CONTENT_TYPE"] == 0x5 \
                    or Results["PKG_CONTENT_TYPE"] == 0x13 \
                    or Results["PKG_CONTENT_TYPE"] == 0x14:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        if Results["PKG_CONTENT_TYPE"] == 0x14:
                            Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PSP_REMASTER
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
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
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                    elif Results["PKG_CONTENT_TYPE"] == 0xD:
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.AVATAR
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PS3 AVATAR"
                    elif Results["PKG_CONTENT_TYPE"] == 0x12:  ## PS2 /SFO_CATEGORY = 2P
                        Results["PLATFORM"] = CONST_PLATFORM.PS3
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        Results["PKG_SUB_TYPE"] = CONST_PKG_SUB_TYPE.PS2_CLASSIC
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
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
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("pspemu", "PSP", "GAME", Results["PKG_CID_TITLE_ID1"])
                        Results["PKG_EXTRACT_UX0_LIC_ROOT"] = os.path.join("pspemu", "PSP", "LICENSE")
                        Results["PKG_EXTRACT_UX0_LIC_FILE"] = os.path.join(Results["PKG_EXTRACT_UX0_LIC_ROOT"], "".join((Results["PKG_CONTENT_ID"], ".rif")))
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSX GAME"
                        #
                        ## Special Case: PCSC80018 "Pocketstation for PS Vita"
                        if Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
                            Results["PLATFORM"] = CONST_PLATFORM.PSV
                            Results["PKG_SUB_TYPE"] = CONST_PLATFORM.PSX
                            Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("ps1emu", Results["PKG_CID_TITLE_ID1"])
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
                        if Pbp_Sfo_Values \
                        and "CATEGORY" in Pbp_Sfo_Values:
                            if Pbp_Sfo_Values["CATEGORY"] == "PG":
                                Results["PKG_TYPE"] = CONST_PKG_TYPE.PATCH
                                Nps_Type = "PSP UPDATE"
                            elif Pbp_Sfo_Values["CATEGORY"] == "MG":
                                Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                                Nps_Type = "PSP DLC"
                        if not "PKG_TYPE" in Results:  ## Normally CATEGORY = EG
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                            Nps_Type = "PSP GAME"
                        #
                        ## TODO: Verify when ISO and when GAME directory has to be used?
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("pspemu", "PSP", "GAME", Results["PKG_CID_TITLE_ID1"])
                        if Results["PKG_TYPE"] != CONST_PKG_TYPE.PATCH:  ## Patches do not need a license file
                            Results["PKG_EXTRACT_UX0_LIC_ROOT"] = os.path.join("pspemu", "PSP", "LICENSE")
                            Results["PKG_EXTRACT_UX0_LIC_FILE"] = os.path.join(Results["PKG_EXTRACT_UX0_LIC_ROOT"], "".join((Results["PKG_CONTENT_ID"], ".rif")))
                        Results["PKG_EXTRACT_UX0_ISOR"] = os.path.join("pspemu", "ISO")
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
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
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
                            Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("patch", Results["CID_TITLE_ID1"])
                            Nps_Type = "PSV UPDATE"
                        else:
                            Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                            Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("app", Results["CID_TITLE_ID1"])
                            Nps_Type = "PSV GAME"
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                            del Update_Hash
                            #
                            Livearea_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[3]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Livearea_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["LIVEAREA_UPDATE_URL"] = "http://livearea.np.dl.playstation.net/livearea/e/info/np/{0}/{1}/{0}-0.pkg".format(Results["TITLE_ID"].strip(), Livearea_Hash.hexdigest())
                            del Livearea_Hash
                    elif Results["PKG_CONTENT_TYPE"] == 0x16:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                        #
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("addcont", Results["CID_TITLE_ID1"], Results["CID_TITLE_ID2"])
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSV DLC"
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                            del Update_Hash
                            #
                            Livearea_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Livearea_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["LIVEAREA_UPDATE_URL"] = "http://livearea.np.dl.playstation.net/livearea/e/info/np/{0}/{1}/{0}-0.pkg".format(Results["TITLE_ID"].strip(), Livearea_Hash.hexdigest())
                    elif Results["PKG_CONTENT_TYPE"] == 0x17:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.LIVEAREA
                        #
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("appmeta-ur0", Results["CID_TITLE_ID1"])
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        if "TITLE_ID" in Results \
                        and Results["TITLE_ID"].strip():
                            Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/pl/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                            del Update_Hash
                            #
                            Livearea_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[2]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                            Livearea_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                            Results["LIVEAREA_UPDATE_URL"] = "http://livearea.np.dl.playstation.net/livearea/e/info/np/{0}/{1}/{0}-0.pkg".format(Results["TITLE_ID"].strip(), Livearea_Hash.hexdigest())
                    elif Results["PKG_CONTENT_TYPE"] == 0x1F:
                        Results["PLATFORM"] = CONST_PLATFORM.PSV
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.THEME
                        #
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("theme", "-".join((Results["CID_TITLE_ID1"], Results["CID_TITLE_ID2"])))
                        ## TODO/FUTURE: bgdl
                        ## - find next free xxxxxxxx dir (hex 00000000-FFFFFFFF)
                        ##   Note that Vita has issues with handling more than 32 bgdls at once
                        ## - package sub dir is Results["PKG_CID_TITLE_ID1"] for Game/DLC/Theme
                        ## - create additional d0/d1.pdb and temp.dat files in root dir for Game/Theme
                        ## - create additional f0.pdb for DLC
                        #Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("bgdl", "t", "xxxxxx")
                        #, )))
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSV THEME"
                    ## --> PSM packages
                    elif Results["PKG_CONTENT_TYPE"] == 0x18 \
                    or Results["PKG_CONTENT_TYPE"] == 0x1D:
                        Results["PLATFORM"] = CONST_PLATFORM.PSM
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.GAME
                        #
                        Results["PKG_EXTRACT_UX0_ROOT"] = os.path.join("psm", Results["PKG_CID_TITLE_ID1"])
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
                        #
                        Nps_Type = "PSM GAME"
                    ## --> UNKNOWN packages
                    else:
                        eprint("PKG content type {0}/{0:#0x}.".format(Results["PKG_CONTENT_TYPE"]), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)), prefix="[UNKNOWN] ")
                        #
                        Results["PKG_EXTRACT_CNT_ROOT"] = Pkg_Header["CONTENT_ID"][7:]
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
                    #
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG4_UPDATE_KEYS[0]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                        Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/plo/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                        del Update_Hash
                elif Results["PKG_CONTENT_TYPE"] == 0x1B:
                    if "SFO_CATEGORY" in Results \
                    and Results["SFO_CATEGORY"] == "ac":
                        Results["PKG_TYPE"] = CONST_PKG_TYPE.DLC
                        Nps_Type = "PS4 DLC"
                    #
                    if "TITLE_ID" in Results \
                    and Results["TITLE_ID"].strip():
                        Update_Hash = Cryptodome.Hash.HMAC.new(CONST_PKG4_UPDATE_KEYS[0]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        Update_Hash.update("".join(("np_", Results["TITLE_ID"].strip())).encode("UTF-8"))
                        Results["TITLE_UPDATE_URL"] = "http://gs-sec.ww.np.dl.playstation.net/plo/np/{0}/{1}/{0}-ver.xml".format(Results["TITLE_ID"].strip(), Update_Hash.hexdigest())
                        del Update_Hash
            ## --> PBP
            elif Pkg_Magic == CONST_PBP_MAGIC:
                pass  ## TODO
                #
                Results["PKG_EXTRACT_CNT_ROOT"] = Results["TITLE_ID"]
            #
            Results["NPS_TYPE"] = Nps_Type
            ## e) Media/App/Firmware Version
            Sfo_Values = None
            for Sfo_Values in (Pbp_Sfo_Values, Item_Sfo_Values, Pkg_Sfo_Values):
                if Sfo_Values is None:
                    continue
                ## --> Media version
                if not "SFO_VERSION" in Results \
                and "DISC_VERSION" in Sfo_Values \
                and Sfo_Values["DISC_VERSION"]:
                    Results["SFO_VERSION"] = float(Sfo_Values["DISC_VERSION"])
                if not "SFO_VERSION" in Results \
                and "VERSION" in Sfo_Values \
                and Sfo_Values["VERSION"]:
                    Results["SFO_VERSION"] = float(Sfo_Values["VERSION"])
                ## --> Application version
                if not "SFO_APP_VER" in Results \
                and "APP_VER" in Sfo_Values \
                and Sfo_Values["APP_VER"]:
                    Results["SFO_APP_VER"] = float(Sfo_Values["APP_VER"])
                ## --> Firmware PS3
                if not "SFO_MIN_VER_PS3" in Results \
                and "PS3_SYSTEM_VER" in Sfo_Values \
                and Sfo_Values["PS3_SYSTEM_VER"]:
                    Results["SFO_MIN_VER_PS3"] = float(Sfo_Values["PS3_SYSTEM_VER"])
                ## --> Firmware PSP
                if not "SFO_MIN_VER_PSP" in Results \
                and "PSP_SYSTEM_VER" in Sfo_Values \
                and Sfo_Values["PSP_SYSTEM_VER"]:
                    Results["SFO_MIN_VER_PSP"] = float(Sfo_Values["PSP_SYSTEM_VER"])
                ## --> Firmware PS Vita
                if not "SFO_MIN_VER_PSV" in Results \
                and "PSP2_DISP_VER" in Sfo_Values \
                and Sfo_Values["PSP2_DISP_VER"]:
                    Results["SFO_MIN_VER_PSV"] = float(Sfo_Values["PSP2_DISP_VER"])
                ## --> Firmware PS4
                if not "SFO_MIN_VER_PS4" in Results \
                and "SYSTEM_VER" in Sfo_Values \
                and Sfo_Values["SYSTEM_VER"]:
                    Results["SFO_MIN_VER_PS4"] = float("{:02x}.{:02x}".format((Sfo_Values["SYSTEM_VER"] >> 24) & 0xff, (Sfo_Values["SYSTEM_VER"] >> 16) & 0xff))
            del Sfo_Values
            if not "SFO_APP_VER" in Results:
                Results["SFO_APP_VER"] = 0.0  ## mandatory value
            #
            Results["SFO_MIN_VER"] = 0.00  ## mandatory value
            if "PLATFORM" in Results:
                if Results["PLATFORM"] == CONST_PLATFORM.PS3:
                    if "SFO_MIN_VER_PS3" in Results:
                        Results["SFO_MIN_VER"] = Results["SFO_MIN_VER_PS3"]
                elif Results["PLATFORM"] == CONST_PLATFORM.PSP:
                    if "SFO_MIN_VER_PSP" in Results:
                        Results["SFO_MIN_VER"] = Results["SFO_MIN_VER_PSP"]
                elif Results["PLATFORM"] == CONST_PLATFORM.PSV:
                    if "SFO_MIN_VER_PSV" in Results:
                        Results["SFO_MIN_VER"] = Results["SFO_MIN_VER_PSV"]
                elif Results["PLATFORM"] == CONST_PLATFORM.PSV:
                    if "SFO_MIN_VER_PS4" in Results:
                        Results["SFO_MIN_VER"] = Results["SFO_MIN_VER_PS4"]

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
                    if "CONTENT_ID" in Results \
                    and Results["CONTENT_ID"].strip():
                        print("{:13} {}".format("Content ID:", Results["CONTENT_ID"]))
                        if "SFO_CONTENT_ID" in Results \
                        and Results["SFO_CONTENT_ID"].strip() \
                        and "PKG_CONTENT_ID" in Results \
                        and Results["PKG_CONTENT_ID"].strip() != Results["SFO_CONTENT_ID"].strip():
                            print("{:13} {}".format("PKG Hdr CID:", Results["PKG_CONTENT_ID"]))
                    if "DEBUG_PKG" in Results:
                        print("{:13} {}".format("Debug Pkg:", Results["DEBUG_PKG"]))
                    if "PKG_CONTENT_TYPE" in Results:
                        print("{:13} {}".format("Content Type:", Results["PKG_CONTENT_TYPE"]))
                    if "PKG_DRM_TYPE" in Results:
                        print("{:13} {}".format("DRM Type:", Results["PKG_DRM_TYPE"]))
                    if "SFO_MIN_VER" in Results \
                    and Results["SFO_MIN_VER"] >= 0:
                        print("{:13} {:.2f}".format("Min FW:", Results["SFO_MIN_VER"]))
                    if "SFO_SDK_VER" in Results \
                    and Results["SFO_SDK_VER"] >= 0:
                        print("{:13} {:.2f}".format("SDK Ver:", Results["SFO_SDK_VER"]))
                    if "SFO_CREATION_DATE" in Results \
                    and Results["SFO_CREATION_DATE"].strip():
                        print("{:13} {}".format("c_date:", datetime.datetime.strptime(Results["SFO_CREATION_DATE"], "%Y%m%d").strftime("%Y-%m-%d")))
                    if "SFO_VERSION" in Results\
                    and Results["SFO_VERSION"] >= 0:
                        print("{:13} {:.2f}".format("Version:", Results["SFO_VERSION"]))
                    if "SFO_APP_VER" in Results \
                    and Results["SFO_APP_VER"] >= 0:
                        print("{:13} {:.2f}".format("App Ver:", Results["SFO_APP_VER"]))
                    if "PSX_TITLE_ID" in Results \
                    and Results["PSX_TITLE_ID"].strip():
                        print("{:13} {}".format("PSX Title ID:", Results["PSX_TITLE_ID"]))
                    if "PKG_TOTAL_SIZE" in Results \
                    and Results["PKG_TOTAL_SIZE"] > 0:
                        print("{:13} {}".format("Size:", Results["PKG_TOTAL_SIZE"]))
                        print("{:13} {}".format("Pretty Size:", prettySize(Results["PKG_TOTAL_SIZE"])))
                    if "FILE_SIZE" in Results:
                        print("{:13} {}".format("File Size:", Results["FILE_SIZE"]))
                    if "TITLE_UPDATE_URL" in Results \
                    and Results["TITLE_UPDATE_URL"].strip():
                        print("{:13} {}".format("Update URL:", Results["TITLE_UPDATE_URL"]))
                    if "LIVEAREA_UPDATE_URL" in Results \
                    and Results["LIVEAREA_UPDATE_URL"].strip():
                        print("{:13} {}".format("Livearea URL:", Results["LIVEAREA_UPDATE_URL"]))
                    if "EDAT_TYPE" in Results:
                        print("{:13} {}".format("EDAT Type:", Results["EDAT_TYPE"]))
                    if "DEV_KLICENSEE_KEY" in Results:
                        for Key, Value in Results["DEV_KLICENSEE_KEY"].items():
                            if isinstance(Value, bytes) \
                            or isinstance(Value, bytearray):
                                Value = convertBytesToHexString(Value, sep="")
                            print("{:13} {}".format("Dev KLic Key:", Value))
                        del Value
                        del Key
                    if "RAP_VERIFY" in Results:
                        for Key, Value in Results["RAP_VERIFY"].items():
                            if isinstance(Value, bytes) \
                            or isinstance(Value, bytearray):
                                Value = convertBytesToHexString(Value, sep="")
                            print("{:13} {}".format("RAP Key:", Value))
                        del Value
                        del Key
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
                    if "DEBUG_PKG" in Results:
                        JSON_Output["results"]["debugPkg"] = Results["DEBUG_PKG"]
                    if "SFO_MIN_VER" in Results \
                    and Results["SFO_MIN_VER"] >= 0:
                        JSON_Output["results"]["minFw"] = Results["SFO_MIN_VER"]
                    if "SFO_MIN_VER_PS3" in Results \
                    and Results["SFO_MIN_VER_PS3"] >= 0:
                        JSON_Output["results"]["minFwPs3"] = Results["SFO_MIN_VER_PS3"]
                    if "SFO_MIN_VER_PSP" in Results \
                    and Results["SFO_MIN_VER_PSP"] >= 0:
                        JSON_Output["results"]["minFwPsp"] = Results["SFO_MIN_VER_PSP"]
                    if "SFO_MIN_VER_PSV" in Results \
                    and Results["SFO_MIN_VER_PSV"] >= 0:
                        JSON_Output["results"]["minFwPsv"] = Results["SFO_MIN_VER_PSV"]
                    if "SFO_MIN_VER_PS4" in Results \
                    and Results["SFO_MIN_VER_PS4"] >= 0:
                        JSON_Output["results"]["minFwPs4"] = Results["SFO_MIN_VER_PS4"]
                    if "SFO_SDK_VER" in Results \
                    and Results["SFO_SDK_VER"] >= 0:
                        JSON_Output["results"]["sdkVer"] = Results["SFO_SDK_VER"]
                    if "SFO_CREATION_DATE" in Results \
                    and Results["SFO_CREATION_DATE"].strip():
                        JSON_Output["results"]["creationDate"] = datetime.datetime.strptime(Results["SFO_CREATION_DATE"], "%Y%m%d").strftime("%Y-%m-%d")
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
                    if "LIVEAREA_UPDATE_URL" in Results \
                    and Results["LIVEAREA_UPDATE_URL"].strip():
                        JSON_Output["results"]["liveareaUpdateUrl"] = Results["LIVEAREA_UPDATE_URL"]
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
                                del JSON_Output["pkgParamSfo"]["STRUCTURE_DEF"]
                        if Pkg_Item_Entries:
                            JSON_Output["pkgItemEntries"] = copy.deepcopy(Pkg_Item_Entries)
                            for Item_Entry in JSON_Output["pkgItemEntries"]:
                                if "STRUCTURE_DEF" in Item_Entry:
                                    del Item_Entry["STRUCTURE_DEF"]
                                if "ALIGN" in Item_Entry:
                                    del Item_Entry["ALIGN"]
                                if "IS_FILE_OFS" in Item_Entry:
                                    del Item_Entry["IS_FILE_OFS"]
                        if Pkg_Meta_Table:
                            JSON_Output["pkgMetaTable"] = copy.deepcopy(Pkg_Meta_Table)
                            for Meta_Entry in JSON_Output["pkgMetaTable"]:
                                if "STRUCTURE_DEF" in Meta_Entry:
                                    del Meta_Entry["STRUCTURE_DEF"]
                        if Item_Sfo_Values:
                            JSON_Output["pkgItemSfo"] = copy.copy(Item_Sfo_Values)
                            if "STRUCTURE_DEF" in JSON_Output["pkgItemSfo"]:
                                del JSON_Output["pkgItemSfo"]["STRUCTURE_DEF"]
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
                        if Pbp_Sfo_Values:
                            JSON_Output["pbpParamSfo"] = copy.copy(Pbp_Sfo_Values)
                            if "STRUCTURE_DEF" in JSON_Output["pbpParamSfo"]:
                                del JSON_Output["pbpParamSfo"]["STRUCTURE_DEF"]
                    #
                    print(json.dumps(JSON_Output, ensure_ascii=False, indent=2, default=specialToJSON))
                    del JSON_Output
                elif Output_Format == 2 \
                or Output_Format == 99:  ## Results/Analysis Output
                    if Output_Format == 99:  ## Analysis Output
                        if Pkg_Header:
                            dprintFieldsDict(Pkg_Header, "Pkg_Header[{KEY:15}|{INDEX:2}]", 2, None, print_func=print)
                        if Pkg_Ext_Header:
                            dprintFieldsDict(Pkg_Ext_Header, "Pkg_Ext_Header[{KEY:14}|{INDEX:2}]", 2, None, print_func=print)
                        if Pkg_Meta_Data:
                            for Key in Pkg_Meta_Data:
                                if Key == "STRUCTURE_DEF":
                                    continue
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
                                        print(" Bytes", convertBytesToHexString(Pkg_Meta_Data[Key]["VALUE"], sep=""), end="")
                                    elif Pkg_Meta_Data["STRUCTURE_DEF"][Key] \
                                    and "HEXSIZE" in Pkg_Meta_Data["STRUCTURE_DEF"][Key]:
                                        print(" Value", "".join(("{0:#0", unicode(Pkg_Meta_Data["STRUCTURE_DEF"][Key]["HEXSIZE"]), "x} = {0}")).format(Pkg_Meta_Data[Key]["VALUE"]), end="")
                                    elif isinstance(Pkg_Meta_Data[Key]["VALUE"], int):
                                        print(" Value", "{0:#x} = {0}".format(Pkg_Meta_Data[Key]["VALUE"]), end="")
                                    else:
                                        print(" Value", Pkg_Meta_Data[Key]["VALUE"], end="")
                                if "FIRMWARE" in Pkg_Meta_Data[Key]:
                                    if isinstance(Pkg_Meta_Data[Key]["FIRMWARE"], bytes) \
                                    or isinstance(Pkg_Meta_Data[Key]["FIRMWARE"], bytearray):
                                        print(" Firmware", convertBytesToHexString(Pkg_Meta_Data[Key]["FIRMWARE"], sep=""), end="")
                                    else:
                                        print(" Firmware", "{:#x}".format(Pkg_Meta_Data[Key]["FIRMWARE"]), end="")
                                if "UNKNOWN" in Pkg_Meta_Data[Key]:
                                    if isinstance(Pkg_Meta_Data[Key]["UNKNOWN"], bytes) \
                                    or isinstance(Pkg_Meta_Data[Key]["UNKNOWN"], bytearray):
                                        print(" Unknown", convertBytesToHexString(Pkg_Meta_Data[Key]["UNKNOWN"], sep=""), end="")
                                    else:
                                        print(" Unknown", Pkg_Meta_Data[Key]["UNKNOWN"], end="")
                                if "UNKNOWN1" in Pkg_Meta_Data[Key]:
                                    if isinstance(Pkg_Meta_Data[Key]["UNKNOWN1"], bytes) \
                                    or isinstance(Pkg_Meta_Data[Key]["UNKNOWN1"], bytearray):
                                        print(" Unknown1", convertBytesToHexString(Pkg_Meta_Data[Key]["UNKNOWN1"], sep=""), end="")
                                    else:
                                        print(" Unknown1", Pkg_Meta_Data[Key]["UNKNOWN1"], end="")
                                if "UNKNOWN2" in Pkg_Meta_Data[Key]:
                                    if isinstance(Pkg_Meta_Data[Key]["UNKNOWN2"], bytes) \
                                    or isinstance(Pkg_Meta_Data[Key]["UNKNOWN2"], bytearray):
                                        print(" Unknown2", convertBytesToHexString(Pkg_Meta_Data[Key]["UNKNOWN2"], sep=""), end="")
                                    else:
                                        print(" Unknown2", Pkg_Meta_Data[Key]["UNKNOWN2"], end="")
                                print()
                        if Pkg_Sfo_Values:
                            dprintFieldsDict(Pkg_Sfo_Values, "Pkg_Sfo_Values[{KEY:20}]", 2, None, print_func=print)
                        if Pkg_Item_Entries:
                            Format_String = "".join(("{:", unicode(len(unicode(len(Pkg_Item_Entries)))), "}"))
                            for Item_Entry in Pkg_Item_Entries:
                                Item_Prefix = "".join(("Pkg_Item_Entries[", Format_String, "]")).format(Item_Entry["INDEX"])
                                print("".join((Item_Prefix, ": Ofs {:#012x} Size {:12}")).format(Item_Entry["DATAOFS"], Item_Entry["DATASIZE"]), end="")
                                if "FLAGS" in Item_Entry:
                                    print(" Flags {:#010x}".format(Item_Entry["FLAGS"]), end="")
                                if "KEYINDEX" in Item_Entry:
                                    print(" Key Index", Item_Entry["KEYINDEX"], end="")
                                if "NAME" in Item_Entry:
                                    print(" Name \"", Item_Entry["NAME"], "\"", sep="", end="")
                                print()
                                if "EDAT" in Item_Entry:
                                    print("".join((Item_Prefix, ": EDAT Version {} License {} Type {} Flags {:#010x}")).format(Item_Entry["EDAT"]["VERSION"], Item_Entry["EDAT"]["LICENSE"], Item_Entry["EDAT"]["TYPE"], Item_Entry["EDAT"]["FLAGS"]), end="")
                                    if "RESULTS" in Item_Entry["EDAT"]:
                                        if "DEV_KLICENSEE_KEY" in Item_Entry["EDAT"]["RESULTS"]:
                                            Value = Item_Entry["EDAT"]["RESULTS"]["DEV_KLICENSEE_KEY"]
                                            if isinstance(Value, bytes) \
                                            or isinstance(Value, bytearray):
                                                Value = convertBytesToHexString(Value, sep="")
                                            print(" Dev KLic ", Value, sep="", end="")
                                        if "RAP_VERIFY" in Item_Entry["EDAT"]["RESULTS"]:
                                            Value = Item_Entry["EDAT"]["RESULTS"]["RAP_VERIFY"]
                                            if isinstance(Value, bytes) \
                                            or isinstance(Value, bytearray):
                                                Value = convertBytesToHexString(Value, sep="")
                                            print(" RAP ", Value, sep="", end="")
                                            del Value
                                    print()
                        if Pkg_Meta_Table:
                            Format_String = "".join(("{:", unicode(len(unicode(Pkg_Header["METACNT"]-1))), "}"))
                            for Meta_Entry in Pkg_Meta_Table:
                                print("".join(("Pkg_Meta_Table[", Format_String, "]: ID {:#06x} Ofs {:#012x} Size {:12} Key Index {:2}")).format(Meta_Entry["INDEX"], Meta_Entry["METAID"], Meta_Entry["DATAOFS"], Meta_Entry["DATASIZE"], Meta_Entry["KEYINDEX"] if Meta_Entry["ENCRYPTED"] else "--"), end="")
                                if "NAME" in Meta_Entry:
                                    print(" Name", "".join(("\"", Meta_Entry["NAME"], "\"")), end="")
                                    if "NAMERELOFS" in Meta_Entry \
                                    and Meta_Entry["NAMERELOFS"]:
                                        print(" (Name Offset {:#03x})".format(Meta_Entry["NAMERELOFS"]), end="")
                                print()
                            dprintFieldsDict(Pkg_Meta_Table_Map, "Pkg_Meta_Table_Map[{KEY:#06x}]", 2, None, print_func=print)
                        if Item_Sfo_Values:
                            dprintFieldsDict(Item_Sfo_Values, "Item_Sfo_Values[{KEY:20}]", 2, None, print_func=print)
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
                        if Pbp_Sfo_Values:
                            dprintFieldsDict(Pbp_Sfo_Values, "Pbp_Sfo_Values[{KEY:20}]", 2, None, print_func=print)
                    dprintFieldsDict(Results, "Results[{KEY:23}]", 2, None, print_func=print, sep="")
            ## --> Ensure that all messages are output
            sys.stdout.flush()
            sys.stderr.flush()

            ## Extract PKG/PBP
            Extractions_Fields["DATAOFS"] = 0
            if Pkg_Magic == CONST_PKG3_MAGIC:
                Extractions_Fields["DATAOFS"] = Pkg_Header["DATAOFS"]
                Extractions_Fields["AES_CTR"] = Pkg_Header["AES_CTR"]
                Extractions_Fields["XOR_CTR"] = Pkg_Header["XOR_CTR"]
                Extractions_Fields["DEBUG_PKG"] = Pkg_Header["DEBUG_PKG"]
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
                        Extract["TARGET"] = os.path.join(Extract["ROOT"], "".join((Input_Stream.getPkgName(function_debug_level=max(0, Debug_Level)), ".decrypted")))
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
                                eprint("{} unencrypted PKG3 header data from offset {:#x} with size {}".format(Extract["FUNCTION"], 0, len(Package["HEAD_BYTES"])), prefix="[{}] ".format(Extract["KEY"]))
                            Extract["BYTES_WRITTEN"] += Extract["STREAM"].write(Package["HEAD_BYTES"])
                            #
                            if Arguments.quiet <= 0:
                                eprint("{} {} PKG3 Items Info from offset {:#x} with size {}".format(Extract["FUNCTION"], Extract["DATATYPE"].lower(), Package["ITEMS_INFO_BYTES"]["ALIGN"]["OFS"]+Extractions_Fields["DATAOFS"], Package["ITEMS_INFO_BYTES"]["ALIGN"]["SIZE"]), prefix="[{}] ".format(Extract["KEY"]))
                            Extract["BYTES_WRITTEN"] += Extract["STREAM"].write(Package["ITEMS_INFO_BYTES"][Extract["DATATYPE"]])
                    #
                    del Extract

                ## UX0 extraction
                if Arguments.ux0 \
                and Pkg_Magic == CONST_PKG3_MAGIC:
                    if "PKG_EXTRACT_UX0_ROOT" in Results:
                        Extractions[CONST_EXTRACT_UX0] = {}
                        Extract = Extractions[CONST_EXTRACT_UX0]
                        Extract["KEY"] = CONST_EXTRACT_UX0
                        Extract["FUNCTION"] = "Extract"
                        Extract["PROCESS"] = False
                        if ("PLATFORM" in Results \
                            and (Results["PLATFORM"] == CONST_PLATFORM.PSX \
                                 or Results["PLATFORM"] == CONST_PLATFORM.PSP)) \
                        or Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
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
                        Extract["ROOT"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_UX0_ROOT"])
                        if Arguments.quiet <= 1:
                            eprint(">>>>> Extraction Directory:", Extract["ROOT"], prefix="[{}] ".format(Extract["KEY"]))
                        #
                        Extract["PROCESS"] = True
                        #
                        if createDirectory(Extract["ROOT"], "package extraction", Extract["KEY"], True, Arguments.quiet, max(0, Debug_Level)) != 0:
                            Extract["PROCESS"] = False
                        #
                        if "PKG_EXTRACT_UX0_ISOR" in Results:
                            Extract["ROOT_ISO"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_UX0_ISOR"])
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
                    if "PKG_EXTRACT_CNT_ROOT" in Results:
                        Extractions[CONST_EXTRACT_CONTENT] = {}
                        Extract = Extractions[CONST_EXTRACT_CONTENT]
                        Extract["KEY"] = CONST_EXTRACT_CONTENT
                        Extract["FUNCTION"] = "Extract"
                        Extract["PROCESS"] = False
                        if Arguments.nosubdirs:
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
                        Extract["TOPDIR"] = Arguments.content
                        #
                        if Arguments.nosubdirs:
                            Extract["ROOT"] = Extract["TOPDIR"]
                        else:
                            Extract["ROOT"] = os.path.join(Extract["TOPDIR"], Results["PKG_EXTRACT_CNT_ROOT"])
                        if Arguments.quiet <= 1:
                            eprint(">>>>> Extraction Directory:", Extract["ROOT"], prefix="[{}] ".format(Extract["KEY"]), end="")
                            eprint(" (no subdirs created)" if Arguments.nosubdirs else "", prefix=None)
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
                Path_Pattern = None
                if Arguments.pathpattern \
                and CONST_EXTRACT_CONTENT in Extractions:
                    Path_Pattern = re.compile(Arguments.pathpattern, flags=re.UNICODE|re.IGNORECASE)
                #
                if not Pkg_Item_Entries is None \
                and Process_Extractions:
                    Item_Entries_Sorted = sorted(Pkg_Item_Entries, key=lambda x: (x["IS_FILE_OFS"], x["INDEX"]))
                    for Item_Entry in Item_Entries_Sorted:
                        ## Initialize per-item variables
                        Item_Data = None
                        Use_Extractions = None
                        #
                        Item_Flags = None
                        if "FLAGS" in Item_Entry:
                            Item_Flags = Item_Entry["FLAGS"] & 0xff
                        Item_Name_Parts = Item_Entry["NAME"].split("/")
                        #
                        Extract_Key = None
                        Extract = None
                        for Extract_Key, Extract in Extractions.items():
                            if not Extract["PROCESS"]:
                                continue  ## next extract
                            #
                            if Extract["SEPARATE_FILES"] \
                            and "STREAM" in Extract:
                                del Extract["STREAM"]
                            if "ITEM_EXTRACT_PATH" in Extract:
                                del Extract["ITEM_EXTRACT_PATH"]
                            if "ITEM_EXTRACT_DIR" in Extract:
                                del Extract["ITEM_EXTRACT_DIR"]
                            #
                            Extract["ITEM_EXTRACT_ROOT"] = Extract["ROOT"]
                            #
                            if Item_Entry["IS_FILE_OFS"] == -1:
                                ## 0x04: Directory
                                ## 0x12: Directory
                                if not Extract["DIRS"]:
                                    continue  ## next extract

                                ## Special exclusions
                                if Extract_Key == CONST_EXTRACT_RAW:
                                    ## no dirs (safety check only)
                                    continue  ## next extract
                                elif Extract_Key == CONST_EXTRACT_CONTENT:
                                    if Arguments.nosubdirs:
                                        ## no dirs (safety check only)
                                        continue  ## next extract
                                    ## Check path pattern if set
                                    if Path_Pattern \
                                    and not Path_Pattern.search(Item_Entry["NAME"]):
                                        continue  ## next extract

                                ## Process item name for item-wise extraction
                                Name_Parts = copy.copy(Item_Name_Parts)

                                ## UX0 special cases
                                if Extract_Key == CONST_EXTRACT_UX0 \
                                and "PLATFORM" in Results:
                                    ## Process name parts depending on platform
                                    ## --> UX0 PSX/PSP extraction
                                    ## --> Special case: PCSC80018 "PocketStation for Playstation Vita (PSX)"
                                    if Results["PLATFORM"] == CONST_PLATFORM.PSX \
                                    or Results["PLATFORM"] == CONST_PLATFORM.PSP \
                                    or Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
                                        ## no dirs (safety check only)
                                        Name_Parts = None
                                    ## --> UX0 PSV extraction
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSV \
                                    and Results["TITLE_ID"] != CONST_TITLE_ID_PSV_POCKETSTATION:
                                        ## Check if special dir "sce_sys/package" is created
                                        if not Extract["SCESYS_PACKAGE_CREATED"] \
                                        and len(Name_Parts) >= 2 \
                                        and Name_Parts[0] == "sce_sys" \
                                        and Name_Parts[1] == "package":
                                            Extract["SCESYS_PACKAGE_CREATED"] = True
                                        ## Special case: PSV Livearea extraction
                                        if Results["PKG_CONTENT_TYPE"] == 0x17 \
                                        and len(Name_Parts) > 0 \
                                        and Name_Parts[0] == "sce_sys":
                                            del Name_Parts[0]
                                    ## --> UX0 PSM extraction
                                    elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                        ## Rename base directory
                                        if len(Name_Parts) > 0 \
                                        and Name_Parts[0] == "contents":
                                            if len(Name_Parts) > 1 \
                                            and Name_Parts[1] == "runtime":
                                                del Name_Parts[0]
                                            else:
                                                Name_Parts[0] = "RO"
                                    else:
                                        pass  ## as-is

                                ## Build and check item extract path
                                if Name_Parts:
                                    Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                    #
                                    ## Avoid writing outside of extraction root dir
                                    Dir_Level = 0
                                    Name_Parts_New = []
                                    for _i in range(len(Name_Parts)):
                                        if Name_Parts[_i] == '..':
                                            if Dir_Level > 0:
                                                Name_Parts_New.append(Name_Parts[_i])
                                                Dir_Level -= 1
                                        elif Name_Parts[_i] == '.':
                                            Name_Parts_New.append(Name_Parts[_i])
                                        else:
                                            Name_Parts_New.append(Name_Parts[_i])
                                            Dir_Level += 1
                                    Name_Parts = Name_Parts_New
                                    del Name_Parts_New
                                    del Dir_Level
                                    #
                                    Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                del Name_Parts
                                #
                                if not "ITEM_EXTRACT_PATH" in Extract \
                                or not Extract["ITEM_EXTRACT_PATH"]:
                                    if "ITEM_EXTRACT_PATH" in Extract:
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next extract

                                ## Create directory
                                if createDirectory(Extract, "#{} items".format(Item_Entry["INDEX"]), Extract_Key, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                    eprint("[{}] ABORT extraction".format(Extract_Key))
                                    Extract["PROCESS"] = False
                                del Extract["ITEM_EXTRACT_PATH"]
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
                                ## 0x17: cert.bin have this type, unpack encrypted
                                ## 0x18: digs.bin have this type, unpack encrypted

                                ## Special exclusions
                                if Extract_Key == CONST_EXTRACT_RAW:
                                    if not "STREAM" in Extract \
                                    or Item_Entry["DATASIZE"] <= 0:
                                        continue  ## next extract
                                elif Extract_Key == CONST_EXTRACT_CONTENT:
                                    ## Check path pattern if set
                                    if Path_Pattern \
                                    and not Path_Pattern.search(Item_Entry["NAME"]):
                                        continue  ## next extract

                                Extract["ITEM_DATATYPE"] = Extract["DATATYPE"]
                                Extract["ITEM_NAME"] = Item_Entry["NAME"]

                                ## Process item name for item-wise extraction
                                if Extract_Key == CONST_EXTRACT_CONTENT \
                                or Extract_Key == CONST_EXTRACT_UX0:
                                    Name_Parts = copy.copy(Item_Name_Parts)

                                    ## UX0 special cases
                                    if Extract_Key == CONST_EXTRACT_UX0 \
                                    and "PLATFORM" in Results:
                                        ## Process name parts depending on platform
                                        ## --> UX0 PSX extraction
                                        ## --> Special case: PCSC80018 "PocketStation for Playstation Vita (PSX)"
                                        if Results["PLATFORM"] == CONST_PLATFORM.PSX \
                                        or Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
                                            if len(Name_Parts) == 3 \
                                            and Name_Parts[0] == "USRDIR" \
                                            and Name_Parts[1] == "CONTENT" \
                                            and (Name_Parts[2] == "DOCUMENT.DAT" \
                                                 or Name_Parts[2] == "EBOOT.PBP" \
                                                 or Name_Parts[2] == "texture.enc"):
                                                ## no dirs
                                                Name_Parts = Name_Parts[-1:]
                                            else:
                                                ## skip file
                                                Name_Parts = None
                                        ## --> UX0 PSP extraction
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSP:
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
                                                    ## no dirs
                                                    Name_Parts = Name_Parts[-1:]
                                            else:
                                                ## skip file
                                                Name_Parts = None
                                        ## --> UX0 PSV extraction
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSV \
                                        and Results["TITLE_ID"] != CONST_TITLE_ID_PSV_POCKETSTATION:
                                            ## Special case: PSV encrypted sce_sys/package/(digs|cert).bin as body.bin
                                            if len(Name_Parts) == 3 \
                                            and Name_Parts[0] == "sce_sys" \
                                            and Name_Parts[1] == "package" \
                                            and (Name_Parts[2] == "digs.bin" \
                                                 or Name_Parts[2] == "cert.bin"):  ## digs.bin: Item_Flags == 0xa0007018/0xa0007818 / cert.bin: Item_Flags == 0xa0007017
                                                Extract["ITEM_DATATYPE"] = CONST_DATATYPE_AS_IS
                                                Name_Parts[2] = "body.bin"
                                                ## Display rename
                                                if Arguments.quiet <= 0:
                                                    eprint("Renaming #{} \"{}\" to \"{}\"".format(Item_Entry["INDEX"], Item_Entry["NAME"], "/".join(Name_Parts)), prefix="[{}] ".format(Extract_Key))
                                            ## Special case: PSV Livearea extraction
                                            if Results["PKG_CONTENT_TYPE"] == 0x17 \
                                            and len(Name_Parts) > 0 \
                                            and Name_Parts[0] == "sce_sys":
                                                del Name_Parts[0]
                                        ## --> UX0 PSM extraction
                                        elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                            ## Rename base directory
                                            if len(Name_Parts) > 0 \
                                            and Name_Parts[0] == "contents":
                                                if len(Name_Parts) > 1 \
                                                and Name_Parts[1] == "runtime":
                                                    del Name_Parts[0]
                                                else:
                                                    Name_Parts[0] = "RO"
                                        else:
                                            pass  ## as-is

                                    ## Build and check item extract path
                                    if Name_Parts:
                                        Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                        #
                                        if Extract_Key == CONST_EXTRACT_CONTENT \
                                        and Arguments.nosubdirs:
                                            Name_Parts = Name_Parts[-1:]
                                        else:
                                            ## Avoid writing outside of extraction root dir
                                            Dir_Level = 0
                                            Name_Parts_New = []
                                            for _i in range(len(Name_Parts)):
                                                if Name_Parts[_i] == '..':
                                                    if Dir_Level > 0:
                                                        Name_Parts_New.append(Name_Parts[_i])
                                                        Dir_Level -= 1
                                                elif Name_Parts[_i] == '.':
                                                    Name_Parts_New.append(Name_Parts[_i])
                                                else:
                                                    Name_Parts_New.append(Name_Parts[_i])
                                                    Dir_Level += 1
                                            Name_Parts = Name_Parts_New
                                            del Name_Parts_New
                                            del Dir_Level
                                        #
                                        Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                        #
                                        if len(Name_Parts) > 1:
                                            Extract["ITEM_EXTRACT_DIR"] = os.path.join(*Name_Parts[:-1])
                                            Extract["ITEM_EXTRACT_DIR_NAME"] = "/".join(Name_Parts[:-1])
                                    del Name_Parts
                                    #
                                    if not "ITEM_EXTRACT_PATH" in Extract \
                                    or not Extract["ITEM_EXTRACT_PATH"]:
                                        if "ITEM_EXTRACT_PATH" in Extract:
                                            del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next extract

                                    ## Special case: create missing directory, e.g. when path pattern is set
                                    if "ITEM_EXTRACT_DIR" in Extract:
                                        Extract["ITEM_BACKUP_NAME"] = Extract["ITEM_NAME"]
                                        Extract["ITEM_BACKUP_EXTRACT"] = Extract["ITEM_EXTRACT_PATH"]
                                        #
                                        Extract["ITEM_EXTRACT_PATH"] = Extract["ITEM_EXTRACT_DIR"]
                                        Extract["ITEM_NAME"] = Extract["ITEM_EXTRACT_DIR_NAME"]
                                        #
                                        if Extract_Key == CONST_EXTRACT_CONTENT \
                                        and Path_Pattern \
                                        and Extract["DIRS"]:
                                            Dir_Type = "items"
                                            Quiet = Arguments.quiet
                                            Func_Debug_Level = 0
                                        else:
                                            Dir_Type = "MISSING items"
                                            Quiet = 0
                                            Func_Debug_Level = Debug_Level
                                        Result = createDirectory(Extract, Dir_Type, Extract_Key, True, Quiet, max(0, Func_Debug_Level))
                                        #
                                        Extract["ITEM_EXTRACT_PATH"] = Extract["ITEM_BACKUP_EXTRACT"]
                                        Extract["ITEM_NAME"] = Extract["ITEM_BACKUP_NAME"]
                                        del Func_Debug_Level
                                        del Quiet
                                        del Dir_Type
                                        del Extract["TARGET"]
                                        del Extract["ITEM_BACKUP_EXTRACT"]
                                        del Extract["ITEM_BACKUP_NAME"]
                                        del Extract["ITEM_EXTRACT_DIR"]
                                        #
                                        if Result != 0:
                                            eprint("[{}] ABORT extraction".format(Extract_Key))
                                            Extract["PROCESS"] = False
                                            del Extract["ITEM_EXTRACT_PATH"]
                                            del Result
                                            continue  ## next extract
                                        del Result

                                ## Display item extract path
                                if Arguments.quiet <= 0:
                                    if Extract["ITEM_NAME"].strip():
                                        Item_Name = "#{} \"{}\"".format(Item_Entry["INDEX"], Extract["ITEM_NAME"])
                                    else:
                                        Item_Name = "#{} unnamed item".format(Item_Entry["INDEX"])
                                    if Extract["ALIGNED"]:
                                        Values = ["aligned ", Extractions_Fields["DATAOFS"]+Item_Entry["ALIGN"]["OFS"], Item_Entry["ALIGN"]["SIZE"]]
                                    else:
                                        Values = ["", Extractions_Fields["DATAOFS"]+Item_Entry["DATAOFS"], Item_Entry["DATASIZE"]]
                                    eprint("{} {} {} from {}offset {:#x} with size {}".format(Extract["FUNCTION"], Item_Name, Extract["ITEM_DATATYPE"].lower(), *Values), prefix="[{}] ".format(Extract_Key))
                                    del Values
                                    del Item_Name

                                ## Build and check target path for item-wise extraction
                                if Extract_Key == CONST_EXTRACT_CONTENT \
                                or Extract_Key == CONST_EXTRACT_UX0:
                                    Extract["TARGET"] = os.path.join(Extract["ITEM_EXTRACT_ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                    Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                                    if Extract["TARGET_CHECK"] != 0:
                                        if Extract["TARGET_CHECK"] < 0:
                                            eprint("[{}] BROKEN extraction".format(Extract_Key))
                                        del Extract["ITEM_EXTRACT_PATH"]
                                        continue  ## next extract
                                #
                                if "STREAM" in Extract:
                                    Use_Extractions = Extractions
                                #
                                continue  ## next extract
                        ## Clean-up
                        del Extract
                        del Extract_Key
                        del Item_Name_Parts
                        del Item_Flags
                        #
                        if not Use_Extractions:
                            continue  ## next item

                        ## Process item data
                        if Item_Entry["DATASIZE"] > 0:
                            Item_Index = Item_Entry["INDEX"]
                            ## --> Special cases: already read data
                            if Item_Index in Package["ITEM_BYTES"]:
                                Item_Data = Package["ITEM_BYTES"][Item_Index]
                            #
                            processPkg3Item(Extractions_Fields, Item_Entry, Input_Stream, Item_Data, extractions=Use_Extractions, function_debug_level=max(0, Debug_Level))

                        ## Close streams
                        Extract_Key = None
                        Extract = None
                        for Extract_Key, Extract in Extractions.items():
                            if Extract["SEPARATE_FILES"] \
                            and "STREAM" in Extract:
                                Extract["STREAM"].close()
                                del Extract["STREAM"]
                            if "ITEM_EXTRACT_PATH" in Extract:
                                del Extract["ITEM_EXTRACT_PATH"]
                        del Extract
                        del Extract_Key
                    #
                    del Use_Extractions
                    del Item_Data
                    #
                    del Item_Entry
                    del Item_Entries_Sorted

                ## Special cases: additional items, clean-up, etc.
                if Process_Extractions:
                    Extract_Key = None
                    Extract = None
                    for Extract_Key, Extract in Extractions.items():
                        if not Extract["PROCESS"]:
                            continue  ## next extract
                        #
                        if Extract["SEPARATE_FILES"] \
                        and "STREAM" in Extract:
                            del Extract["STREAM"]

                        if Extract_Key == CONST_EXTRACT_RAW:
                            ## Write PKG3 unencrypted tail data
                            if Arguments.quiet <= 0:
                                eprint("{} unencrypted PKG3 tail data from offset {:#x} with size {}".format(Extract["FUNCTION"], Extractions_Fields["DATAOFS"]+Pkg_Header["DATASIZE"], Results["PKG_TAIL_SIZE"]), prefix="[{}] ".format(Extract_Key))
                            if not "TAIL_BYTES" in Package:
                                ## Data not available
                                eprint("MISSING tail data, maybe this is only the first file of a multi-part package or it is a head.bin", prefix="[{}] ".format(Extract_Key))
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
                                eprint("Written size {} of unencrypted/decrypted data from".format(Extract["BYTES_WRITTEN"]), Input_Stream.getSource(function_debug_level=max(0, Debug_Level)))
                                if "PKG_TOTAL_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["PKG_TOTAL_SIZE"]:
                                    eprint("mismatches package total size of", Results["PKG_TOTAL_SIZE"])
                                if "FILE_SIZE" in Results \
                                and Extract["BYTES_WRITTEN"] != Results["FILE_SIZE"]:
                                    eprint("mismatches file size of", Results["FILE_SIZE"])
                                eprint("Please report this issue at https://github.com/windsurfer1122/PSN_get_pkg_info")
                        #
                        elif Extract_Key == CONST_EXTRACT_UX0 \
                        or Extract_Key == CONST_EXTRACT_CONTENT:
                            if not "PLATFORM" in Results:
                                continue  ## next extract

                            ## Definitions
                            Dirs = collections.OrderedDict()
                            Files = collections.OrderedDict()
                            ## --> PSX/PSP extraction
                            ## --> Special case: PCSC80018 "PocketStation for Playstation Vita (PSX)"
                            if Results["PLATFORM"] == CONST_PLATFORM.PSX \
                            or Results["PLATFORM"] == CONST_PLATFORM.PSP \
                            or Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
                                ## --> PSX/PSP RIF (license)
                                if "PKG_EXTRACT_UX0_LIC_FILE" in Results \
                                and Results["PKG_TYPE"] != CONST_PKG_TYPE.PATCH:  ## Patches do not need a license file
                                    if not Results["PKG_CONTENT_ID"] in Rifs:
                                        eprint("MISSING zrif license for package content id", Results["PKG_CONTENT_ID"], prefix="[{}] ".format(Extract_Key))
                                    else:
                                        ## Dirs
                                        Dirs[1] = { "PATH": Results["PKG_EXTRACT_UX0_LIC_ROOT"].split(os.sep), }
                                        ## Files
                                        Files[1] = { "PATH": Results["PKG_EXTRACT_UX0_LIC_FILE"].split(os.sep), "VALUES": ["Write", None, "license", "", "zrif", len(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])], }
                                        #
                                        if Extract_Key == CONST_EXTRACT_UX0:  ## UX0-only PSP extraction
                                            Dirs[1]["ROOT"] = Extract["TOPDIR"]
                                            Dirs[1]["DIRS"] = True
                                            Files[1]["ROOT"] = Extract["TOPDIR"]
                            ## --> PSV extraction
                            elif Results["PLATFORM"] == CONST_PLATFORM.PSV \
                            and Results["PKG_CONTENT_TYPE"] != 0x17 \
                            and Results["TITLE_ID"] != CONST_TITLE_ID_PSV_POCKETSTATION:
                                ## Dirs
                                if Extract["DIRS"]:
                                    if not Extract["SCESYS_PACKAGE_CREATED"]:
                                        Dirs[1] = { "PATH": ["sce_sys", "package"], }
                                ## Files
                                ## --> PSV head.bin
                                Files[1] = { "PATH": ["sce_sys", "package", "head.bin"], "VALUES": [Extract["FUNCTION"], None, "unencrypted head + encrypted items info", "", "offset {:#x}".format(0), len(Package["HEAD_BYTES"])+len(Package["ITEMS_INFO_BYTES"][CONST_DATATYPE_AS_IS])], }
                                ## --> PSV tail.bin
                                if not "TAIL_BYTES" in Package:  ## Tail data not available
                                    eprint("MISSING tail data, maybe this is only the first file of a multi-part package or it is a head.bin", prefix="[{}] ".format(Extract_Key))
                                else:
                                    Files[2] = { "PATH": ["sce_sys", "package", "tail.bin"], "VALUES": [Extract["FUNCTION"], None, "unencrypted tail", "", "offset {:#x}".format(Extractions_Fields["DATAOFS"]+Pkg_Header["DATASIZE"]), len(Package["TAIL_BYTES"])], }
                                ## --> PSV stat.bin
                                if Extract_Key == CONST_EXTRACT_UX0:  ## UX0-only PSV extraction
                                    Files[3] = { "PATH": ["sce_sys", "package", "stat.bin"], "VALUES": ["Write", None, "fake data", "", "zeroes", 0x300], }
                                ## --> PSV work.bin (license)
                                if Results["PKG_TYPE"] != CONST_PKG_TYPE.PATCH:  ## Patches do not need a license file
                                    if not Results["PKG_CONTENT_ID"] in Rifs:
                                        eprint("MISSING zrif license for package content id", Results["PKG_CONTENT_ID"], prefix="[{}] ".format(Extract_Key))
                                    else:
                                        Files[4] = { "PATH": ["sce_sys", "package", "work.bin"], "VALUES": ["Write", None, "license", "", "zrif", len(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])], }
                            ## --> PSM extraction
                            elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                ## Dirs
                                if Extract["DIRS"]:
                                    Dirs[1] = { "PATH": ["RW", "System"], }
                                    #
                                    if Extract_Key == CONST_EXTRACT_UX0:  ## UX0-only PSM extraction
                                        Dirs[2] = { "PATH": ["RW", "Documents"], }
                                        Dirs[3] = { "PATH": ["RW", "Temp"], }
                                    #
                                    Dirs[4] = { "PATH": ["RO", "License"], }
                                ## --> PSM content_id
                                Files[1] = { "PATH": ["RW", "System", "content_id"], "VALUES": [Extract["FUNCTION"], None, "content id", "", "offset {:#x}".format(CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]), CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["SIZE"]], }
                                ## --> PSM pm.dat
                                if Extract_Key == CONST_EXTRACT_UX0:  ## UX0-only PSM extraction
                                    Files[2] = { "PATH": ["RW", "System", "pm.dat"], "VALUES": ["Write", None, "fake data", "", "zeroes", 0x10000], }
                                ## --> PSM FAKE.rif (license)
                                if not Results["PKG_CONTENT_ID"] in Rifs:
                                    eprint("MISSING zrif license for package content id", Results["PKG_CONTENT_ID"], prefix="[{}] ".format(Extract_Key))
                                else:
                                    Files[3] = { "PATH": ["RO", "License", "FAKE.rif"], "VALUES": ["Write", None, "license", "", "zrif", len(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])], }

                            ## Process dirs
                            Dir_Number = None
                            Dir_Data = None
                            for Dir_Number, Dir_Data in Dirs.items():
                                if not Extract["DIRS"] \
                                and not ("DIRS" in Dir_Data \
                                         and Dir_Data["DIRS"]):
                                    continue  ## next dir

                                ## Special exclusions
                                if Extract_Key == CONST_EXTRACT_CONTENT:
                                    if Arguments.nosubdirs:
                                        ## no dirs (safety check only)
                                        continue  ## next extract

                                if "ITEM_EXTRACT_PATH" in Extract:
                                    del Extract["ITEM_EXTRACT_PATH"]
                                if "ITEM_EXTRACT_DIR" in Extract:
                                    del Extract["ITEM_EXTRACT_DIR"]
                                #
                                if "ROOT" in Dir_Data:
                                    Extract["ITEM_EXTRACT_ROOT"] = Dir_Data["ROOT"]
                                else:
                                    Extract["ITEM_EXTRACT_ROOT"] = Extract["ROOT"]

                                ## Process item name for item-wise extraction
                                Name_Parts = copy.copy(Dir_Data["PATH"])

                                ## Build and check item extract path
                                if Name_Parts:
                                    Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                    #
                                    ## Special exclusions
                                    if Extract_Key == CONST_EXTRACT_CONTENT:
                                        ## Check path pattern if set
                                        if Path_Pattern \
                                        and not Path_Pattern.search(Extract["ITEM_NAME"]):
                                            del Name_Parts
                                            continue  ## next dir
                                    #
                                    Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                del Name_Parts
                                #
                                if not "ITEM_EXTRACT_PATH" in Extract \
                                or not Extract["ITEM_EXTRACT_PATH"]:
                                    if "ITEM_EXTRACT_PATH" in Extract:
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next dir

                                ## Create directory
                                if createDirectory(Extract, "extra", Extract_Key, True, Arguments.quiet, max(0, Debug_Level)) != 0:
                                    eprint("[{}] ABORT extraction".format(Extract_Key))
                                    Extract["PROCESS"] = False
                                    del Extract["ITEM_EXTRACT_PATH"]
                                    break  ## no more dirs
                                del Extract["ITEM_EXTRACT_PATH"]
                                #
                                continue  ## next dir
                            #
                            del Dir_Data
                            del Dir_Number
                            del Dirs
                            #
                            if not Extract["PROCESS"]:
                                continue  ## next extract

                            ## Process files
                            File_Number = None
                            File_Data = None
                            for File_Number, File_Data in Files.items():
                                if "ITEM_EXTRACT_PATH" in Extract:
                                    del Extract["ITEM_EXTRACT_PATH"]
                                if "ITEM_EXTRACT_DIR" in Extract:
                                    del Extract["ITEM_EXTRACT_DIR"]
                                #
                                if "ROOT" in File_Data:
                                    Extract["ITEM_EXTRACT_ROOT"] = File_Data["ROOT"]
                                else:
                                    Extract["ITEM_EXTRACT_ROOT"] = Extract["ROOT"]
                                Extract["ITEM_DATATYPE"] = Extract["DATATYPE"]

                                ## Process item name for item-wise extraction
                                Name_Parts = copy.copy(File_Data["PATH"])

                                ## Build and check item extract path
                                if Name_Parts:
                                    Extract["ITEM_NAME"] = "/".join(Name_Parts)
                                    #
                                    ## Special exclusions
                                    if Extract_Key == CONST_EXTRACT_CONTENT:
                                        ## Check path pattern if set
                                        if Path_Pattern \
                                        and not Path_Pattern.search(Extract["ITEM_NAME"]):
                                            del Name_Parts
                                            continue  ## next file
                                    #
                                    if Extract_Key == CONST_EXTRACT_CONTENT:
                                        if Arguments.nosubdirs:
                                            Name_Parts = Name_Parts[-1:]
                                    #
                                    Extract["ITEM_EXTRACT_PATH"] = os.path.join(*Name_Parts)
                                    #
                                    if len(Name_Parts) > 1:
                                        Extract["ITEM_EXTRACT_DIR"] = os.path.join(*Name_Parts[:-1])
                                        Extract["ITEM_EXTRACT_DIR_NAME"] = "/".join(Name_Parts[:-1])
                                del Name_Parts
                                #
                                if not "ITEM_EXTRACT_PATH" in Extract \
                                or not Extract["ITEM_EXTRACT_PATH"]:
                                    if "ITEM_EXTRACT_PATH" in Extract:
                                        del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next file

                                ## Special case: create missing directory, e.g. when path pattern is set
                                if "ITEM_EXTRACT_DIR" in Extract:
                                    Extract["ITEM_BACKUP_NAME"] = Extract["ITEM_NAME"]
                                    Extract["ITEM_BACKUP_EXTRACT"] = Extract["ITEM_EXTRACT_PATH"]
                                    #
                                    Extract["ITEM_EXTRACT_PATH"] = Extract["ITEM_EXTRACT_DIR"]
                                    Extract["ITEM_NAME"] = Extract["ITEM_EXTRACT_DIR_NAME"]
                                    #
                                    if Extract_Key == CONST_EXTRACT_CONTENT \
                                    and Path_Pattern \
                                    and Extract["DIRS"]:
                                        Dir_Type = "extra"
                                        Quiet = Arguments.quiet
                                        Func_Debug_Level = 0
                                    else:
                                        Dir_Type = "MISSING extra"
                                        Quiet = 0
                                        Func_Debug_Level = Debug_Level
                                    Result = createDirectory(Extract, Dir_Type, Extract_Key, True, Quiet, max(0, Func_Debug_Level))
                                    #
                                    Extract["ITEM_EXTRACT_PATH"] = Extract["ITEM_BACKUP_EXTRACT"]
                                    Extract["ITEM_NAME"] = Extract["ITEM_BACKUP_NAME"]
                                    del Func_Debug_Level
                                    del Quiet
                                    del Dir_Type
                                    del Extract["TARGET"]
                                    del Extract["ITEM_BACKUP_EXTRACT"]
                                    del Extract["ITEM_BACKUP_NAME"]
                                    del Extract["ITEM_EXTRACT_DIR"]
                                    #
                                    if Result != 0:
                                        eprint("[{}] ABORT extraction".format(Extract_Key))
                                        Extract["PROCESS"] = False
                                        del Extract["ITEM_EXTRACT_PATH"]
                                        del Result
                                        break  ## no more files
                                    del Result

                                ## Display item extract path
                                if Arguments.quiet <= 0:
                                    Values = None
                                    if "VALUES" in File_Data:
                                        Values = File_Data["VALUES"]
                                    else:
                                        Values = ["Write", None, "item", "unknown", "", "unknown"]
                                    if Values[1] is None:
                                        Values[1] = "\"{}\"".format(Extract["ITEM_NAME"])
                                    eprint("{} {} {} from {}{} with size {}".format(*Values), prefix="[{}] ".format(Extract_Key))
                                    del Values

                                ## Build and check target path for item-wise extraction
                                Extract["TARGET"] = os.path.join(Extract["ITEM_EXTRACT_ROOT"], Extract["ITEM_EXTRACT_PATH"])
                                Extract["TARGET_CHECK"] = checkExtractFile(Extract, Arguments.overwrite, Arguments.quiet, max(0, Debug_Level))
                                if Extract["TARGET_CHECK"] != 0:
                                    if Extract["TARGET_CHECK"] < 0:
                                        eprint("[{}] BROKEN extraction".format(Extract_Key))
                                    del Extract["ITEM_EXTRACT_PATH"]
                                    continue  ## next file

                                ## Write data
                                ## --> PSX/PSP extraction
                                ## --> Special case: PCSC80018 "PocketStation for Playstation Vita (PSX)"
                                if Results["PLATFORM"] == CONST_PLATFORM.PSX \
                                or Results["PLATFORM"] == CONST_PLATFORM.PSP \
                                or Results["TITLE_ID"] == CONST_TITLE_ID_PSV_POCKETSTATION:
                                    ## --> PSX/PSP RIF (license)
                                    if File_Number == 1:
                                        Extract["STREAM"].write(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                ## --> PSV extraction
                                elif Results["PLATFORM"] == CONST_PLATFORM.PSV \
                                and Results["TITLE_ID"] != CONST_TITLE_ID_PSV_POCKETSTATION:
                                    ## --> PSV head.bin
                                    if File_Number == 1:
                                        Extract["STREAM"].write(Package["HEAD_BYTES"])
                                        Extract["STREAM"].write(Package["ITEMS_INFO_BYTES"][CONST_DATATYPE_AS_IS])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    ## --> PSV tail.bin
                                    elif File_Number == 2:
                                        Extract["STREAM"].write(Package["TAIL_BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    ## --> PSV stat.bin
                                    elif File_Number == 3:
                                        Extract["STREAM"].write(bytearray(0x300))
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    ## --> PSV work.bin (license)
                                    elif File_Number == 4:
                                        Extract["STREAM"].write(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                ## --> PSM extraction
                                elif Results["PLATFORM"] == CONST_PLATFORM.PSM:
                                    ## --> PSM content_id
                                    if File_Number == 1:
                                        Extract["STREAM"].write(Package["HEAD_BYTES"][CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]:CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["OFFSET"]+CONST_PKG3_MAIN_HEADER_FIELDS["CONTENT_ID"]["SIZE"]])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    ## --> PSM pm.dat
                                    elif File_Number == 2:
                                        Extract["STREAM"].write(bytearray(0x10000))
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                    ## --> PSM FAKE.rif (license)
                                    elif File_Number == 3:
                                        Extract["STREAM"].write(Rifs[Results["PKG_CONTENT_ID"]]["BYTES"])
                                        Extract["STREAM"].close()
                                        del Extract["STREAM"]
                                #
                                del Extract["ITEM_EXTRACT_PATH"]
                                #
                                if "STREAM" in Extract:
                                    eprint("[{}]".format(Extract_Key), "NOT IMPLEMENTED for item", "\"{}\"".format(Extract["ITEM_NAME"]))
                                    Extract["STREAM"].close()
                                    del Extract["STREAM"]
                                    os.remove(Extract["TARGET"])
                                    continue  ## next file
                                #
                                continue  ## next file
                            #
                            del File_Data
                            del File_Number
                            del Files
                            #
                            if not Extract["PROCESS"]:
                                continue  ## next extract
                    ## Clean-up
                    del Extract
                    del Extract_Key

                ## Clean-up
                del Path_Pattern
            ## --> PKG4
            elif Pkg_Magic == CONST_PKG4_MAGIC:
                pass  ## TODO: PS4 extraction not supported yet

            ## Close input stream
            Input_Stream.close(function_debug_level=max(0, Debug_Level))
            del Input_Stream

            ## Output additional results
            for Output_Format in Arguments.format:
                if Output_Format == 50:  ## Additional debugging Output
                    if Extractions:
                        dprintFieldsDict(Extractions, "extractions[{KEY:5}]", 2, None, print_func=print, sep="")
            ## --> Ensure that all messages are output
            sys.stdout.flush()
            sys.stderr.flush()

            ## Clean-Up
            del Package
    except SystemExit:
        raise  ## re-raise/throw up (let Python handle it)
    except:
        print_exc_plus()
