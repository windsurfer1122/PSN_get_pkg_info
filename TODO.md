# PSN_get_pkg_info.py - To Do List

## To Do
- [ ] Recognize more package types
  * PSP: PKG content type 15/0xf not supported. PSP/Minis/PC Engine/Neo Geo
    * UP4128/NPUZ00242_00/GSknEkVAKwcEGLQVjxbSnOJFFvmtRYSsfCfCkCURuVKgBrKDJuNgrbmUyadjTzIYTQglsNZTWaMfIjacotTAArwGtyPWSIZTOVMVy.pkg (Game Mini)
    * UP4128/NPUZ00193_00/NTPIvymtsQUIyYqhGucTmnidjuSdWhcnpFEBZwFDfkkAbpUnBrBOvueSpAAKWFapwYWvuFUvbhiqWeaufJShHxBwrzwfcBhTXXOxT.pkg (Game Mini)
    * JP0805/NPJJ30059_00/hGkJbqgmXJYjRBTOmUmPvqrLwUhFBiHNNSiAeBuaezdPyvmyVlzYvKgYuoBBOdEFEltRyPeWSKluetJvVrbuPSQiAZgSSKKEjeyTF.pkg (PC Engine)
    * JP0576/NPJH70002_00/EpdkZDkoEKlZtxUVKzdIqeCuFXiSzhjrWwNoANeOHvFjLnPsydXwtAtYfLbklqLMBlQEHaoxtEqsRnRLCUTLvklkSEJgtQNWMWtMB.pkg (Neo Geo)
- [x] Switch from unmaintained module pycrypto to pycryptodomex
  * pycrypto has not been maintained since 2014
- [x] Find package that uses PKG3 Key #03
  * None found in known PS3/PSX/PSP/PSV/PSM packages
  * Extracted all data via -f 99 to separate text files and grep'ed through them

## Wishlist
- [ ] -x/--extract functionality from pkg2zip
  * How to recognize directories and other non-files?
  * Analyze itementries of test examples.
  * Needs to read complete file.
  * https://github.com/mmozeiko/pkg2zip/blob/master/pkg2zip.c#L873
  * https://github.com/weaknespase/PkgDecrypt/blob/master/pkg_dec.c#L256
- [ ] Extend PS4 package support
  * Decrypt files (not necessary, nice-to-have)
    http://www.psdevwiki.com/ps4/PKG_files#PFS
    https://github.com/xvortex/ps4-dumper-vtx/blob/master/source/dump.c
    https://github.com/n1ghty/pkg_tools/blob/master/lib/pkg_parser.py
  * ~~Correct HTTP headers (difficult, PKG type only known when already accessed)~~
- [x] --raw functionality from pkg2dec
  * Needs to read complete file.
