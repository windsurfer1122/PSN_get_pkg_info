# PSN_get_pkg_info.py - To Do List

<u>To Do:</u>
* Recognize more package types
  * PSP: PKG content type 15/0xf not supported. PSP/Minis/PC Engine/Neo Geo
    *  UP4128/NPUZ00242_00/GSknEkVAKwcEGLQVjxbSnOJFFvmtRYSsfCfCkCURuVKgBrKDJuNgrbmUyadjTzIYTQglsNZTWaMfIjacotTAArwGtyPWSIZTOVMVy.pkg (Game Mini)
    *  UP4128/NPUZ00193_00/NTPIvymtsQUIyYqhGucTmnidjuSdWhcnpFEBZwFDfkkAbpUnBrBOvueSpAAKWFapwYWvuFUvbhiqWeaufJShHxBwrzwfcBhTXXOxT.pkg (Game Mini)
    * JP0805/NPJJ30059_00/hGkJbqgmXJYjRBTOmUmPvqrLwUhFBiHNNSiAeBuaezdPyvmyVlzYvKgYuoBBOdEFEltRyPeWSKluetJvVrbuPSQiAZgSSKKEjeyTF.pkg (PC Engine)
    * JP0576/NPJH70002_00/EpdkZDkoEKlZtxUVKzdIqeCuFXiSzhjrWwNoANeOHvFjLnPsydXwtAtYfLbklqLMBlQEHaoxtEqsRnRLCUTLvklkSEJgtQNWMWtMB.pkg (Neo Geo)
* Find package that uses PKG3 Key #03
  * Via -f 99 log all used pkg type, keys, ext. header per platform for all known packages.

<u>Wishlist:</u>
* Verify function
  * Read the following block with digest (0x40) or SHA-1 (0x20) and compare with result
* Extend PS4 package support
  * decrypt files (not necessary, nice-to-have)
    http://www.psdevwiki.com/ps4/PKG_files#PFS
    https://github.com/xvortex/ps4-dumper-vtx/blob/master/source/dump.c
    https://github.com/n1ghty/pkg_tools/blob/master/lib/pkg_parser.py
  * - Correct HTTP headers (difficult, PKG type only known when already accessed)
