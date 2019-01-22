# PSN_get_pkg_info.py - To Do List

## To Do
- [ ] Recognize more package types
  * [ ] PS4: all content types
  * [ ] PS3:
    * [ ] 0x12  (~120)
      * http://zeus.dl.playstation.net/cdn/EP0082/NPED00074_00/VoMyrXCrWATePvUyryZuDHHxDALraMWTDGFGwFnaHKyopFrDccwRrCTXAvAPxcje.pkg
      * http://zeus.dl.playstation.net/cdn/EP0082/NPED00075_00/grcqGWaHzewtoNdvZNWSgXXZMgCSEckKhcLbsHhDRsfymtOUPHPTWsbbIbhttiJw.pkg
      * http://zeus.dl.playstation.net/cdn/EP0102/NPED00052_00/ZaZbieaYFakfVgarWgAitqWPQdQUnaFUPHIjlOUmyeJJZMnzNeWmlwuOTMSAfMmk.pkg
      * http://zeus.dl.playstation.net/cdn/EP0102/NPED00053_00/zXHDGKwawTmGxFRdvzrbFDMwFRZoKeRXjLYsjehijcEKLRYUkCCXGYInEaQluPqt.pkg
      * http://zeus.dl.playstation.net/cdn/UP9000/NPUC97264_00/NPhIMQZdoQiKhozFlXZEmIubFOADKIxDSgRYOCrsMHKgupvOFEpllnvigLXOkRgPeTNawvsMIIiqwyAzBNptyZZsQZCxHLnZiguWp.pkg
      * http://zeus.dl.playstation.net/cdn/UP9000/NPUC97355_00/pkMXkKUtHHiKLdNxPxdLRtryBKdgnVyCKDSofgNyOpPLovIYRBFIlsMrsqGzCxUL.pkg
      * http://zeus.dl.playstation.net/cdn/UP9000/NPUD00294_00/UP9000-NPUD00294_00-GSUIKODEN3000001_bg_1_49c2d881b0828e5a0caafd59311b08605ec1b1da.pkg
    * [ ] 0x13 (4)
      * http://zeus.dl.playstation.net/cdn/EP0700/NPEB01202_00/USQeayptvnilvJYHZhbDGsLJkhnVxGUYyqAMVEMCTyjZMKYcgBMAViDHppMgKArB.pkg
      * http://zeus.dl.playstation.net/cdn/JP9000/NPJA00102_00/XYEnBIbgQzQZBByvAoJqqYPrDImdimIeSNDKRtaqayKkyqNkiTYUqhWKRbjrtChwpRzoOqhwjAxjCezuDfhRiKxSOftekvvGQxmYO.pkg
      * http://zeus.dl.playstation.net/cdn/JP9000/NPJA00104_00/wzhwRwKebinCHvOxRmvATaHYuMeTDokliWioWHUylTNNFazDJikZShgBZvwKUoawZIIixneZFVeSCUBzpIXuRIwCwEQIpKBlCpaQC.pkg
      * http://zeus.dl.playstation.net/cdn/UP0005/NPUB30910_00/MfxrUDwAWCgSWmixQoFdiKbaBdrkFAvAfoiXLUXaDBYJzYOkIvGqlbOyfrquqXgv.pkg
    * [ ] 0x14 (1)
      * http://zeus.dl.playstation.net/cdn/JP0102/NPJB00370_00/dhuyqrqbzuyFjxqfAiFbvDvkBAWJAUAufQrECuurDgNzZtVIRVPwgSScAVVGwZuizwEWRBnugnsqyAqRdpZBAqyzPzxNWyJYSedsr.pkg
  * [x] PSP: PKG content type 15/0xf not supported. PSP/Minis/PC Engine/Neo Geo
    * UP4128/NPUZ00242_00/GSknEkVAKwcEGLQVjxbSnOJFFvmtRYSsfCfCkCURuVKgBrKDJuNgrbmUyadjTzIYTQglsNZTWaMfIjacotTAArwGtyPWSIZTOVMVy.pkg (Game Mini)
    * UP4128/NPUZ00193_00/NTPIvymtsQUIyYqhGucTmnidjuSdWhcnpFEBZwFDfkkAbpUnBrBOvueSpAAKWFapwYWvuFUvbhiqWeaufJShHxBwrzwfcBhTXXOxT.pkg (Game Mini)
    * JP0805/NPJJ30059_00/hGkJbqgmXJYjRBTOmUmPvqrLwUhFBiHNNSiAeBuaezdPyvmyVlzYvKgYuoBBOdEFEltRyPeWSKluetJvVrbuPSQiAZgSSKKEjeyTF.pkg (PC Engine)
    * JP0576/NPJH70002_00/EpdkZDkoEKlZtxUVKzdIqeCuFXiSzhjrWwNoANeOHvFjLnPsydXwtAtYfLbklqLMBlQEHaoxtEqsRnRLCUTLvklkSEJgtQNWMWtMB.pkg (Neo Geo)
- [ ] Create ZRIF structure (BE)
- [ ] `-x` extract functionality from pkg2zip (similar to `--make-dirs=ux` extract functionality from pkg_dec)
  * [x] extraction of PSV/PSM packages
  * [x] zrif support for PSV/PSM packages
  * [x] extraction of PSX packages
  * [ ] extraction of PSP packages
  * [ ] zip support (see pkg2zip_out.c, variable out_zipped)
- [ ] Read PSM's "contents/Application/app.info" for details (wiki entries present)
- [x] Switch from unmaintained module pycrypto to pycryptodomex
  * pycrypto has not been maintained since 2014
- [x] Find package that uses PKG3 Key #03
  * None found in known PS3/PSX/PSP/PSV/PSM packages
  * Extracted all data via -f 99 to separate text files and grep'ed through them

## Wishlist
- [ ]  Extraction special cases for ux0
  * [ ] PSV "PocketStation for PlayStation Vita" with Content ID JA0003-PCSC80018_00-POCKETSTATION001 and content type 0x6 for PSX game
        http://zeus.dl.playstation.net/cdn/JA0003/PCSC80018_00/pQPQxDhSsKTYgePChkMtuIpyghZywbSOvfKvPsvdKMfgkUPSKGmOvibEysgRQBOURpMTlweKQnpGtFDaIXhaJPbEPRGdFqYUvZprD.pkg
        PSV exclusive PS1 Emu package. Just stores texture.enc as ux0:ps1emu/PCSC80018/texture.enc plus license in ux0:pspemu/whereverlicensesare/.
        No bubble after installation, but certain JP PS1 classics will then have PocketStation button on their LiveArea page, which will run this pocketstation emulator. To run PocketStation it needs valid PS1 Classic license [of the title you want to run this emu on].
        There's no NoPs1emuDrm.
        PKG installer can install it (TODO: verify).
        No support for it in pkg2zip/pkgj.
        Special pkg, the only "DRMfree" PSP pkg.
        The PSV OS embeds hardcoded titleid so it knows it doesnt need a account bound license to be installed
- [ ] Extend PS4 package support
  * Decrypt files (not necessary, nice-to-have)
    http://www.psdevwiki.com/ps4/PKG_files#PFS
    https://github.com/xvortex/ps4-dumper-vtx/blob/master/source/dump.c
    https://github.com/n1ghty/pkg_tools/blob/master/lib/pkg_parser.py
  * ~~Correct HTTP headers (difficult, PKG type only known when already accessed)~~
- [ ] Determine package's details URL in Store
  * https://store.playstation.com/valkyrie-api/en/GB/25/resolve/EP9000-PCSF00214_00-PREORDER0AMAZON0?depth=2
  * https://store.playstation.com/valkyrie-api/en/US/25/resolve/UP9000-PCSA00002_00-MLB12THESHOWVITA?depth=2
  * https://store.playstation.com/valkyrie-api/en/HK/25/resolve/JP0106-PCSG00002_00-MUSOUNEXT0000000?depth=2
  * https://store.playstation.com/valkyrie-api/en/HK/25/resolve/HP0106-PCSH10027_00-TOUKIDEN2F2P0000?depth=2
  * Korea?
- [x] `--make-dirs=id` extract functionality from pkg_dec
  * [x] extraction of PSV/PSM packages
  * [x] zrif support for PSV/PSM packages
  * [x] extraction of PSX/PSP packages
  * [x] extraction of PS3 packages
- [x] --raw functionality from pkg2dec
  * Needs to read complete file.
