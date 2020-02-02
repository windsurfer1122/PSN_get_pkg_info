# PSN_get_pkg_info.py (c) 2018-2020 by "windsurfer1122"
Extract package information from header and PARAM.SFO of PS3/PSX/PSP/PSV/PSM and PS4 packages.

## Test cases
### PSV (JP) - PCSC80018 - PocketStation for Playstation Vita (PSX)
Extra stuff for other PSX titles.
* App: http://zeus.dl.playstation.net/cdn/JA0003/PCSC80018_00/pQPQxDhSsKTYgePChkMtuIpyghZywbSOvfKvPsvdKMfgkUPSKGmOvibEysgRQBOURpMTlweKQnpGtFDaIXhaJPbEPRGdFqYUvZprD.pkg
  * ux0:ps1emu/PCSC80018/texture.enc
  * ux0:pspemu/PSP/LICENSE/JA0003-PCSC80018_00-POCKETSTATION001.rif
* Example: Crash Bandicot 3 (JP, PSX)
  * https://gamefaqs.gamespot.com/ps/196988-crash-bandicoot-3-warped/faqs/9325
  * https://www.youtube.com/watch?v=DJL1xW5VlHI

### PSV (JP) - PCSG01200 - Dungeon Hunter 5 - Small Size
* Game 1.0 - JP3608-PCSG01200_00-0000000000000001 (4.7 MiB): http://zeus.dl.playstation.net/cdn/JP3608/PCSG01200_00/JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg

### PSV (EU) - PCSF00012 - Uncharted Golden Abyss
* Game 1.0 - EP9000-PCSF00012_00-0000000000000000: http://zeus.dl.playstation.net/cdn/EP9000/PCSF00012_00/pxTfWxOyWsQLbZrQgfOVPdtVDXXgdjitvaylZvByLCOehpAHngZNeOtKbcJkWqAM.pkg
  * ux0:app/PCSF00012/*
  * ux0:license/app/PCSF00012/*
* Patch 1.03 - EP9000-PCSF00012_00-0000000000000000:
http://gs.ww.np.dl.playstation.net/ppkg/np/PCSF00012/PCSF00012_T4/b5d50e0b8223976a/EP9000-PCSF00012_00-0000000000000000-A0103-V0100-2325cc7774eda39fb90c2eb6a1c6ff217b5561a3-PE.pkg
  * ux0:patch/PCSF00012/*
* DLC Map - EP9000-PCSF00012_00-UGAMAPPACKSDLC01: http://zeus.dl.playstation.net/cdn/EP9000/PCSF00012_00/MafVxzBiiTSLhohgMQiiLKZWRwwOintuOfVxvokgnPMfPIViIqnxokLAXMXOsITX.pkg
  * ux0:addcont/PCSF00012/UGAMAPPACKSDLC01/*
  * ux0:license/addcont/PCSF00012/UGAMAPPACKSDLC01/*.rif
* Theme 1.0 - EP9000-PCSF00012_00-UGAVITATHEME0000: http://zeus.dl.playstation.net/cdn/EP9000/PCSF00012_00/QrpaSpXugMiNnDuDtKJtJfYzqTWzNJwfIGBJEPTCvXjpINuvUPJZHmvCHdjHezSc.pkg
  * ux0:theme/PCSF00012-UGAVITATHEME0000/*
  * ux0:license/theme/PCSF00012-UGAVITATHEME0000/*.rif
* LiveArea - EP9000-PCSF00012_00-0000000000000000: http://livearea.np.dl.playstation.net/livearea/e/info/np/PCSF00012/f25c3f014a72dbac0b727f051802d7e964f09333c5c71896df7bc3d8d0403b07/PCSF00012-0.pkg
  * ur0:appmeta/PCSF00012/*

### PSP (EU) - NPEG00001 - Beats - Small Size
* Game 1.0 - EP9000-NPEG00001_00-SCEBEATS20071003 (236.0 MiB): http://zeus.dl.playstation.net/cdn/EP9000/NPEG00001_00/Sh8o5XfmsUBPwsYmA4g38MLTUAbUvK4eo4Umf23bsFUWbMbr7s0lMqxaH2eVLQV53SjGlsmWnR2CLYLOngdldSRPPAkUAvrLaw600.pkg

### PSP (US) - UCUS98744 - LittleBigPlanet
* Game 2.0 - UP9000-UCUS98744_00-LBPPSPAFULL00001: http://zeus.dl.playstation.net/cdn/UP9000/UCUS98744_00/QUrbJ75dAHp1Ap2xbKWRnGD7sKBOQhIGsE2e68nfVpUhR5kBGfatNc6uQc8iou99pcYh3686lGGwv20g3E0OptUnaKW71bm0fYQbP.pkg
  * ux0:pspemu/PSP/GAME/UCUS98744/*
  * ux0:pspemu/PSP/LICENSE/UP9000-UCUS98744_00-LBPPSPAFULL00001.rif
* Patch 2.02 - UP9000-UCUS98744_00-LBPPDLCSONYPA002:
http://zeus.dl.playstation.net/cdn/UP9000/UCUS98744_00/JS2QY6Iq0Nlx5JIvskoV1dKFLt9GKtUj9xga3hseXKhNTYeeYRh9Nb2a3i19GWb4MWSsoVaOTqrXoeuSmtLPw0wqxegUqfGWKEKTt.pkg
  * ux0:pspemu/PSP/GAME/UCUS98744/PBOOT.PBP
* Patch 2.05 - UP9000-UCUS98744_00-LBPPDLCSONYPA002: http://zeus.dl.playstation.net/cdn/UP9000/UCUS98744_00/g7DaaHVpsHMYPNSiF1TlV4WnKDGBjhGQ91vQvU7RJpP5tsTSxGs2cjhNciqno8HcqJIgDJGgl7gorOWtWsxkcQRDU3svKcWjd3R15.pkg
  * ux0:pspemu/PSP/GAME/UCUS98744/(PBOOT.PBP|*.arc)
* DLC Sack Circus Extravaganza Costume - UP9000-UCUS98744_00-LBPPDLCSONYCK015: http://zeus.dl.playstation.net/cdn/UP9000/UCUS98744_00/C0UWt4DcAfKWPvHUjDVfme6y6smJJNYO1UKGMQ0ThYv6gE89xoqD3uVQ6XnHogHQMs36oqxqWVBd247iJ1un4jLWl7En27aDnJfss.pkg
  * ux0:pspemu/PSP/GAME/UCUS98744/sackcircuscostume.lbppsp.edat
  * ux0:pspemu/PSP/LICENSE/UP9000-UCUS98744_00-LBPPDLCSONYCK015.rif

### PS3 (US) - NPUB31200 - Hotline Miami - Single Package
* Game 1.03 - UP3643-NPUB31200_00-HOTLINEMIAMI0000 (564.7 MiB): http://zeus.dl.playstation.net/cdn/UP3643/NPUB31200_00/frGBHyCbJSfeRJFOVZvBKRSLSXgbkrxBhCItFUVOowEUNEoOqOfYuCzjbCZoGCvN.pkg

### PS3 (EU) - NPEB02026 - Diablo III - Multi-Part-Package
* Game 1.0 - EP0002-NPEB02026_00-D3ULTIMATEEVIL00 (21.8 GiB): http://hfs.dl.playstation.net/cdn/EP0002/NPEB02026_00/EP0002-NPEB02026_00-D3ULTIMATEEVIL00_ojEJre1DH3gRcOcyNckmwls1Ik7tFafmqqEx3OGsMSs6faElDbwd4IS4bwpjq2QR.pkg.xml

### PS4 (US) - CUSA00368: - Hotline Miami 2: Wrong Number - Single Package
* Game 1.03 - UP3643-CUSA00368_00-HOTLINEMIAMI2000 (402.6 MiB): http://gs2.ww.prod.dl.playstation.net/gs2/appkgo/prod/CUSA00368_00/4/f_82bbe229d1d83b20c6fe68fed118af394a324e41c5806fb5f98a20d14747f822/f/UP3643-CUSA00368_00-HOTLINEMIAMI2000.json

### PS4 (JP) - CUSA02864 - NBA 2K16 - Multi-Part-Package
* Game 1.0 - JP0230-CUSA02864_00-NBA2K16000000000 (41.1 GiB): http://gs2.ww.prod.dl.playstation.net/gs2/appkgo/prod/CUSA02864_00/1/f_3f37ba0d06cb2fa2310c61f9a2d8151c0a16ab3af63d300630e79f6c123fb69e/f/JP0230-CUSA02864_00-NBA2K16000000000.json

### PS3 (EU) - NPIA00005 - PlayStation Home - Debug Package
* Game 1.21: http://nopsn.com/pkg/ps3/playstation-home/debug/PlayStation-Home-v1.21-%5BNPIA00005%5D-DEBUG.pkg
