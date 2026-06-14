// ==========================================================================
// 默认 YARA 规则集 - 常见恶意软件特征
// ==========================================================================

// --------------------------------------------------------------------------
// 通用 PE/可执行文件检测
// --------------------------------------------------------------------------
rule PE_Executable
{
    meta:
        description = "检测 Windows PE 可执行文件"
        author = "Malware Analysis Team"
        category = "identifier"

    strings:
        $mz = "MZ"

    condition:
        $mz at 0
}

rule ELF_Executable
{
    meta:
        description = "检测 Linux ELF 可执行文件"
        author = "Malware Analysis Team"
        category = "identifier"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0
}

// --------------------------------------------------------------------------
// 打包/混淆工具检测
// --------------------------------------------------------------------------
rule Packer_UPX
{
    meta:
        description = "检测 UPX 加壳的可执行文件"
        author = "Malware Analysis Team"
        category = "packer"
        family = "UPX"

    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX2"

    condition:
        any of them
}

rule Packer_ASPack
{
    meta:
        description = "检测 ASPack 加壳"
        author = "Malware Analysis Team"
        category = "packer"
        family = "ASPack"

    strings:
        $aspack = "ASPack"

    condition:
        $aspack
}

// --------------------------------------------------------------------------
// 常见恶意软件家族特征
// --------------------------------------------------------------------------
rule Generic_Suspicious_APIs
{
    meta:
        description = "检测调用可疑 API 的程序（注入、进程操作等）"
        author = "Malware Analysis Team"
        category = "suspicious"
        severity = "medium"

    strings:
        $api1 = "CreateRemoteThread" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "SetWindowsHookEx" ascii wide
        $api6 = "InternetOpenUrl" ascii wide
        $api7 = "HttpSendRequest" ascii wide
        $api8 = "URLDownloadToFile" ascii wide

    condition:
        3 of them
}

rule Generic_Registry_Persistence
{
    meta:
        description = "检测包含注册表持久化机制的程序"
        author = "Malware Analysis Team"
        category = "persistence"
        severity = "medium"

    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $reg3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide
        $reg4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" ascii wide

    condition:
        any of them
}

rule Generic_AntiDebug
{
    meta:
        description = "检测包含反调试技术的程序"
        author = "Malware Analysis Team"
        category = "anti_analysis"
        severity = "low"

    strings:
        $ad1 = "IsDebuggerPresent" ascii wide
        $ad2 = "CheckRemoteDebuggerPresent" ascii wide
        $ad3 = "OutputDebugString" ascii wide
        $ad4 = "NtQueryInformationProcess" ascii wide

    condition:
        2 of them
}

rule Generic_Credential_Theft
{
    meta:
        description = "检测疑似凭据窃取的程序"
        author = "Malware Analysis Team"
        category = "credential_theft"
        severity = "high"
        family = "credential"

    strings:
        $pwd1 = "samlib.dll" ascii wide
        $pwd2 = "crypt32.dll" ascii wide
        $pwd3 = "advapi32.dll" ascii wide
        $pwd4 = "LsaEnumerateLogonSessions" ascii wide
        $pwd5 = "LsaGetLogonSessionData" ascii wide
        $pwd6 = "Mimikatz" ascii wide
        $pwd7 = "sekurlsa" ascii wide

    condition:
        3 of them
}

rule Generic_Ransomware_Indicators
{
    meta:
        description = "检测勒索软件特征"
        author = "Malware Analysis Team"
        category = "ransomware"
        severity = "critical"
        family = "ransomware"

    strings:
        $r1 = "vssadmin" ascii wide
        $r2 = "Delete Shadows" ascii wide
        $r3 = "bcdedit" ascii wide
        $r4 = "Your files have been encrypted" ascii wide
        $r5 = "README.txt" ascii wide
        $r6 = "INSTRUCTION.txt" ascii wide
        $r7 = ".encrypted" ascii wide
        $r8 = ".locked" ascii wide
        $r9 = "bitcoin" ascii wide nocase
        $r10 = "CryptoAPI" ascii wide

    condition:
        3 of them
}

// --------------------------------------------------------------------------
// 网络行为特征
// --------------------------------------------------------------------------
rule Generic_C2_Communication
{
    meta:
        description = "检测疑似 C2 通信特征"
        author = "Malware Analysis Team"
        category = "c2"
        severity = "high"

    strings:
        $c21 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" ascii
        $c22 = "/cgi-bin/main.cgi" ascii
        $c23 = "/panel/index.php" ascii
        $c24 = "cmd=" ascii
        $c25 = "id=" ascii

    condition:
        2 of them
}

rule Generic_Reverse_Shell
{
    meta:
        description = "检测反弹 Shell 特征"
        author = "Malware Analysis Team"
        category = "backdoor"
        severity = "critical"

    strings:
        $rs1 = "/bin/sh" ascii
        $rs2 = "bash -i" ascii
        $rs3 = "nc -e" ascii
        $rs4 = "powershell -nop -exec bypass" ascii wide
        $rs5 = "socket.AF_INET" ascii

    condition:
        2 of them
}

// --------------------------------------------------------------------------
// 脚本类恶意检测
// --------------------------------------------------------------------------
rule Script_PowerShell_Suspicious
{
    meta:
        description = "检测可疑 PowerShell 脚本"
        author = "Malware Analysis Team"
        category = "script"
        severity = "high"

    strings:
        $ps1 = "IEX" ascii nocase
        $ps2 = "Invoke-Expression" ascii
        $ps3 = "DownloadString" ascii
        $ps4 = "FromBase64String" ascii
        $ps5 = "System.Net.WebClient" ascii
        $ps6 = "Add-MpPreference" ascii
        $ps7 = "Set-MpPreference" ascii
        $ps8 = "Net.WebClient" ascii

    condition:
        3 of them
}

rule Script_OBFUSCATED_Base64
{
    meta:
        description = "检测包含大量 Base64 编码的脚本"
        author = "Malware Analysis Team"
        category = "obfuscation"
        severity = "medium"

    strings:
        $b64 = /[A-Za-z0-9+\/=]{80,}/

    condition:
        2 of them
}

// --------------------------------------------------------------------------
// 挖矿程序特征
// --------------------------------------------------------------------------
rule Crypto_Miner
{
    meta:
        description = "检测加密货币挖矿程序"
        author = "Malware Analysis Team"
        category = "miner"
        severity = "medium"
        family = "cryptominer"

    strings:
        $m1 = "stratum+tcp://" ascii
        $m2 = "xmrig" ascii nocase
        $m3 = "minerd" ascii nocase
        $m4 = "cpuminer" ascii nocase
        $m5 = "monero" ascii nocase
        $m6 = "ethash" ascii nocase

    condition:
        2 of them
}
