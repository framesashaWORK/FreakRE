rule PEDosStub
{
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        $dos
}

rule QwenAiTrace
{
    strings:
        $qwen = "chat.qwen.ai" ascii
        $dash = "dashscope.aliyuncs.com" ascii
    condition:
        $qwen or $dash
}

// ─── PowerShell obfuscation / loader patterns ──────────────────────
rule PSEncodedCommand
{
    strings:
        $a = "-EncodedCommand" ascii nocase
        $b = " -enc " ascii nocase
        $c = "-EncodedComman" ascii nocase
    condition:
        any of them
}

rule PSDownloadCradle
{
    strings:
        $a = "DownloadString" ascii nocase
        $b = "DownloadFile" ascii nocase
        $c = "DownloadData" ascii nocase
        $d = "IEX (New-Object" ascii nocase
        $e = "Invoke-WebRequest" ascii nocase
        $f = "iwr " ascii nocase
    condition:
        any of them
}

rule PSAmsiBypass
{
    strings:
        $a = "AmsiInitFailed" ascii nocase
        $b = "AmsiUtils" ascii nocase
        $c = "amsi.dll" ascii nocase
        $d = "amsiInitFailed" ascii
    condition:
        any of them
}

rule PSDefenderTamper
{
    strings:
        $a = "Set-MpPreference" ascii nocase
        $b = "Add-MpPreference" ascii nocase
        $c = "-ExclusionPath" ascii nocase
        $d = "DisableRealtimeMonitoring" ascii nocase
    condition:
        any of them
}

rule PSReflectiveInjection
{
    strings:
        $a = "VirtualAlloc" ascii nocase
        $b = "CreateThread" ascii nocase
        $c = "WriteProcessMemory" ascii nocase
        $d = "QueueUserAPC" ascii nocase
        $e = "Reflection.Emit" ascii nocase
    condition:
        $a and ($b or $c or $d or $e)
}

// ─── AutoIt / AHK stealer / loader patterns ───────────────────────
rule AutoItScript
{
    strings:
        $a = "Func " ascii
        $b = "EndFunc" ascii
        $c = "AutoIt" ascii nocase
        $d = "DllCall" ascii
        $e = "FileInstall" ascii
    condition:
        $a and $b and ($d or $e)
}

rule AutoHotkeyScript
{
    strings:
        $a = "#SingleInstance" ascii nocase
        $b = "AutoHotkey" ascii nocase
        $c = "Send," ascii
        $d = "DllCall" ascii
    condition:
        $a or $b or ($c and $d)
}

// ─── VBScript / Batch download cradles ─────────────────────────────
rule VBSAdodbStream
{
    strings:
        $a = "ADODB.Stream" ascii nocase
        $b = "Msxml2.XMLHTTP" ascii nocase
        $c = "Msxml2.ServerXMLHTTP" ascii nocase
    condition:
        any of them
}

rule BatchCertutilDownload
{
    strings:
        $a = "certutil -urlcache" ascii nocase
        $b = "certutil -decode" ascii nocase
        $c = "bitsadmin /transfer" ascii nocase
    condition:
        any of them
}

// ─── PDF malicious patterns ────────────────────────────────────────
rule PDFJavaScript
{
    strings:
        $a = "/JavaScript" ascii
        $b = "/JS (" ascii
    condition:
        any of them
}

rule PDFOpenAction
{
    strings:
        $a = "/OpenAction" ascii
        $b = "/AA " ascii
    condition:
        any of them
}

rule PDFEmbeddedExe
{
    strings:
        $a = { 4D 5A } // MZ
        $b = { 4D 5A 90 00 03 00 00 00 }
    condition:
        // Heuristic: 2+ MZ signatures in 1MB window (single MZ is normal for the header itself)
        #a > 1
}

rule PDFLaunchAction
{
    strings:
        $a = "/Launch" ascii
        $b = "/SubmitForm" ascii
        $c = "/ImportData" ascii
    condition:
        any of them
}

rule PDFEncrypted
{
    strings:
        $a = "/Encrypt" ascii
    condition:
        $a
}

// ─── PyInstaller / Python stealer indicators ───────────────────────
rule PyInstallerBundle
{
    strings:
        $a = "MEI\x0C\x0B\x0A\x0B\x0E"
        $b = "PyInstaller" ascii
        $c = "pyi-" ascii
        $d = "pyi_rth" ascii
        $e = "pyi-bootloader" ascii
    condition:
        any of them
}

rule PythonStealerImports
{
    strings:
        $a = "browser_cookie3" ascii
        $b = "Cryptodome" ascii
        $c = "pyperclip" ascii
        $d = "pyautogui" ascii
        $e = "pynput.keyboard" ascii
        $f = "mss" ascii
        $g = "Crypto.Cipher" ascii
        $h = "wallet.dat" ascii
    condition:
        2 of them
}

// ─── .NET suspicious patterns ──────────────────────────────────────
rule DotNetReflectionShellcode
{
    strings:
        $a = "System.Reflection.Assembly" ascii
        $b = "VirtualAlloc" ascii
        $c = "CreateThread" ascii
        $d = "LoadLibrary" ascii
        $e = "GetProcAddress" ascii
    condition:
        $a and any of ($b, $c, $d, $e)
}

rule DotNetPowerShellHost
{
    strings:
        $a = "System.Management.Automation" ascii
        $b = "PowerShell.Create" ascii
    condition:
        any of them
}

// ─── UEFI / firmware patterns ──────────────────────────────────────
rule UEFIFirmwareVolume
{
    strings:
        $a = "_FVH" ascii
    condition:
        $a
}

rule UEFIEfiGuid
{
    strings:
        $a = { 8C 8C E5 78 8A 3D 4F 1C 99 35 89 61 85 C3 2D D3 }
    condition:
        $a
}

rule EFIApplicationImage
{
    strings:
        $a = { 4D 5A } // MZ
        $b = { 0B 01 } // Subsystem EFI_APPLICATION (PE32)
        $c = { 0B 02 } // Subsystem EFI_APPLICATION (PE32+)
        $d = { 0C 02 } // Subsystem EFI_BOOT_SERVICE_DRIVER
    condition:
        all of them
}

// ─── Memory dump patterns ──────────────────────────────────────────
rule WindowsMinidump
{
    strings:
        $a = { 4D 44 4D 50 93 C7 53 } // MDMP + signature1
    condition:
        $a
}

rule MinidumpMalwareTrace
{
    strings:
        $a = "mimikatz" ascii nocase
        $b = "lazagne" ascii nocase
        $c = "rclone" ascii nocase
        $d = "cobaltstrike" ascii nocase
        $e = "meterpreter" ascii nocase
        $f = "beacon.dll" ascii nocase
    condition:
        any of them
}

// ─── Packer / Cryptor detection ────────────────────────────────────
rule UPXPacker
{
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX2" ascii
        $d = "UPX!" ascii
        $e = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B }
    condition:
        any of them
}

rule ASPackPacker
{
    strings:
        $a = ".aspack" ascii nocase
        $b = "ASPack" ascii
        $c = { 00 61 73 70 61 63 6B 00 }
    condition:
        any of them
}

rule ThemidaOrePacker
{
    strings:
        $a = ".themida" ascii nocase
        $b = "Ore" ascii
        $c = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }
    condition:
        any of them
}

rule VMProtectPacker
{
    strings:
        $a = ".vmp0" ascii nocase
        $b = ".vmp1" ascii nocase
        $c = ".vmp2" ascii nocase
        $d = "VMProtect" ascii nocase
    condition:
        any of them
}

rule PECompactPacker
{
    strings:
        $a = "PEC2" ascii
        $b = "PEC2MO" ascii
        $c = "petite" ascii nocase
    condition:
        any of them
}

rule EnigmaPacker
{
    strings:
        $a = "ENIGMA" ascii
        $b = ".enigma1" ascii nocase
        $c = ".enigma2" ascii nocase
    condition:
        any of them
}

rule GenericPackerSection
{
    strings:
        $a = { 2E 70 61 63 6B 00 00 00 } // .pack
        $b = { 2E 70 65 74 69 74 6C 65 00 } // .petite
        $c = { 2E 6E 75 74 70 61 63 6B 00 } // .nupack
        $d = { 2E 6D 65 77 70 61 63 6B 00 } // .mewpack
    condition:
        any of them
}

rule HighEntropySection
{
    strings:
        $a = { 2E 76 6D 70 00 } // .vmp
        $b = { 2E 76 6D 70 30 00 } // .vmp0
        $c = { 2E 76 6D 70 31 00 } // .vmp1
    condition:
        any of them
}

rule PackerOverlay
{
    strings:
        $a = "This program must be run under Win32" ascii
        $b = "UPX Version" ascii nocase
        $c = "ASPack" ascii nocase
    condition:
        any of them
}

// ─── Code injection detection ──────────────────────────────────────
rule ProcessInjectionAPIs
{
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtCreateThreadEx" ascii
        $e = "RtlCreateUserThread" ascii
        $f = "QueueUserAPC" ascii
        $g = "NtQueueApcThread" ascii
        $h = "SetThreadContext" ascii
    condition:
        2 of them
}

rule ReflectiveDLLInjection
{
    strings:
        $a = "ReflectiveLoader" ascii
        $b = "IMAGE_DIRECTORY_ENTRY_EXPORT" ascii
        $c = { 55 8B EC 83 EC ?? 53 56 57 E8 ?? ?? ?? ?? 83 C4 ?? }
    condition:
        any of them
}

rule ProcessHollowing
{
    strings:
        $a = "NtUnmapViewOfSection" ascii
        $b = "ZwUnmapViewOfSection" ascii
        $c = "NtWriteVirtualMemory" ascii
        $d = "ZwWriteVirtualMemory" ascii
    condition:
        2 of them
}

rule AtomBombing
{
    strings:
        $a = "GlobalAddAtomW" ascii
        $b = "GlobalGetAtomNameW" ascii
        $c = "NtQueueApcThread" ascii
    condition:
        all of them
}

rule EarlyBirdInjection
{
    strings:
        $a = "CreateProcessW" ascii
        $b = "CreateProcessA" ascii
        $c = "WriteProcessMemory" ascii
        $d = "ResumeThread" ascii
    condition:
        ($a or $b) and $c and $d
}

rule APCInjection
{
    strings:
        $a = "OpenThread" ascii
        $b = "QueueUserAPC" ascii
        $c = "NtQueueApcThread" ascii
        $d = "ResumeThread" ascii
    condition:
        3 of them
}

// ─── C2 communication detection ────────────────────────────────────
rule CobaltStrikeBeacon
{
    strings:
        $a = "beacon.dll" ascii nocase
        $b = "cobaltstrike" ascii nocase
        $c = "rapid7" ascii nocase
        $d = { 68 00 20 00 00 68 00 10 00 00 } // Beacon config marker
    condition:
        any of them
}

rule MetasploitPayload
{
    strings:
        $a = "meterpreter" ascii nocase
        $b = "metsrv" ascii nocase
        $c = "reverse_tcp" ascii nocase
        $d = "reverse_http" ascii nocase
        $e = "bind_tcp" ascii nocase
    condition:
        any of them
}

rule C2HTTPComm
{
    strings:
        $a = "User-Agent: Mozilla/4.0" ascii
        $b = "POST /gate.php" ascii nocase
        $c = "POST /submit.php" ascii nocase
        $d = "POST /panel" ascii nocase
        $e = "GET /download?id=" ascii nocase
        $f = "Cookie: session=" ascii nocase
    condition:
        2 of them
}

rule C2DNSComm
{
    strings:
        $a = "DnsQuery_A" ascii
        $b = "DnsQuery_W" ascii
        $c = "InternetOpenA" ascii
        $d = "InternetOpenW" ascii
        $e = "InternetConnectA" ascii
        $f = "HttpOpenRequestA" ascii
    condition:
        3 of them
}

rule C2RawSocket
{
    strings:
        $a = "WSAStartup" ascii
        $b = "socket(" ascii
        $c = "connect(" ascii
        $d = "send(" ascii
        $e = "recv(" ascii
        $f = "SOCK_STREAM" ascii
    condition:
        3 of them
}

rule EncryptedC2Channel
{
    strings:
        $a = "CryptEncrypt" ascii
        $b = "CryptDecrypt" ascii
        $c = "InternetWriteFile" ascii
        $d = "HttpSendRequest" ascii
    condition:
        ($a or $b) and ($c or $d)
}

// ─── Anti-analysis techniques ──────────────────────────────────────
rule AntiDebugAPIs
{
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
        $d = "OutputDebugStringA" ascii
        $e = "OutputDebugStringW" ascii
        $f = "NtSetInformationThread" ascii
        $g = "GetTickCount" ascii
        $h = "QueryPerformanceCounter" ascii
    condition:
        3 of them
}

rule AntiVM
{
    strings:
        $a = "VMware" ascii nocase
        $b = "VirtualBox" ascii nocase
        $c = "VBOX" ascii
        $d = "SbieDll" ascii // Sandboxie
        $e = "sbiedll.dll" ascii nocase
        $f = "CWSandbox" ascii nocase
        $g = "wine_get_unix_file_name" ascii // Wine
        $h = "Xen" ascii
    condition:
        2 of them
}

rule AntiEmulation
{
    strings:
        $a = "NtCanMoveForward" ascii
        $b = "NtCurrentPeb" ascii
        $c = "NtGlobalFlag" ascii
        $d = { 64 A1 30 00 00 00 } // mov eax, dword ptr fs:[0x30] (PEB)
        $e = { 65 48 8B 04 25 60 00 00 00 } // mov rax, qword ptr gs:[0x60] (PEB64)
    condition:
        2 of them
}

rule AntiSandbox
{
    strings:
        $a = "SbieDLL.dll" ascii nocase
        $b = "sbiedll.dll" ascii nocase
        $c = "SandboxieDcomLaunch" ascii
        $d = "SandboxieRpcSs" ascii
        $e = "cmd.exe /c echo" ascii
    condition:
        2 of them
}

rule AntiDripCampaign
{
    strings:
        $a = "John the Ripper" ascii nocase
        $b = "hashcat" ascii nocase
        $c = "mimikatz" ascii nocase
        $d = "lazagne" ascii nocase
        $e = "Responder" ascii nocase
    condition:
        any of them
}

rule ObfuscatedStrings
{
    strings:
        $a = { 2B 41 2B 41 2B 41 2B 41 } // +A+A+A+A (XOR loop)
        $b = { 33 C0 8A 04 ?? 34 ?? 88 04 ?? 40 } // XOR decoding loop
        $c = { 80 34 ?? ?? 40 } // XOR byte decode
        $d = { 80 3C ?? ?? 74 } // XOR + conditional jump
    condition:
        any of them
}

rule CodeVirtualization
{
    strings:
        $a = ".vmp0" ascii nocase
        $b = ".vmp1" ascii nocase
        $c = "VMProtect" ascii nocase
        $d = { 55 8B EC 83 EC ?? C7 45 } // VM entry prologue
    condition:
        any of them
}

rule AntiDump
{
    strings:
        $a = "NtUnmapViewOfSection" ascii
        $b = "ZwUnmapViewOfSection" ascii
        $c = "NtProtectVirtualMemory" ascii
        $d = "VirtualProtect" ascii
    condition:
        2 of them
}
