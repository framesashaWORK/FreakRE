# FreakRE YARA Rule Cookbook

Quick-reference for writing YARA rules compatible with FreakRE's YARA-lite engine.

## Basic Structure

```yara
rule RuleName
{
    meta:
        author = "Analyst"
        description = "What this rule detects"
        severity = "high"

    strings:
        $text = "hello world" ascii
        $hex = { 4D 5A 90 00 }
        $regex = /pattern[0-9]+/

    condition:
        any of them
}
```

## String Modifiers

### Text patterns
```yara
$s1 = "cmd.exe" ascii              // case-sensitive ASCII
$s2 = "cmd.exe" nocase             // case-insensitive
$s3 = "cmd.exe" wide               // UTF-16LE (2 bytes per char)
$s4 = "cmd.exe" ascii wide         // both ASCII and wide variants
$s5 = "cmd.exe" fullword           // whole-word match only
$s6 = "cmd.exe" xor                // XOR with any key (0-255)
$s7 = "cmd.exe" nocase wide fullword
```

### Hex patterns
```yara
$h1 = { 4D 5A }                         // exact bytes
$h2 = { 4D 5A ?? 90 }                   // wildcard byte
$h3 = { 4D 5A 90 ?? ?? }                // multiple wildcards
$h4 = { (4D | 5A) 90 }                  // alternation
$h5 = { 4D 5A [0-10] 45 46 }            // jump (0-10 bytes between)
$h6 = { 4D 5A [3] 45 46 }               // exactly 3 bytes skip
$h7 = { 4D 5A [0-] 45 46 }             // unbounded jump
```

### Regex patterns
```yara
$r1 = /http:\/\/[a-z]+\.com/i
$r2 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/   // IP address
```

## Conditions

### Basic operators
```yara
condition:
    $text                          // any match
    #text > 3                      // count of matches
    filesize < 1MB                 // file size
    entrypoint == 0x1000           // PE entry point
    offset == 0                    // alias for entrypoint
```

### Integer expressions
```yara
condition:
    filesize == 4 + 4              // arithmetic: 8
    uint16(0) == 0x5A4D           // read 2 bytes at offset 0
    uint32(60) == 0x00010000      // PE offset
    int16(0) == -1                 // signed read
    int32(4) > 1000                // signed comparison
    math.hash(0, 64) > 0           // FNV-1a hash of first 64 bytes
```

### Combining
```yara
condition:
    $a and $b                      // both match
    $a or $b                       // either matches
    not $a                         // negation
    ($a or $b) and $c              // grouped
    2 of ($a, $b, $c)              // N of them
    all of them                    // all strings match
    any of them                    // any string matches
```

### Position constraints
```yara
condition:
    $a at 0                        // match at fixed offset
    $a at @b                       // match at same offset as $b
    $a in (0..100)                 // match within range
    $a in (0..filesize)            // match anywhere
```

### PE module (partial support)
```yara
condition:
    pe.number_of_sections > 5      // section count
    pe.imports("kernel32.dll")     // import check
    pe.sections(".text")           // section exists
```

## Practical Examples

### Detect Packer
```yara
rule UPX_Packer
{
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        any of them
}
```

### Detect Injection
```yara
rule Process_Injection
{
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        2 of them
}
```

### Detect C2 Beacon
```yara
rule C2_Beacon
{
    strings:
        $ua = "User-Agent: Mozilla/4.0" ascii
        $post = "POST /gate.php" ascii
        $cookie = "Cookie: session=" ascii
    condition:
        $ua and ($post or $cookie)
}
```

### Detect PowerShell Obfuscation
```yara
rule PS_Obfuscation
{
    strings:
        $enc = "-EncodedCommand" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $invoke = "IEX (New-Object" ascii nocase
    condition:
        any of them
}
```

### Detect Anti-Debug
```yara
rule Anti_Debug
{
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
    condition:
        2 of them
}
```

### Detect Cobalt Strike
```yara
rule Cobalt_Strike_Beacon
{
    strings:
        $a = "beacon.dll" ascii nocase
        $b = "cobaltstrike" ascii nocase
        $config = { 68 00 20 00 00 68 00 10 00 00 }
    condition:
        any of them
}
```

## Supported Features Summary

| Feature | Status |
|---------|--------|
| Text patterns | ✅ Full |
| Hex patterns (literals, wildcards) | ✅ Full |
| Hex alternation `(A \| B)` | ✅ Full |
| Hex jumps `[N-M]` | ✅ Full |
| Regex patterns | ✅ Full |
| `ascii`, `wide`, `nocase`, `fullword` | ✅ Full |
| `xor` modifier | ✅ Full (256 variants) |
| `at`, `in` on strings | ✅ Full |
| `filesize`, `entrypoint`, `offset` | ✅ Full |
| `uint8/16/32`, `int8/16/32` | ✅ Full |
| `math.hash(offset, len)` | ✅ Full |
| Arithmetic `+`, `-`, `*`, `/` | ✅ Full |
| `pe.number_of_sections` | ✅ Full |
| `pe.imports("dll")` | ✅ Full |
| `pe.sections(".name")` | ✅ Full |
| `for all X : (cond)` | ❌ Not yet |
| `cuckoo.` module | ❌ Not yet |
| `import "pe"` declaration | ❌ Optional |
