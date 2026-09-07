param(
    [Parameter(Mandatory = $true)]
    [string]$Source,
    [string]$Destination = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $Source "check"
}
if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
    throw "Source directory does not exist: $Source"
}
if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

function Read-U16([byte[]]$Data, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 2 -gt $Data.Length) { return $null }
    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Read-U32([byte[]]$Data, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Data.Length) { return $null }
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Get-PeKind([string]$Path) {
    try {
        $Data = [IO.File]::ReadAllBytes($Path)
        if ($Data.Length -lt 64 -or $Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
            return [pscustomobject]@{ Selected = $false; Reason = "not_pe"; Architecture = $null; Machine = $null }
        }
        $Nt = Read-U32 $Data 0x3C
        if ($null -eq $Nt -or $Nt -gt $Data.Length - 24 -or (Read-U32 $Data $Nt) -ne 0x00004550) {
            return [pscustomobject]@{ Selected = $false; Reason = "bad_pe_headers"; Architecture = $null; Machine = $null }
        }

        $Machine = Read-U16 $Data ($Nt + 4)
        $Architecture = switch ($Machine) {
            0x014c { "x86" }
            0x8664 { "x64" }
            0x01c4 { "arm" }
            0xAA64 { "arm64" }
            default { $null }
        }
        if ($null -eq $Architecture) {
            return [pscustomobject]@{ Selected = $false; Reason = "unsupported_machine"; Architecture = $null; Machine = ("0x{0:X4}" -f $Machine) }
        }

        $Optional = $Nt + 24
        $Magic = Read-U16 $Data $Optional
        $DirectoryOffset = switch ($Magic) {
            0x010B { 96 }
            0x020B { 112 }
            default { $null }
        }
        if ($null -eq $DirectoryOffset) {
            return [pscustomobject]@{ Selected = $false; Reason = "bad_optional_header"; Architecture = $Architecture; Machine = ("0x{0:X4}" -f $Machine) }
        }

        # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR) is index 14.
        $ClrDirectory = $Optional + $DirectoryOffset + (14 * 8)
        $ClrRva = Read-U32 $Data $ClrDirectory
        $ClrSize = Read-U32 $Data ($ClrDirectory + 4)
        if (($null -ne $ClrRva -and $ClrRva -ne 0) -or ($null -ne $ClrSize -and $ClrSize -ne 0)) {
            return [pscustomobject]@{ Selected = $false; Reason = "dotnet_clr"; Architecture = $Architecture; Machine = ("0x{0:X4}" -f $Machine) }
        }

        return [pscustomobject]@{ Selected = $true; Reason = "native_pe"; Architecture = $Architecture; Machine = ("0x{0:X4}" -f $Machine) }
    }
    catch {
        return [pscustomobject]@{ Selected = $false; Reason = "read_error"; Architecture = $null; Machine = $null }
    }
}

$SourceFull = [IO.Path]::GetFullPath($Source).TrimEnd('\')
$DestinationFull = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
$Manifest = [Collections.Generic.List[object]]::new()
$SelectedCount = 0
$SelectedBytes = [int64]0

$Files = Get-ChildItem -LiteralPath $SourceFull -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "$DestinationFull\*" }

foreach ($File in $Files) {
    $Kind = Get-PeKind $File.FullName
    $Relative = $File.FullName.Substring($SourceFull.Length).TrimStart('\')
    $DestinationPath = $null

    if ($Kind.Selected) {
        $DestinationPath = Join-Path $DestinationFull $Relative
        $Parent = Split-Path -Parent $DestinationPath
        if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
            New-Item -ItemType Directory -Path $Parent -Force | Out-Null
        }
        Copy-Item -LiteralPath $File.FullName -Destination $DestinationPath -Force
        $SelectedCount++
        $SelectedBytes += $File.Length
    }

    $Manifest.Add([pscustomobject]@{
        source = $Relative
        destination = if ($null -eq $DestinationPath) { $null } else { $DestinationPath.Substring($DestinationFull.Length).TrimStart('\') }
        size = $File.Length
        machine = $Kind.Machine
        architecture = $Kind.Architecture
        selected = $Kind.Selected
        reason = $Kind.Reason
    })
}

$Manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $DestinationFull "manifest.json") -Encoding UTF8
"selected=$SelectedCount"
"selected_bytes=$SelectedBytes"
"rejected=$($Manifest.Count - $SelectedCount)"
"manifest=$(Join-Path $DestinationFull 'manifest.json')"
