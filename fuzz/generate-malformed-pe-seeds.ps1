[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$WriteFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot 'corpus/generated-pe'
}

# These are synthetic parser inputs only. They are never executed or downloaded.
$seeds = [ordered]@{
    'empty.bin' = [byte[]]@()
    'mz-truncated.bin' = [byte[]]@(0x4D, 0x5A, 0x00, 0x00)
    'mz-bad-header-offset.bin' = [byte[]]@(0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    'pe-signature-only.bin' = [byte[]]@(0x50, 0x45, 0x00, 0x00)
    'mz-and-pe-at-zero.bin' = [byte[]]@(0x4D, 0x5A, 0x50, 0x45, 0x00, 0x00)
    'high-entropy-short.bin' = [byte[]](0..255)
}

if (-not $WriteFiles) {
    $seeds.GetEnumerator() | ForEach-Object {
        '{0}: {1} bytes' -f $_.Key, $_.Value.Length
    }
    Write-Host 'Dry run. Pass -WriteFiles to create the local generated corpus.'
    exit 0
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
foreach ($seed in $seeds.GetEnumerator()) {
    [System.IO.File]::WriteAllBytes((Join-Path $OutputDirectory $seed.Key), $seed.Value)
}

Write-Host ("Wrote {0} synthetic seeds to {1}" -f $seeds.Count, $OutputDirectory)
