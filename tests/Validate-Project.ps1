\
param(
    [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'CrackShell.ps1')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "Source file not found: $ScriptPath"
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_.Message }
    throw "PowerShell syntax validation failed with $($parseErrors.Count) error(s)."
}

$source = Get-Content -LiteralPath $ScriptPath -Raw
$required = @(
    '$form.Text = ''CrackShell''',
    'OpenStego Cracker',
    'Hash Solver',
    "'MD5','SHA1','SHA256','SHA384','SHA512','AES'",
    'openstego.jar',
    '& java @args',
    'function Get-StringDistance',
    'Use only on files and hashes you own or are authorized to test.'
)
foreach ($item in $required) {
    if (-not $source.Contains($item)) { throw "Required feature marker missing: $item" }
}

$networkPatterns = 'Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|System\.Net\.Http\.HttpClient'
if ($source -match $networkPatterns) {
    throw 'Unexpected network-capable code was found in CrackShell.ps1.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Write-Host 'CrackShell validation passed.'
