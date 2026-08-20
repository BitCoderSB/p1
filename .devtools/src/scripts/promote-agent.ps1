param(
    [Parameter(Mandatory = $true)]
    [string]$StagingRoot,
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -cnotmatch "^v[0-9]+\.[0-9]+\.[0-9]+$") {
            throw "Version must use canonical lowercase semantic-version syntax."
        }
        $true
    })]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -cnotmatch "^[0-9a-f]{64}$") {
            throw "SourceDigest must be exactly 64 lowercase hexadecimal characters."
        }
        $true
    })]
    [string]$SourceDigest,
    [switch]$SessionsStopped
)

$ErrorActionPreference = "Stop"
if (-not $SessionsStopped) {
    throw "Promotion requires -SessionsStopped after stopping provider sessions and hook processes."
}

$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ActiveRoot = [System.IO.Path]::GetFullPath((Join-Path $SourceRoot "..\bin"))
$StagingRoot = [System.IO.Path]::GetFullPath($StagingRoot)
$NormalizedActive = $ActiveRoot.TrimEnd("\", "/")
$NormalizedStaging = $StagingRoot.TrimEnd("\", "/")
$PathComparison = if ($IsWindows -or $env:OS -eq "Windows_NT") {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}
if ($NormalizedActive.Equals($NormalizedStaging, $PathComparison)) {
    throw "Staging and active bin directories must be different."
}

$BinaryPaths = @(
    "windows/amd64/setup.exe",
    "windows/arm64/setup.exe",
    "linux/amd64/setup",
    "linux/arm64/setup",
    "macos/amd64/setup",
    "macos/arm64/setup"
)
$ReleasePaths = @($BinaryPaths + "SHA256SUMS" | Sort-Object)

function Assert-RegularDirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (
                -not $Item.PSIsContainer -or
                ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "Non-directory or reparse-point path refused: $Current"
            }
        }
        $Parent = Split-Path -Parent $Current
        if ([string]::IsNullOrEmpty($Parent) -or $Parent -eq $Current) {
            break
        }
        $Current = $Parent
    }
}

function Get-ReleaseFileSet {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$NormalizedRoot
    )
    @(
        Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
            if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release file is a reparse point: $($_.FullName)"
            }
            $_.FullName.Substring($NormalizedRoot.Length).TrimStart("\", "/").Replace("\", "/")
        } | Sort-Object
    )
}

function Assert-ExactReleaseFileSet {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$NormalizedRoot
    )
    foreach ($Entry in (Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
        if (($Entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release tree contains a reparse point: $($Entry.FullName)"
        }
    }
    $Actual = Get-ReleaseFileSet -Root $Root -NormalizedRoot $NormalizedRoot
    if (($Actual -join "`n") -cne ($ReleasePaths -join "`n")) {
        throw "Release tree must contain exactly six binaries and SHA256SUMS."
    }
}

function Assert-NoUnexpectedReleaseFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$NormalizedRoot
    )
    foreach ($Entry in (Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
        if (($Entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release tree contains a reparse point: $($Entry.FullName)"
        }
    }
    $Actual = Get-ReleaseFileSet -Root $Root -NormalizedRoot $NormalizedRoot
    foreach ($Relative in $Actual) {
        if ($ReleasePaths -cnotcontains $Relative) {
            throw "Active release tree contains an unexpected file: $Relative"
        }
    }
}

Assert-RegularDirectoryTree -Path $StagingRoot
Assert-RegularDirectoryTree -Path $ActiveRoot
Assert-ExactReleaseFileSet -Root $StagingRoot -NormalizedRoot $NormalizedStaging

# A killed promotion can leave only its random, regular temporary file. Remove
# those narrowly named artifacts so the same command can repair the release.
foreach ($Temporary in (Get-ChildItem -LiteralPath $ActiveRoot -Recurse -File -Force -Filter ".promote-*.tmp")) {
    if (
        $Temporary.Name -cnotmatch "^\.promote-(?:manifest-)?[0-9a-f]{32}(?:\.backup)?\.tmp$" -or
        ($Temporary.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Unsafe promotion temporary file refused: $($Temporary.FullName)"
    }
    [System.IO.File]::Delete($Temporary.FullName)
}
Assert-NoUnexpectedReleaseFiles -Root $ActiveRoot -NormalizedRoot $NormalizedActive

$PromotionEnvironmentNames = @(
    "CGO_ENABLED",
    "GOAMD64",
    "GOARCH",
    "GOARM64",
    "GOENV",
    "GOEXPERIMENT",
    "GOFIPS140",
    "GOFLAGS",
    "GOOS",
    "GOTOOLCHAIN",
    "GOWORK"
)
$SavedPromotionEnvironment = @{}
foreach ($Name in $PromotionEnvironmentNames) {
    $SavedPromotionEnvironment[$Name] = [System.Environment]::GetEnvironmentVariable($Name, "Process")
}

function Get-CurrentSourceDigest {
    Push-Location $SourceRoot
    try {
        $Digest = (& go run ./scripts/sourcehash).Trim()
        if ($LASTEXITCODE -ne 0 -or $Digest -cnotmatch "^[0-9a-f]{64}$") {
            throw "Source digest calculation failed."
        }
        return $Digest
    }
    finally {
        Pop-Location
    }
}

try {
    $env:CGO_ENABLED = "0"
    $env:GOAMD64 = "v1"
    $env:GOARM64 = "v8.0"
    $env:GOENV = "off"
    $env:GOEXPERIMENT = ""
    $env:GOFIPS140 = "off"
    $env:GOFLAGS = ""
    $env:GOTOOLCHAIN = "local"
    $env:GOWORK = "off"
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    $GoVersion = (& go version).Trim()
    if ($LASTEXITCODE -ne 0 -or $GoVersion -cnotmatch "^go version go1\.24\.13 ") {
        throw "Promotion validation requires the pinned Go 1.24.13 toolchain."
    }
    $CurrentDigest = Get-CurrentSourceDigest
    if ($CurrentDigest -cne $SourceDigest) {
        throw "Requested source digest does not match the current frozen source."
    }

$ManifestPath = Join-Path $StagingRoot "SHA256SUMS"
$ManifestInfo = Get-Item -LiteralPath $ManifestPath -Force
if ($ManifestInfo.Length -le 0 -or $ManifestInfo.Length -gt 4096) {
    throw "Manifest has an invalid size."
}
$ManifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
if (
    $ManifestBytes.Length -eq 0 -or
    $ManifestBytes[$ManifestBytes.Length - 1] -ne 10 -or
    ($ManifestBytes -contains 13) -or
    (
        $ManifestBytes.Length -ge 3 -and
        $ManifestBytes[0] -eq 0xEF -and
        $ManifestBytes[1] -eq 0xBB -and
        $ManifestBytes[2] -eq 0xBF
    )
) {
    throw "Manifest must be nonempty UTF-8 without BOM, use LF only, and end with LF."
}
$StrictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
$ManifestText = $StrictUtf8.GetString($ManifestBytes)
$ManifestLines = @($ManifestText.Substring(0, $ManifestText.Length - 1).Split("`n"))
if ($ManifestLines.Count -ne 6) {
    throw "Manifest must contain exactly six lines."
}
$ManifestHashes = [System.Collections.Generic.Dictionary[string, string]]::new(
    [System.StringComparer]::Ordinal
)
foreach ($Line in $ManifestLines) {
    if ($Line -cnotmatch "^([0-9a-f]{64})  ((?:windows|linux|macos)/(?:amd64|arm64)/setup(?:\.exe)?)$") {
        throw "Manifest contains a malformed line."
    }
    $Hash = $Matches[1]
    $Relative = $Matches[2]
    if ($BinaryPaths -cnotcontains $Relative -or $ManifestHashes.ContainsKey($Relative)) {
        throw "Manifest contains an unexpected or duplicate path."
    }
    $ManifestHashes.Add($Relative, $Hash)
}
if ($ManifestHashes.Count -cne $BinaryPaths.Count) {
    throw "Manifest does not cover the exact binary target set."
}

foreach ($Relative in $BinaryPaths) {
    $Source = Join-Path $StagingRoot $Relative.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $SourceInfo = Get-Item -LiteralPath $Source -Force
    if ($SourceInfo.Length -le 0 -or $SourceInfo.Length -gt 128MB) {
        throw "Staging binary has an invalid size for $Relative."
    }
    $Hash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Hash -cne $ManifestHashes[$Relative]) {
        throw "Staging hash mismatch for $Relative."
    }
    $Parts = $Relative.Split("/")
    $ExpectedGOOS = if ($Parts[0] -ceq "macos") { "darwin" } else { $Parts[0] }
    $ExpectedGOARCH = $Parts[1]
    $Metadata = (& go version -m $Source 2>&1 | Out-String)
    if (
        $LASTEXITCODE -ne 0 -or
        $Metadata -cnotmatch ("go1\.24\.13") -or
        $Metadata -cnotmatch [regex]::Escape("GOOS=$ExpectedGOOS") -or
        $Metadata -cnotmatch [regex]::Escape("GOARCH=$ExpectedGOARCH") -or
        $Metadata -cnotmatch [regex]::Escape("CGO_ENABLED=0") -or
        $Metadata -cnotmatch [regex]::Escape("-trimpath=true")
    ) {
        throw "Go build metadata mismatch for $Relative."
    }
    if (
        $ExpectedGOARCH -ceq "amd64" -and
        $Metadata -cnotmatch [regex]::Escape("GOAMD64=v1")
    ) {
        throw "GOAMD64 metadata mismatch for $Relative."
    }
    if (
        $ExpectedGOARCH -ceq "arm64" -and
        $Metadata -cnotmatch [regex]::Escape("GOARM64=v8.0")
    ) {
        throw "GOARM64 metadata mismatch for $Relative."
    }
    # Go 1.24 intentionally omits -ldflags/-X from `go version -m` when
    # -trimpath is enabled. Verify the two linker-injected values directly in
    # every target; the runnable host binary is checked below as well.
    $BinaryText = [System.Text.Encoding]::ASCII.GetString(
        [System.IO.File]::ReadAllBytes($Source)
    )
    if (
        $BinaryText.IndexOf($Version, [System.StringComparison]::Ordinal) -lt 0 -or
        $BinaryText.IndexOf($SourceDigest, [System.StringComparison]::Ordinal) -lt 0
    ) {
        throw "Embedded release metadata mismatch for $Relative."
    }
}

$HostOS = if ($IsWindows -or $env:OS -eq "Windows_NT") {
    "windows"
}
elseif ($PSVersionTable.OS -cmatch "Darwin") {
    "macos"
}
else {
    "linux"
}
$HostArch = if (
    $env:PROCESSOR_ARCHITECTURE -ceq "ARM64" -or
    $env:PROCESSOR_ARCHITEW6432 -ceq "ARM64" -or
    [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ceq "Arm64"
) {
    "arm64"
}
else {
    "amd64"
}
$HostExtension = if ($HostOS -ceq "windows") { ".exe" } else { "" }
$HostBinary = Join-Path $StagingRoot "$HostOS/$HostArch/setup$HostExtension"
$VersionOutput = (& $HostBinary version).Trim()
if ($LASTEXITCODE -ne 0 -or $VersionOutput -cne "$Version source=$SourceDigest") {
    throw "Runnable staging binary reported unexpected version or source metadata."
}

foreach ($Relative in $BinaryPaths) {
    $RelativePlatform = $Relative.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $Source = Join-Path $StagingRoot $RelativePlatform
    $Destination = Join-Path $ActiveRoot $RelativePlatform
    $DestinationDirectory = Split-Path -Parent $Destination
    Assert-RegularDirectoryTree -Path $DestinationDirectory
    if (-not (Test-Path -LiteralPath $DestinationDirectory)) {
        New-Item -ItemType Directory -Path $DestinationDirectory | Out-Null
        Assert-RegularDirectoryTree -Path $DestinationDirectory
    }
    $PromotionID = [Guid]::NewGuid().ToString("N")
    $Temporary = Join-Path $DestinationDirectory (".promote-" + $PromotionID + ".tmp")
    $Backup = Join-Path $DestinationDirectory (".promote-" + $PromotionID + ".backup.tmp")
    try {
        [System.IO.File]::Copy($Source, $Temporary, $false)
        $TemporaryHash = (Get-FileHash -LiteralPath $Temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($TemporaryHash -cne $ManifestHashes[$Relative]) {
            throw "Temporary promotion hash mismatch for $Relative."
        }
        if ([System.IO.File]::Exists($Destination)) {
            [System.IO.File]::Replace($Temporary, $Destination, $Backup, $true)
        }
        else {
            [System.IO.File]::Move($Temporary, $Destination)
        }
        if (-not ($IsWindows -or $env:OS -ceq "Windows_NT") -and $Relative -cnotlike "windows/*") {
            & chmod 755 -- $Destination
            if ($LASTEXITCODE -ne 0) {
                throw "Could not restore executable mode for $Relative."
            }
        }
        $DestinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($DestinationHash -cne $ManifestHashes[$Relative]) {
            throw "Destination verification failed for $Relative."
        }
    }
    finally {
        if ([System.IO.File]::Exists($Temporary)) {
            [System.IO.File]::Delete($Temporary)
        }
        if ([System.IO.File]::Exists($Backup)) {
            [System.IO.File]::Delete($Backup)
        }
    }
}

# Publish the manifest last. Until this atomic replacement succeeds, any
# platform whose binary changed is fail-closed against the old manifest.
if ((Get-CurrentSourceDigest) -cne $SourceDigest) {
    throw "Source changed before manifest publication; active wrappers remain fail-closed."
}
foreach ($Relative in $BinaryPaths) {
    $Destination = Join-Path $ActiveRoot $Relative.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $DestinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($DestinationHash -cne $ManifestHashes[$Relative]) {
        throw "Refusing manifest publication after destination drift: $Relative."
    }
}
$ActiveManifest = Join-Path $ActiveRoot "SHA256SUMS"
$ManifestPromotionID = [Guid]::NewGuid().ToString("N")
$ManifestTemporary = Join-Path $ActiveRoot (".promote-manifest-" + $ManifestPromotionID + ".tmp")
$ManifestBackup = Join-Path $ActiveRoot (".promote-manifest-" + $ManifestPromotionID + ".backup.tmp")
try {
    [System.IO.File]::WriteAllBytes($ManifestTemporary, $ManifestBytes)
    if ([System.IO.File]::Exists($ActiveManifest)) {
        [System.IO.File]::Replace($ManifestTemporary, $ActiveManifest, $ManifestBackup, $true)
    }
    else {
        [System.IO.File]::Move($ManifestTemporary, $ActiveManifest)
    }
}
finally {
    if ([System.IO.File]::Exists($ManifestTemporary)) {
        [System.IO.File]::Delete($ManifestTemporary)
    }
    if ([System.IO.File]::Exists($ManifestBackup)) {
        [System.IO.File]::Delete($ManifestBackup)
    }
}

Assert-ExactReleaseFileSet -Root $ActiveRoot -NormalizedRoot $NormalizedActive
if (
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($ManifestPath)) -cne
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($ActiveManifest))
) {
    throw "Active manifest bytes differ from the validated staging manifest."
}
foreach ($Relative in $BinaryPaths) {
    $Destination = Join-Path $ActiveRoot $Relative.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $DestinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($DestinationHash -cne $ManifestHashes[$Relative]) {
        throw "Active release verification failed for $Relative."
    }
}
if ((Get-CurrentSourceDigest) -cne $SourceDigest) {
    throw "Source changed during final promotion verification."
}

Write-Output "Promoted six verified binaries; SHA256SUMS published last."
}
finally {
    foreach ($Name in $PromotionEnvironmentNames) {
        [System.Environment]::SetEnvironmentVariable(
            $Name,
            $SavedPromotionEnvironment[$Name],
            "Process"
        )
    }
}
