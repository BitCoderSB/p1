param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -cnotmatch "^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$") {
            throw "Version must use canonical lowercase semantic-version syntax."
        }
        $true
    })]
    [string]$Version
)

$ErrorActionPreference = "Stop"
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$ActiveBin = [System.IO.Path]::GetFullPath((Join-Path $SourceRoot "..\bin"))
$PathComparison = if ($IsWindows -or $env:OS -eq "Windows_NT") {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}
$NormalizedOutput = $OutputRoot.TrimEnd("\", "/")
$NormalizedActive = $ActiveBin.TrimEnd("\", "/")
$NormalizedSource = $SourceRoot.TrimEnd("\", "/")
$ActivePrefix = $NormalizedActive + [System.IO.Path]::DirectorySeparatorChar
$SourcePrefix = $NormalizedSource + [System.IO.Path]::DirectorySeparatorChar
if (
    $NormalizedOutput.Equals($NormalizedActive, $PathComparison) -or
    $NormalizedOutput.StartsWith($ActivePrefix, $PathComparison) -or
    $NormalizedOutput.Equals($NormalizedSource, $PathComparison) -or
    $NormalizedOutput.StartsWith($SourcePrefix, $PathComparison)
) {
    throw "Refusing staging inside the source or active bin directory."
}
if (Test-Path -LiteralPath $OutputRoot) {
    throw "OutputRoot must be a new, nonexistent staging directory."
}

function Assert-NoReparsePointInExistingPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse-point staging path refused: $Current"
            }
        }
        $Parent = Split-Path -Parent $Current
        if ([string]::IsNullOrEmpty($Parent) -or $Parent -eq $Current) {
            break
        }
        $Current = $Parent
    }
}

Assert-NoReparsePointInExistingPath -Path $OutputRoot
Assert-NoReparsePointInExistingPath -Path $ActiveBin

$Targets = @(
    @{ GOOS = "windows"; DirectoryOS = "windows"; Arch = "amd64"; Extension = ".exe" },
    @{ GOOS = "windows"; DirectoryOS = "windows"; Arch = "arm64"; Extension = ".exe" },
    @{ GOOS = "linux"; DirectoryOS = "linux"; Arch = "amd64"; Extension = "" },
    @{ GOOS = "linux"; DirectoryOS = "linux"; Arch = "arm64"; Extension = "" },
    @{ GOOS = "darwin"; DirectoryOS = "macos"; Arch = "amd64"; Extension = "" },
    @{ GOOS = "darwin"; DirectoryOS = "macos"; Arch = "arm64"; Extension = "" }
)

$BuildEnvironmentNames = @(
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
$SavedBuildEnvironment = @{}
$LocationPushed = $false
foreach ($Name in $BuildEnvironmentNames) {
    $SavedBuildEnvironment[$Name] = [System.Environment]::GetEnvironmentVariable($Name, "Process")
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
        throw "This release must be built with the pinned Go 1.24.13 toolchain."
    }

    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
    Push-Location $SourceRoot
    $LocationPushed = $true
    $SourceDigest = (& go run ./scripts/sourcehash).Trim()
    if ($LASTEXITCODE -ne 0 -or $SourceDigest -cnotmatch "^[0-9a-f]{64}$") {
        throw "Source digest calculation failed."
    }
    foreach ($Target in $Targets) {
        $Directory = Join-Path $OutputRoot (Join-Path $Target.DirectoryOS $Target.Arch)
        New-Item -ItemType Directory -Force -Path $Directory | Out-Null
        $Output = Join-Path $Directory ("setup" + $Target.Extension)
        $env:GOOS = $Target.GOOS
        $env:GOARCH = $Target.Arch
        & go build -buildvcs=false -trimpath `
            -ldflags "-s -w -X main.version=$Version -X main.sourceDigest=$SourceDigest" `
            -o $Output ./agent/cmd/prompt-audit
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $($Target.GOOS)/$($Target.Arch)."
        }
    }
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    $SourceDigestAfter = (& go run ./scripts/sourcehash).Trim()
    if ($LASTEXITCODE -ne 0 -or $SourceDigestAfter -cne $SourceDigest) {
        throw "Source changed during the multi-target build; discard this staging directory."
    }
}
finally {
    if ($LocationPushed) {
        Pop-Location
    }
    foreach ($Name in $BuildEnvironmentNames) {
        [System.Environment]::SetEnvironmentVariable(
            $Name,
            $SavedBuildEnvironment[$Name],
            "Process"
        )
    }
}

$ExpectedBinaryPaths = @(
    $Targets | ForEach-Object {
        "$($_.DirectoryOS)/$($_.Arch)/setup$($_.Extension)"
    }
)
$ActualBinaryPaths = @(
    Get-ChildItem -LiteralPath $OutputRoot -Recurse -File -Force | ForEach-Object {
        $_.FullName.Substring($NormalizedOutput.Length).TrimStart("\", "/").Replace("\", "/")
    }
)
$SortedActualBinaries = @($ActualBinaryPaths | Sort-Object)
$SortedExpectedBinaries = @($ExpectedBinaryPaths | Sort-Object)
if (($SortedActualBinaries -join "`n") -cne ($SortedExpectedBinaries -join "`n")) {
    throw "Staging does not contain exactly the six expected binaries."
}

$ManifestLines = foreach ($Target in $Targets) {
    $Relative = "$($Target.DirectoryOS)/$($Target.Arch)/setup$($Target.Extension)"
    $BinaryPath = Join-Path $OutputRoot ($Relative.Replace("/", [System.IO.Path]::DirectorySeparatorChar))
    $Hash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $Relative"
}
$ManifestPath = Join-Path $OutputRoot "SHA256SUMS"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $ManifestPath,
    (($ManifestLines -join "`n") + "`n"),
    $Utf8NoBom
)

foreach ($Path in (Get-ChildItem -LiteralPath $OutputRoot -Recurse -Force)) {
    if (($Path.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Staging contains a reparse point: $($Path.FullName)"
    }
}
$ExpectedReleasePaths = @($ExpectedBinaryPaths + "SHA256SUMS" | Sort-Object)
$ActualReleasePaths = @(
    Get-ChildItem -LiteralPath $OutputRoot -Recurse -File -Force | ForEach-Object {
        $_.FullName.Substring($NormalizedOutput.Length).TrimStart("\", "/").Replace("\", "/")
    } | Sort-Object
)
if (($ActualReleasePaths -join "`n") -cne ($ExpectedReleasePaths -join "`n")) {
    throw "Staging does not contain exactly the six binaries and one manifest."
}

Write-Output $SourceDigest
