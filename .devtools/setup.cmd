@echo off
setlocal
for /f "delims=" %%R in ('git rev-parse --show-toplevel 2^>nul') do set "ENV_ROOT=%%R"
if not defined ENV_ROOT (
  if /I "%~1"=="capture" (
    >&2 echo devtools: repository root could not be resolved
    exit /b 2
  )
  exit /b 1
)
set "ENV_MARKER=%ENV_ROOT%\.devtools\local-store\.initialized"
set "ENV_ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ENV_ARCH=arm64"
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "ENV_ARCH=arm64"
set "ENV_BINARY=%ENV_ROOT%\.devtools\bin\windows\%ENV_ARCH%\setup.exe"
set "ENV_CHECKSUMS=%ENV_ROOT%\.devtools\bin\SHA256SUMS"
call :verify_local_paths
set "ENV_STATUS=%ERRORLEVEL%"
if not "%ENV_STATUS%"=="0" (
  if /I "%~1"=="capture" exit /b 2
  exit /b %ENV_STATUS%
)
call :verify_binary
set "ENV_STATUS=%ERRORLEVEL%"
if not "%ENV_STATUS%"=="0" goto verify_failed
if /I "%~1"=="bootstrap" goto command_bootstrap
if /I "%~1"=="capture" goto command_capture
if /I "%~1"=="recover" goto command_recover
if /I "%~1"=="init" goto command_init
goto command_default

:verify_failed
if /I not "%~1"=="capture" exit /b %ENV_STATUS%
call :record_health "capture refused: binary integrity verification failed"
exit /b 2

:command_bootstrap
call :run_bootstrap
set "ENV_STATUS=%ERRORLEVEL%"
exit /b %ENV_STATUS%

:command_capture
call :run_capture %*
set "ENV_STATUS=%ERRORLEVEL%"
if not "%ENV_STATUS%"=="0" exit /b 2
exit /b 0

:command_recover
"%ENV_BINARY%" recover >nul 2>&1
set "ENV_STATUS=%ERRORLEVEL%"
if "%ENV_STATUS%"=="0" exit /b 0
call :record_health "history recovery failed; run recover again to retry"
exit /b 1

:command_init
"%ENV_BINARY%" %* >nul
set "ENV_STATUS=%ERRORLEVEL%"
if not "%ENV_STATUS%"=="0" exit /b %ENV_STATUS%
call :write_marker
exit /b %ERRORLEVEL%

:command_default
"%ENV_BINARY%" %*
exit /b %ERRORLEVEL%

:verify_binary
set "ENV_EXPECTED_HASH="
set "ENV_ACTUAL_HASH="
if not exist "%ENV_CHECKSUMS%" (
  >&2 echo devtools: checksum manifest is missing
  exit /b 20
)
for /f "usebackq delims=" %%H in (`powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; $manifest = Get-Item -LiteralPath $env:ENV_CHECKSUMS -Force; if ($manifest.Length -le 0 -or $manifest.Length -gt 4096) { exit 20 }; $bytes = [IO.File]::ReadAllBytes($env:ENV_CHECKSUMS); if ($bytes[$bytes.Length - 1] -ne 10 -or ($bytes -contains 13) -or ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) { exit 20 }; $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes); $lines = @($text.Substring(0, $text.Length - 1).Split([char]10)); $allowed = @('windows/amd64/setup.exe','windows/arm64/setup.exe','linux/amd64/setup','linux/arm64/setup','macos/amd64/setup','macos/arm64/setup'); if ($lines.Count -ne 6) { exit 20 }; $hashes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal); foreach ($line in $lines) { if ($line -cnotmatch '^([0-9a-f]{64})  ((?:windows|linux|macos)/(?:amd64|arm64)/setup(?:\.exe)?)$') { exit 20 }; $relative = $Matches[2]; if ($allowed -cnotcontains $relative -or $hashes.ContainsKey($relative)) { exit 20 }; $hashes.Add($relative, $Matches[1]) }; if ($hashes.Count -ne 6) { exit 20 }; $wanted = 'windows/' + $env:ENV_ARCH + '/setup.exe'; if (-not $hashes.ContainsKey($wanted)) { exit 20 }; $hashes[$wanted]"`) do set "ENV_EXPECTED_HASH=%%H"
if not defined ENV_EXPECTED_HASH (
  >&2 echo devtools: checksum manifest is malformed or incomplete
  exit /b 20
)
for /f "usebackq delims=" %%H in (`powershell.exe -NoLogo -NoProfile -NonInteractive -Command "(Get-FileHash -LiteralPath $env:ENV_BINARY -Algorithm SHA256).Hash.ToLowerInvariant()"`) do set "ENV_ACTUAL_HASH=%%H"
if not defined ENV_ACTUAL_HASH (
  >&2 echo devtools: unable to calculate the agent checksum
  exit /b 20
)
if not "%ENV_ACTUAL_HASH%"=="%ENV_EXPECTED_HASH%" (
  >&2 echo devtools: agent checksum mismatch; execution refused
  exit /b 20
)
exit /b 0

:run_capture
set "PROMPT_AUDIT_REPOSITORY_ROOT=%ENV_ROOT%"
if defined TEMP (
  set "ENV_CAPTURE_ERROR=%TEMP%\prompt-audit-capture-%RANDOM%-%RANDOM%.tmp"
) else (
  set "ENV_CAPTURE_ERROR=%ENV_ROOT%\.devtools\.capture-error-%RANDOM%-%RANDOM%.tmp"
)
"%ENV_BINARY%" %* 2>"%ENV_CAPTURE_ERROR%"
set "ENV_CAPTURE_STATUS=%ERRORLEVEL%"
if exist "%ENV_CAPTURE_ERROR%" for %%F in ("%ENV_CAPTURE_ERROR%") do if %%~zF GTR 0 (
  call :record_health "capture reported an error; prompt text was not copied to this log"
  >&2 type "%ENV_CAPTURE_ERROR%"
)
if exist "%ENV_CAPTURE_ERROR%" del /q "%ENV_CAPTURE_ERROR%" >nul 2>&1
if not "%ENV_CAPTURE_STATUS%"=="0" exit /b 2
exit /b 0

:record_health
call :verify_local_paths >nul 2>&1
if errorlevel 1 exit /b 0
if not exist "%ENV_ROOT%\.devtools\local-store" mkdir "%ENV_ROOT%\.devtools\local-store"
>>"%ENV_ROOT%\.devtools\local-store\health.log" echo [%DATE% %TIME%] %~1
exit /b 0

:run_bootstrap
set "ENV_CURRENT_MARKER="
if exist "%ENV_MARKER%" set /p ENV_CURRENT_MARKER=<"%ENV_MARKER%"
if "%ENV_CURRENT_MARKER%"=="v2:%ENV_EXPECTED_HASH%" goto bootstrap_activate
"%ENV_BINARY%" init >nul
set "ENV_STATUS=%ERRORLEVEL%"
if not "%ENV_STATUS%"=="0" exit /b %ENV_STATUS%
call :write_marker
exit /b %ERRORLEVEL%

:bootstrap_activate
"%ENV_BINARY%" activate >nul
exit /b %ERRORLEVEL%

:verify_local_paths
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$binaryDirectory = Split-Path -Parent $env:ENV_BINARY; $directories = @((Join-Path $env:ENV_ROOT '.devtools'), (Join-Path $env:ENV_ROOT '.devtools\bin'), (Split-Path -Parent $binaryDirectory), $binaryDirectory, (Join-Path $env:ENV_ROOT '.devtools\local-store')); $files = @($env:ENV_CHECKSUMS, $env:ENV_BINARY, $env:ENV_MARKER, (Join-Path $env:ENV_ROOT '.devtools\local-store\health.log')); foreach ($path in @($directories + $files)) { $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; if ($null -ne $item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { [Console]::Error.WriteLine('devtools: linked or redirected project path refused: ' + $path); exit 21 } }; foreach ($path in $directories) { $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; if ($null -ne $item -and -not $item.PSIsContainer) { exit 21 } }; foreach ($path in $files) { $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; if ($null -ne $item -and $item.PSIsContainer) { exit 21 } }; exit 0"
exit /b %ERRORLEVEL%

:write_marker
call :verify_local_paths
if errorlevel 1 exit /b %ERRORLEVEL%
if not exist "%ENV_ROOT%\.devtools\local-store" mkdir "%ENV_ROOT%\.devtools\local-store"
if errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; $directory = Split-Path -Parent $env:ENV_MARKER; $id = [Guid]::NewGuid().ToString('N'); $temporary = Join-Path $directory ('.initialized-' + $id + '.tmp'); $backup = Join-Path $directory ('.initialized-' + $id + '.backup.tmp'); try { [IO.File]::WriteAllText($temporary, ('v2:' + $env:ENV_EXPECTED_HASH + [char]10), (New-Object Text.UTF8Encoding($false))); if ([IO.File]::Exists($env:ENV_MARKER)) { [IO.File]::Replace($temporary, $env:ENV_MARKER, $backup, $true) } else { [IO.File]::Move($temporary, $env:ENV_MARKER) } } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }; if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) } }"
exit /b %ERRORLEVEL%
