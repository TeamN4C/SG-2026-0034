param(
    [string]$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    [string]$Serial,
    [ValidateSet("vulnerable", "patched")]
    [string]$Expected = "vulnerable",
    [string]$ResultsDirectory = "results",
    [ValidateRange(1, 300)]
    [int]$PostSuspendDelaySeconds = 5,
    [switch]$ProbeInput,
    [int]$TapX = 700,
    [int]$TapY = 950,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$androidRoot = Join-Path $root "android"
$apk = Join-Path $androidRoot "app\build\outputs\apk\debug\app-debug.apk"
$results = if ([System.IO.Path]::IsPathRooted($ResultsDirectory)) {
    $ResultsDirectory
} else {
    Join-Path $root $ResultsDirectory
}
$package = "lab.cve28650"
$script:adbPrefix = if ($Serial) { @("-s", $Serial) } else { @() }

function Invoke-Adb {
    $commandArgs = @($script:adbPrefix) + @($args)
    & $Adb @commandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: $($commandArgs -join ' ')"
    }
}

function Invoke-AdbOutput {
    $commandArgs = @($script:adbPrefix) + @($args)
    $output = @(& $Adb @commandArgs)
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: $($commandArgs -join ' ')"
    }
    return $output
}

function Get-DeviceProperty {
    param([string]$Name)
    return ((Invoke-AdbOutput shell getprop $Name) -join "").Trim()
}

function Get-WindowState {
    param(
        [string]$Dump,
        [string]$Title
    )

    $escaped = [regex]::Escape($Title)
    $pattern = "(?ms)^\s*Window #\d+ Window\{[^\r\n]*$escaped\}:.*?(?=^\s*Window #\d+ Window\{|\z)"
    $match = [regex]::Match($Dump, $pattern)

    if (-not $match.Success) {
        return [pscustomobject]@{
            found = $false
            type = $null
            shown = $null
            visible = $null
            hiddenWhileSuspended = $null
        }
    }

    $block = $match.Value
    $typeMatch = [regex]::Match($block, "\bty=([A-Z_]+)")
    $shownMatch = [regex]::Match($block, "Surface: shown=(true|false)")
    $visibleMatch = [regex]::Match($block, "(?m)^\s*isVisible=(true|false)")
    $suspendedMatch = [regex]::Match($block, "mHiddenWhileSuspended=(true|false)")

    return [pscustomobject]@{
        found = $true
        type = if ($typeMatch.Success) { $typeMatch.Groups[1].Value } else { $null }
        shown = if ($shownMatch.Success) { $shownMatch.Groups[1].Value -eq "true" } else { $null }
        visible = if ($visibleMatch.Success) { $visibleMatch.Groups[1].Value -eq "true" } else { $null }
        hiddenWhileSuspended = if ($suspendedMatch.Success) {
            $suspendedMatch.Groups[1].Value -eq "true"
        } else {
            $false
        }
    }
}

function Capture-State {
    param([string]$Name)

    $dump = (Invoke-AdbOutput shell dumpsys window windows) -join "`n"
    $dump | Set-Content -Encoding utf8 (Join-Path $results "window-$Name.txt")

    $deviceImage = "/sdcard/cve28650-$Name.png"
    Invoke-Adb shell screencap -p $deviceImage
    Invoke-Adb pull $deviceImage (Join-Path $results "$Name.png")

    return [pscustomobject]@{
        parent = Get-WindowState -Dump $dump -Title "CVE-28650-parent-overlay"
        child = Get-WindowState -Dump $dump -Title "CVE-28650-child-panel"
    }
}

if (-not (Test-Path -LiteralPath $Adb)) {
    throw "adb was not found: $Adb"
}

New-Item -ItemType Directory -Force -Path $results | Out-Null

if (-not $SkipBuild) {
    Push-Location $androidRoot
    try {
        & .\gradlew.bat --offline --no-daemon --console=plain :app:assembleDebug
        if ($LASTEXITCODE -ne 0) {
            throw "Gradle build failed"
        }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $apk)) {
    throw "APK was not found: $apk"
}

Invoke-Adb wait-for-device
Invoke-Adb shell input keyevent KEYCODE_WAKEUP
Invoke-Adb shell wm dismiss-keyguard
Invoke-Adb shell settings put system screen_off_timeout 2147483647
Invoke-Adb install -r $apk
try {
    Invoke-Adb shell pm unsuspend --user 0 $package
    Invoke-Adb shell appops set $package SYSTEM_ALERT_WINDOW allow
    Invoke-Adb shell am force-stop $package
    Invoke-Adb logcat -c
    Invoke-Adb shell am start -W -n "$package/.MainActivity"
    Start-Sleep -Seconds 4

    $pidBefore = ((Invoke-AdbOutput shell pidof $package) -join "").Trim()
    $before = Capture-State -Name "before"

    $baselineClickReceived = $null
    $suspendedClickReceived = $null
    if ($ProbeInput) {
        Invoke-Adb logcat -c
        Invoke-Adb shell input tap $TapX $TapY
        Start-Sleep -Seconds 2
        $baselineInputLog = (Invoke-AdbOutput logcat -d -s "CVE28650:I" "*:S") -join "`n"
        $baselineInputLog | Set-Content -Encoding utf8 (Join-Path $results "input-before-suspend.txt")
        $baselineClickReceived = $baselineInputLog -match "child click received"
        Invoke-Adb logcat -c
    }

    Invoke-Adb shell pm suspend --user 0 $package
    Start-Sleep -Seconds $PostSuspendDelaySeconds

    $pidAfter = ((Invoke-AdbOutput shell pidof $package) -join "").Trim()
    $suspended = Capture-State -Name "after-suspend"

    if ($ProbeInput) {
        Invoke-Adb shell input tap $TapX $TapY
        Start-Sleep -Seconds 2
        $suspendedInputLog = (Invoke-AdbOutput logcat -d -s "CVE28650:I" "*:S") -join "`n"
        $suspendedInputLog | Set-Content -Encoding utf8 (Join-Path $results "input-after-suspend.txt")
        $suspendedClickReceived = $suspendedInputLog -match "child click received"
    }

    $commonState =
        $before.parent.found -and
        $before.parent.shown -and
        $before.parent.visible -and
        $before.child.found -and
        $before.child.shown -and
        $before.child.visible -and
        $suspended.parent.found -and
        (-not $suspended.parent.shown) -and
        (-not $suspended.parent.visible) -and
        $suspended.parent.hiddenWhileSuspended -and
        $suspended.child.found -and
        $pidBefore -and
        ($pidBefore -eq $pidAfter)

    $vulnerableBehaviorObserved =
        $commonState -and
        $suspended.child.shown -and
        $suspended.child.visible -and
        (-not $suspended.child.hiddenWhileSuspended)

    $patchedBehaviorObserved =
        $commonState -and
        (-not $suspended.child.shown) -and
        (-not $suspended.child.visible) -and
        $suspended.child.hiddenWhileSuspended

    $statePassed = if ($Expected -eq "vulnerable") {
        $vulnerableBehaviorObserved
    } else {
        $patchedBehaviorObserved
    }

    $inputPassed = if (-not $ProbeInput) {
        $true
    } elseif ($Expected -eq "vulnerable") {
        $baselineClickReceived -and $suspendedClickReceived
    } else {
        $baselineClickReceived -and (-not $suspendedClickReceived)
    }

    $passed = $statePassed -and $inputPassed

    $summary = [ordered]@{
        cve = "CVE-2026-28650"
        timestamp = (Get-Date).ToString("o")
        serial = $Serial
        expected = $Expected
        postSuspendDelaySeconds = $PostSuspendDelaySeconds
        device = [ordered]@{
            release = Get-DeviceProperty "ro.build.version.release"
            securityPatch = Get-DeviceProperty "ro.build.version.security_patch"
            fingerprint = Get-DeviceProperty "ro.build.fingerprint"
        }
        process = [ordered]@{
            pidBefore = $pidBefore
            pidAfter = $pidAfter
            remainedAlive = [bool]($pidBefore -and ($pidBefore -eq $pidAfter))
        }
        before = $before
        afterSuspend = $suspended
        inputProbe = if ($ProbeInput) {
            [ordered]@{
                tapX = $TapX
                tapY = $TapY
                baselineClickReceived = [bool]$baselineClickReceived
                suspendedClickReceived = [bool]$suspendedClickReceived
                passed = [bool]$inputPassed
            }
        } else {
            $null
        }
        vulnerableBehaviorObserved = [bool]$vulnerableBehaviorObserved
        patchedBehaviorObserved = [bool]$patchedBehaviorObserved
        passed = [bool]$passed
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $results "summary.json")
    $summary | ConvertTo-Json -Depth 8
} finally {
    try {
        Invoke-Adb shell pm unsuspend --user 0 $package
    } catch {
        Write-Warning "Failed to restore package suspension state: $_"
    }
}

if (-not $passed) {
    exit 2
}

exit 0
