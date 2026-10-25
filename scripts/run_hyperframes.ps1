param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$env:DO_NOT_TRACK = "1"
$env:HYPERFRAMES_NO_TELEMETRY = "1"
$env:HYPERFRAMES_SKIP_SKILLS = "1"
if ($env:Path -notlike "*E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin*") {
    $env:Path = "E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin;$env:Path"
}

& npx --yes hyperframes @Arguments
