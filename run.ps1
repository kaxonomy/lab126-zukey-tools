param([switch]$Elevated)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path '.venv\Scripts\python.exe')) {
    python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdmin -and -not $Elevated) {
    Start-Process powershell -Verb RunAs -WorkingDirectory $Root -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated'
    )
    exit
}

& .\.venv\Scripts\python.exe .\main.py

