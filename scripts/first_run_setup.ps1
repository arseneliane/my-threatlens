param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference="Stop"
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot.Trim().Trim('"'))
$envPath=Join-Path $ProjectRoot ".env"
$examplePath=Join-Path $ProjectRoot ".env.example"

function Find-CommandPath([string]$Name,[string[]]$Candidates){
    $command=Get-Command $Name -ErrorAction SilentlyContinue
    if($command){return $command.Source}
    foreach($candidate in $Candidates){
        $expanded=[Environment]::ExpandEnvironmentVariables($candidate)
        if(Test-Path -LiteralPath $expanded){return $expanded}
    }
    return $null
}

Write-Host ""
Write-Host "My ThreatLens first-run setup" -ForegroundColor Cyan
Write-Host "This prepares Python and a blank local configuration." -ForegroundColor DarkGray

$python=Find-CommandPath "py" @()
if(-not $python){$python=Find-CommandPath "python" @("%LOCALAPPDATA%\Programs\Python\Python312\python.exe")}
if(-not $python){
    $winget=Find-CommandPath "winget" @()
    if(-not $winget){throw "Python is missing and Windows Package Manager is unavailable. Install Python 3.11 or newer, then run this file again."}
    Write-Host "Installing Python 3.12..." -ForegroundColor Yellow
    & $winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements
    if($LASTEXITCODE -ne 0){throw "Python installation did not complete."}
}

if(-not (Test-Path -LiteralPath $envPath)){
    if(-not (Test-Path -LiteralPath $examplePath)){throw ".env.example is missing."}
    Copy-Item -LiteralPath $examplePath -Destination $envPath
    Write-Host "Blank local configuration created. Email and AI are optional and can be configured later." -ForegroundColor Green
}else{
    Write-Host "Existing .env kept unchanged." -ForegroundColor DarkGray
}
Write-Host "Startup prerequisites are ready." -ForegroundColor Green
