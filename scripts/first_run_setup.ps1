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
$compatible=$false
if($python){
    try{
        & $python -3 -c "import sys; raise SystemExit(0 if (3,11) <= sys.version_info[:2] < (3,15) else 1)" 2>$null
        $compatible=$LASTEXITCODE -eq 0
    }catch{$compatible=$false}
}
if(-not $compatible){
    $python=Find-CommandPath "python" @("%LOCALAPPDATA%\Programs\Python\Python312\python.exe")
    if($python){
        try{
            & $python -c "import sys; raise SystemExit(0 if (3,11) <= sys.version_info[:2] < (3,15) else 1)" 2>$null
            $compatible=$LASTEXITCODE -eq 0
        }catch{$compatible=$false}
    }
}
if(-not $compatible){
    $winget=Find-CommandPath "winget" @()
    if(-not $winget){throw "A compatible Python version (3.11 through 3.14) was not found and Windows Package Manager is unavailable. Install Python 3.12, then run this file again."}
    Write-Host "No compatible Python was found. Installing the tested Python 3.12 runtime..." -ForegroundColor Yellow
    & $winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements
    if($LASTEXITCODE -ne 0){throw "Python installation did not complete."}
}else{
    $version=& $python $(if((Split-Path -Leaf $python) -like 'py*'){'-3'}) -c "import platform; print(platform.python_version())"
    Write-Host "Compatible Python $version detected." -ForegroundColor Green
}

if(-not (Test-Path -LiteralPath $envPath)){
    if(-not (Test-Path -LiteralPath $examplePath)){throw ".env.example is missing."}
    Copy-Item -LiteralPath $examplePath -Destination $envPath
    Write-Host "Blank local configuration created. Email and AI are optional and can be configured later." -ForegroundColor Green
}else{
    Write-Host "Existing .env kept unchanged." -ForegroundColor DarkGray
}
Write-Host "Startup prerequisites are ready." -ForegroundColor Green
