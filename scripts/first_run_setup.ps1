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

function Set-EnvValue([string]$Text,[string]$Name,[string]$Value){
    $safe=$Value.Replace("\","\\").Replace('"','\"').Replace("`r","").Replace("`n","")
    $line="$Name=`"$safe`""
    if($Text -match "(?m)^$([regex]::Escape($Name))="){
        return [regex]::Replace($Text,"(?m)^$([regex]::Escape($Name))=.*$",[System.Text.RegularExpressions.MatchEvaluator]{param($match) $line})
    }
    return $Text.TrimEnd()+"`r`n"+$line+"`r`n"
}

Write-Host ""
Write-Host "My ThreatLens first-run setup" -ForegroundColor Cyan
Write-Host "This prepares Python, local DeepSeek through Ollama, and email delivery." -ForegroundColor DarkGray

$python=Find-CommandPath "py" @()
if(-not $python){$python=Find-CommandPath "python" @("%LOCALAPPDATA%\Programs\Python\Python312\python.exe")}
if(-not $python){
    $winget=Find-CommandPath "winget" @()
    if(-not $winget){throw "Python is missing and Windows Package Manager is unavailable. Install Python 3.11 or newer, then run this file again."}
    Write-Host "Installing Python 3.12..." -ForegroundColor Yellow
    & $winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements
    if($LASTEXITCODE -ne 0){throw "Python installation did not complete."}
}

$ollama=Find-CommandPath "ollama" @("%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
if(-not $ollama){
    $winget=Find-CommandPath "winget" @()
    if(-not $winget){throw "Ollama is missing and Windows Package Manager is unavailable. Install Ollama for Windows, then run this file again."}
    Write-Host "Installing Ollama from the official Windows package..." -ForegroundColor Yellow
    & $winget install --id Ollama.Ollama --exact --silent --accept-package-agreements --accept-source-agreements
    if($LASTEXITCODE -ne 0){throw "Ollama installation did not complete."}
    $ollama=Find-CommandPath "ollama" @("%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
    if(-not $ollama){throw "Ollama was installed but its executable could not be located. Restart Windows and run this file again."}
}

$ramBytes=0
try{$ramBytes=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory}catch{
    Write-Host "RAM size could not be read; selecting the lightweight DeepSeek model." -ForegroundColor DarkGray
}
$model=if($ramBytes -ge 16GB){"deepseek-r1:7b"}else{"deepseek-r1:1.5b"}
$apiReady=$false
try{$null=Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 2; $apiReady=$true}catch{}
if(-not $apiReady){
    Start-Process -FilePath $ollama -ArgumentList "serve" -WindowStyle Hidden
    for($attempt=0;$attempt -lt 20;$attempt++){
        Start-Sleep -Milliseconds 500
        try{$null=Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 2; $apiReady=$true; break}catch{}
    }
}
if(-not $apiReady){throw "Ollama installed but its local service did not start."}

$installed=& $ollama list
if($installed -notmatch [regex]::Escape($model)){
    Write-Host "Downloading $model. This is required only once and may take several minutes..." -ForegroundColor Yellow
    & $ollama pull $model
    if($LASTEXITCODE -ne 0){throw "The DeepSeek model download did not complete."}
}

if(-not (Test-Path -LiteralPath $envPath)){
    if(-not (Test-Path -LiteralPath $examplePath)){throw ".env.example is missing."}
    do{$mailAddress=(Read-Host "Email sender address").Trim()}until($mailAddress -match "^[^\s@]+@[^\s@]+\.[^\s@]+$")
    $securePassword=Read-Host "Email app password" -AsSecureString
    $passwordPointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try{$appPassword=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)}
    if([string]::IsNullOrWhiteSpace($appPassword)){throw "The email app password cannot be empty."}
    $domain=($mailAddress.Split('@')[-1]).ToLowerInvariant()
    $smtpHost=""; $smtpPort="465"; $smtpUseTls="false"; $smtpUseSsl="true"
    switch -Regex ($domain) {
        '^(zoho\.(com|eu|in|com\.au)|zohomail\.com)$' {$smtpHost="smtp.zoho.com"; break}
        '^(gmail\.com|googlemail\.com)$' {$smtpHost="smtp.gmail.com"; break}
        '^(outlook\.com|hotmail\.com|live\.com|office365\.com)$' {$smtpHost="smtp.office365.com"; $smtpPort="587"; $smtpUseTls="true"; $smtpUseSsl="false"; break}
        '^(yahoo\.|ymail\.com)' {$smtpHost="smtp.mail.yahoo.com"; break}
        '^(icloud\.com|me\.com|mac\.com)$' {$smtpHost="smtp.mail.me.com"; $smtpPort="587"; $smtpUseTls="true"; $smtpUseSsl="false"; break}
        default {
            Write-Host "This email provider is not recognized automatically." -ForegroundColor Yellow
            do{$smtpHost=(Read-Host "SMTP server (example: smtp.example.com)").Trim()}until(-not [string]::IsNullOrWhiteSpace($smtpHost))
            $enteredPort=(Read-Host "SMTP port [465]").Trim(); if($enteredPort){$smtpPort=$enteredPort}
            $security=(Read-Host "Security: SSL or TLS [SSL]").Trim().ToUpperInvariant()
            if($security -eq "TLS"){$smtpUseTls="true"; $smtpUseSsl="false"}
        }
    }
    $configuration=Get-Content -Raw -LiteralPath $examplePath
    $values=[ordered]@{
        "SMTP_HOST"=$smtpHost; "SMTP_PORT"=$smtpPort; "SMTP_USERNAME"=$mailAddress;
        "SMTP_PASSWORD"=$appPassword; "SMTP_FROM_EMAIL"=$mailAddress;
        "SMTP_USE_TLS"=$smtpUseTls; "SMTP_USE_SSL"=$smtpUseSsl;
        "OLLAMA_URL"="http://127.0.0.1:11434"; "OLLAMA_MODEL"=$model; "OLLAMA_API_KEY"=""
    }
    foreach($item in $values.GetEnumerator()){$configuration=Set-EnvValue $configuration $item.Key $item.Value}
    [IO.File]::WriteAllText($envPath,$configuration,(New-Object Text.UTF8Encoding($false)))
    Write-Host "Local configuration created." -ForegroundColor Green
}else{
    Write-Host "Existing .env kept unchanged." -ForegroundColor DarkGray
}

Write-Host "DeepSeek is ready through local Ollama ($model)." -ForegroundColor Green
