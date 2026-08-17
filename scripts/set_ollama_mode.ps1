param(
    [ValidateSet("local","api")][string]$Mode,
    [string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference="Stop"
$envPath=Join-Path $ProjectRoot ".env"
if(-not (Test-Path -LiteralPath $envPath)){throw "Run START_MY_THREATLENS.bat once before changing Ollama mode."}

function Set-EnvValue([string]$Text,[string]$Name,[string]$Value){
    $safe=$Value.Replace("\","\\").Replace('"','\"').Replace("`r","").Replace("`n","")
    $line="$Name=`"$safe`""
    if($Text -match "(?m)^$([regex]::Escape($Name))="){
        return [regex]::Replace($Text,"(?m)^$([regex]::Escape($Name))=.*$",[System.Text.RegularExpressions.MatchEvaluator]{param($match) $line})
    }
    return $Text.TrimEnd()+"`r`n"+$line+"`r`n"
}

$configuration=Get-Content -Raw -LiteralPath $envPath
if($Mode -eq "api"){
    $secureKey=Read-Host "Ollama API key" -AsSecureString
    $keyPointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    try{$apiKey=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)}
    if([string]::IsNullOrWhiteSpace($apiKey)){throw "The API key cannot be empty."}
    $requestedModel=(Read-Host "Ollama API model [gpt-oss:20b]").Trim()
    if(-not $requestedModel){$requestedModel="gpt-oss:20b"}
    $values=[ordered]@{"OLLAMA_URL"="https://ollama.com";"OLLAMA_MODEL"=$requestedModel;"OLLAMA_API_KEY"=$apiKey}
}else{
    $ramBytes=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $localModel=if($ramBytes -ge 16GB){"deepseek-r1:7b"}else{"deepseek-r1:1.5b"}
    $ollama=(Get-Command ollama -ErrorAction SilentlyContinue).Source
    if(-not $ollama){$ollama="$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"}
    if(-not (Test-Path -LiteralPath $ollama)){throw "Local Ollama is not installed. Run START_MY_THREATLENS.bat again to install it."}
    & $ollama pull $localModel
    if($LASTEXITCODE -ne 0){throw "The local DeepSeek model download did not complete."}
    $values=[ordered]@{"OLLAMA_URL"="http://127.0.0.1:11434";"OLLAMA_MODEL"=$localModel;"OLLAMA_API_KEY"=""}
}

foreach($item in $values.GetEnumerator()){$configuration=Set-EnvValue $configuration $item.Key $item.Value}
[IO.File]::WriteAllText($envPath,$configuration,(New-Object Text.UTF8Encoding($false)))
Write-Host "Ollama $Mode mode saved. Restart My ThreatLens to apply it." -ForegroundColor Green
