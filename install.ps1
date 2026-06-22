# VIGIL - Automated Setup Wizard (xcomrade.tech Edition) for Windows
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  VIGIL — Verified Intelligent Ground-station Infrastructure  ║" -ForegroundColor Cyan
Write-Host "║  Air-Gapped Predictive AI NOC Copilot • xcomrade.tech        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "STEP 1 / 4 - Scanning Environment" -ForegroundColor Yellow

$HasRust = $false
$HasOllama = $false
$FoundGguf = ""

# Rust check
try {
    $rustVer = (rustc --version)
    Write-Host "[+] Rust compiler found: $rustVer" -ForegroundColor Green
    $HasRust = $true
} catch {
    Write-Host "[-] Rust compiler not found. Please install from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Ollama check
try {
    $ollamaVer = (ollama --version)
    Write-Host "[+] Ollama detected: $ollamaVer" -ForegroundColor Green
    $HasOllama = $true
    
    $ollamaModels = (ollama list) | Select-Object -Skip 1 | ForEach-Object { ($_ -split '\s+')[0] }
    if ($ollamaModels) {
        Write-Host "    Models available:" -ForegroundColor Green
        foreach ($m in $ollamaModels) {
            Write-Host "    - $m" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[*] Ollama not installed. (optional)" -ForegroundColor Cyan
}

# GGUF check
$modelDir = ".\models"
if (!(Test-Path $modelDir)) {
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
}

$ggufFiles = Get-ChildItem -Path $modelDir -Filter "*.gguf"
if ($ggufFiles) {
    Write-Host "[+] GGUF model(s) already present:" -ForegroundColor Green
    foreach ($f in $ggufFiles) {
        Write-Host "    - $($f.Name)" -ForegroundColor Green
    }
    $FoundGguf = $ggufFiles[0].FullName
}

Write-Host "`nSTEP 2 / 4 - AI Backend Selection" -ForegroundColor Yellow

$DefaultChoice = 1
if ($FoundGguf) {
    Write-Host "  AUTO-DETECTED: GGUF model found at $($FoundGguf)" -ForegroundColor Green
    $DefaultChoice = 0
} elseif ($HasOllama -and $ollamaModels) {
    Write-Host "  AUTO-DETECTED: Ollama is running with local models." -ForegroundColor Green
    $DefaultChoice = 0
}

if ($DefaultChoice -eq 0) {
    Write-Host "  Press Enter to use detected AI backend, or choose manually:" -ForegroundColor Cyan
} else {
    Write-Host "  How should VIGIL generate root-cause diagnostics?" -ForegroundColor Cyan
}

Write-Host "  1) Expert System (instant, zero download, works offline)" -ForegroundColor Green
if ($HasOllama) {
    Write-Host "  2) Use Ollama (pull a small model if needed)" -ForegroundColor Cyan
} else {
    Write-Host "  2) Install Ollama + pull a model (ollama not detected - skipping)" -ForegroundColor Gray
}
Write-Host "  3) Download GGUF model from Hugging Face (~1-4 GB)" -ForegroundColor Blue

if ($DefaultChoice -eq 0) {
    $choice = Read-Host "  Enter choice [Enter = use auto-detected, 1-3]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "0" }
} else {
    $choice = Read-Host "  Enter choice [1-3, default: 1]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
}

$ChosenModelPath = "./models/expert-fallback-placeholder"
$UseOllama = $false

switch ($choice) {
    "0" {
        if ($FoundGguf) {
            $ChosenModelPath = $FoundGguf
            Write-Host "[+] Using detected GGUF model" -ForegroundColor Green
        } elseif ($HasOllama) {
            $UseOllama = $true
            $ChosenModelPath = "./models/ollama-routed"
            Write-Host "[+] Using Ollama for inference routing." -ForegroundColor Green
        }
    }
    "1" {
        Write-Host "[+] Expert System selected." -ForegroundColor Green
    }
    "2" {
        if ($HasOllama) {
            $UseOllama = $true
            $ChosenModelPath = "./models/ollama-routed"
            Write-Host "  Available models:"
            Write-Host "    a) qwen2.5:1.5b (fast, recommended)"
            Write-Host "    b) phi3:mini"
            $mChoice = Read-Host "  Pick model [a/b, default: a]"
            $model = if ($mChoice -eq "b") { "phi3:mini" } else { "qwen2.5:1.5b" }
            Write-Host "[*] Pulling $model via Ollama..." -ForegroundColor Cyan
            ollama pull $model
        } else {
            Write-Host "[-] Ollama not found. Falling back to Expert System." -ForegroundColor Red
        }
    }
    "3" {
        Write-Host "  Available GGUF models:"
        Write-Host "    a) Qwen2.5-1.5B-Q4_K_M (~1.1 GB, recommended)"
        Write-Host "    b) Phi-3.5-mini-Q4_K_M (~2.2 GB)"
        $mChoice = Read-Host "  Pick model [a/b, default: a]"
        if ($mChoice -eq "b") {
            $modelName = "Phi-3.5-mini-instruct-Q4_K_M.gguf"
            $url = "https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf"
        } else {
            $modelName = "Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
            $url = "https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
        }
        $ChosenModelPath = ".\models\$modelName"
        
        if (!(Test-Path $ChosenModelPath)) {
            Write-Host "[*] Downloading $modelName..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $url -OutFile $ChosenModelPath
            Write-Host "[+] Download complete." -ForegroundColor Green
        } else {
            Write-Host "[+] Model already exists at $ChosenModelPath" -ForegroundColor Green
        }
    }
}

# If the chosen model is a GGUF file, ensure we have the llama-cli runner.
$LLM_BIN_PATH_TOML = ""
if ($ChosenModelPath -like "*.gguf") {
    if ($env:VIGIL_LLM_BIN -and (Test-Path $env:VIGIL_LLM_BIN)) {
        $LLM_BIN_PATH_TOML = $env:VIGIL_LLM_BIN.Replace("\", "/")
        Write-Host "[+] Using custom llama-cli from env VIGIL_LLM_BIN: $LLM_BIN_PATH_TOML" -ForegroundColor Green
    } elseif (!(Get-Command llama-cli -ErrorAction SilentlyContinue) -and !(Test-Path ".\bin\llama-bin\llama-cli.exe")) {
        Write-Host "[*] llama-cli not found in PATH or bin folder. Downloading pre-compiled llama.cpp for Windows..." -ForegroundColor Cyan
        if (!(Test-Path ".\bin")) { New-Item -ItemType Directory -Force -Path ".\bin" | Out-Null }
        $llamaZip = ".\bin\llama-bin.zip"
        Invoke-WebRequest -Uri "https://github.com/ggerganov/llama.cpp/releases/download/b3130/llama-b3130-bin-win-avx2-x64.zip" -OutFile $llamaZip
        Expand-Archive -Path $llamaZip -DestinationPath ".\bin\llama-bin" -Force
        Remove-Item $llamaZip -Force
        $LLM_BIN_PATH_TOML = "./bin/llama-bin/llama-cli.exe"
        Write-Host "[+] Extracted llama-cli to $LLM_BIN_PATH_TOML" -ForegroundColor Green
    } elseif (Test-Path ".\bin\llama-bin\llama-cli.exe") {
        $LLM_BIN_PATH_TOML = "./bin/llama-bin/llama-cli.exe"
    }
}

Write-Host "`nSTEP 3 / 4 - Generating Configuration" -ForegroundColor Yellow
$ConfigPath = ".\vigil.toml"
$ShouldWrite = $true

if (Test-Path $ConfigPath) {
    $ow = Read-Host "  vigil.toml already exists. Overwrite? [y/N]"
    if ($ow -notmatch "^y") {
        $ShouldWrite = $false
        Write-Host "[*] Keeping existing vigil.toml" -ForegroundColor Cyan
    }
}

# Fix backslashes to forward slashes for TOML
$ChosenModelPathToml = $ChosenModelPath.Replace("\", "/")
$BinPathConfig = ""
if ($LLM_BIN_PATH_TOML) {
    $BinPathConfig = "bin_path = `"$LLM_BIN_PATH_TOML`""
}

if ($ShouldWrite) {
    $toml = @"
[ingestion]
max_events_per_second = 1000
channel_capacity = 10000
max_event_age_seconds = 60
enforce_hmac = false
bind_address = "127.0.0.1:3000"

[storage]
db_path = "target/vigil-dev.redb"
max_db_size_bytes = 1073741824
compaction_interval_secs = 3600

[detection]
model_path = "./models/isolation_forest.model"
anomaly_threshold = 0.85
window_size = 100

[llm]
model_path = "$ChosenModelPathToml"
$BinPathConfig
max_tokens = 512
temperature = 0.1
n_threads = 4
gpu_layers = 0

[hmac_keys]
ground-station-1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"@
    Set-Content -Path $ConfigPath -Value $toml
    Write-Host "[+] Generated vigil.toml" -ForegroundColor Green
}

Write-Host "`nSTEP 4 / 4 - Compiling VIGIL" -ForegroundColor Yellow
if (Test-Path "target\vigil-dev.redb") {
    Remove-Item "target\vigil-dev.redb" -Force
}
Write-Host "[*] Running cargo build..." -ForegroundColor Cyan
cargo build

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Setup complete!                                             ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n  To start VIGIL, run:" -ForegroundColor White
Write-Host "`n    cargo run --bin vigil-daemon -- --mode synthetic --events 150`n" -ForegroundColor Green
Write-Host "  Then open your browser to: http://localhost:3000`n" -ForegroundColor Cyan
