#!/usr/bin/env bash
# ==============================================================================
# VIGIL — Automated Setup Wizard (xcomrade.tech Edition)
#
# Usage:  bash install.sh
#
# This wizard:
#   1. Auto-detects Rust, Ollama, llama-cli, and existing GGUF models
#   2. Offers the best LLM strategy based on what's already available
#   3. Generates vigil.toml with correct paths
#   4. Compiles the project
#   5. Prints a single copy-paste command to start the dashboard
#
# No sudo required for local developer mode.
# ==============================================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\e[1;31m'; GREEN='\e[1;92m'; YELLOW='\e[1;33m'
BLUE='\e[1;34m'; CYAN='\e[1;36m'; DIM='\e[2m'; BOLD='\e[1m'
NC='\e[0m'

# ── Helpers ─────────────────────────────────────────────────────────────────
info()  { echo -e "  ${CYAN}[*]${NC} $1"; }
ok()    { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "  ${RED}[-]${NC} $1"; }
hline() { echo -e "${DIM}──────────────────────────────────────────────────────────────${NC}"; }

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}VIGIL${NC} — Verified Intelligent Ground-station Infrastructure  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Air-Gapped Predictive AI NOC Copilot • xcomrade.tech${NC}        ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Environment Scan ───────────────────────────────────────────────
echo -e "${BOLD}STEP 1 / 4 — Scanning Environment${NC}"
hline

HAS_RUST=false; HAS_OLLAMA=false; HAS_LLAMA_CLI=false
FOUND_GGUF=""

# Rust
if command -v cargo >/dev/null 2>&1; then
    RUST_VER=$(rustc --version 2>/dev/null || echo "unknown")
    ok "Rust compiler found: ${CYAN}${RUST_VER}${NC}"
    HAS_RUST=true
else
    warn "Rust compiler not found."
    echo -e "     Install Rust (takes ~2 min):"
    echo -e "     ${CYAN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    echo -e "     Then run: ${CYAN}source ~/.cargo/env && bash install.sh${NC}"
    exit 1
fi

# Ollama
if command -v ollama >/dev/null 2>&1; then
    HAS_OLLAMA=true
    ok "Ollama detected: ${CYAN}$(command -v ollama)${NC}"
    # Try to list locally available models
    OLLAMA_MODELS=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' || true)
    if [ -n "$OLLAMA_MODELS" ]; then
        ok "Ollama models already pulled:"
        echo "$OLLAMA_MODELS" | while read -r m; do echo -e "     ${GREEN}•${NC} $m"; done
    fi
else
    info "Ollama not installed. ${DIM}(optional — Expert System works without it)${NC}"
fi

# llama-cli / llama.cpp
if command -v llama-cli >/dev/null 2>&1; then
    HAS_LLAMA_CLI=true
    ok "llama-cli detected: ${CYAN}$(command -v llama-cli)${NC}"
elif command -v llama-server >/dev/null 2>&1; then
    ok "llama-server detected (llama.cpp installed)"
    HAS_LLAMA_CLI=true
else
    info "llama-cli not found. ${DIM}(optional — Ollama or Expert System works without it)${NC}"
fi

# Scan for existing GGUF files
mkdir -p ./models
GGUF_FILES=$(find ./models -maxdepth 1 -name "*.gguf" -type f 2>/dev/null || true)
if [ -n "$GGUF_FILES" ]; then
    ok "GGUF model(s) already present in ./models/:"
    echo "$GGUF_FILES" | while read -r f; do
        SIZE=$(du -h "$f" 2>/dev/null | awk '{print $1}')
        echo -e "     ${GREEN}•${NC} $(basename "$f") ${DIM}(${SIZE})${NC}"
    done
    FOUND_GGUF=$(echo "$GGUF_FILES" | head -1)
fi

echo ""

# ── Step 2: AI Backend Selection ───────────────────────────────────────────
echo -e "${BOLD}STEP 2 / 4 — AI Backend Selection${NC}"
hline

# Smart default: pick the best option based on what's available
DEFAULT_CHOICE=1
if [ -n "$FOUND_GGUF" ]; then
    echo -e "  ${GREEN}AUTO-DETECTED: GGUF model found at ${CYAN}$(basename "$FOUND_GGUF")${NC}"
    echo -e "  VIGIL will use this model via llama-cli automatically."
    echo ""
    DEFAULT_CHOICE=0
elif [ "$HAS_OLLAMA" = true ] && [ -n "$OLLAMA_MODELS" ]; then
    echo -e "  ${GREEN}AUTO-DETECTED: Ollama is running with local models.${NC}"
    echo -e "  VIGIL will route diagnostics through Ollama automatically."
    echo ""
    DEFAULT_CHOICE=0
fi

if [ "$DEFAULT_CHOICE" -eq 0 ]; then
    echo -e "  Press ${CYAN}Enter${NC} to use detected AI backend, or choose manually:"
else
    echo -e "  How should VIGIL generate root-cause diagnostics?"
fi

echo ""
echo -e "  ${GREEN}1)${NC} Expert System (instant, zero download, works offline)"
echo -e "     ${DIM}Rule-based heuristics for BGP/LSP/Interface anomalies — always reliable${NC}"
echo ""
if [ "$HAS_OLLAMA" = true ]; then
    echo -e "  ${CYAN}2)${NC} Use Ollama (pull a small model if needed)"
    echo -e "     ${DIM}Recommended: qwen2.5:1.5b — only ~1 GB via Ollama registry${NC}"
else
    echo -e "  ${DIM}2) Install Ollama + pull a model  (ollama not detected — skipping)${NC}"
fi
echo ""
echo -e "  ${BLUE}3)${NC} Download GGUF model from Hugging Face (~1-4 GB)"
echo -e "     ${DIM}Direct .gguf download, requires llama-cli to run${NC}"
echo ""

if [ "$DEFAULT_CHOICE" -eq 0 ]; then
    read -r -p "  Enter choice [Enter = use auto-detected, 1-3]: " llm_choice
    llm_choice=${llm_choice:-0}
else
    read -r -p "  Enter choice [1-3, default: 1]: " llm_choice
    llm_choice=${llm_choice:-1}
fi

CHOSEN_MODEL_PATH="./models/expert-fallback-placeholder"
USE_OLLAMA_BACKEND=false

case "$llm_choice" in
    0)
        # Use whatever was auto-detected
        if [ -n "$FOUND_GGUF" ]; then
            CHOSEN_MODEL_PATH="$FOUND_GGUF"
            ok "Using detected GGUF model: $(basename "$FOUND_GGUF")"
        elif [ "$HAS_OLLAMA" = true ]; then
            USE_OLLAMA_BACKEND=true
            CHOSEN_MODEL_PATH="./models/ollama-routed"
            ok "Using Ollama for inference routing."
        fi
        ;;
    1)
        ok "Expert System selected — zero-download, instant startup."
        ;;
    2)
        if [ "$HAS_OLLAMA" = true ]; then
            USE_OLLAMA_BACKEND=true
            CHOSEN_MODEL_PATH="./models/ollama-routed"
            echo ""
            echo -e "  Available lightweight models:"
            echo -e "    a) ${GREEN}qwen2.5:1.5b${NC}   (~1 GB, fast)  ${DIM}← recommended${NC}"
            echo -e "    b) ${BLUE}phi3:mini${NC}       (~2.3 GB)"
            echo -e "    c) ${YELLOW}mistral:7b${NC}      (~4 GB, powerful)"
            read -r -p "  Pick model [a/b/c, default: a]: " model_pick
            model_pick=${model_pick:-a}
            case "$model_pick" in
                b) OLLAMA_PULL_MODEL="phi3:mini" ;;
                c) OLLAMA_PULL_MODEL="mistral:7b" ;;
                *) OLLAMA_PULL_MODEL="qwen2.5:1.5b" ;;
            esac
            echo ""
            info "Pulling ${CYAN}${OLLAMA_PULL_MODEL}${NC} via Ollama..."
            if ollama pull "$OLLAMA_PULL_MODEL" 2>&1; then
                ok "Model ${CYAN}${OLLAMA_PULL_MODEL}${NC} pulled successfully!"
            else
                warn "Ollama pull failed. Make sure the Ollama daemon is running."
                warn "You can start it with: ${CYAN}ollama serve${NC} (in another terminal)"
                warn "VIGIL will still work using the Expert System fallback."
            fi
        else
            warn "Ollama is not installed. Falling back to Expert System."
            warn "To install Ollama later: ${CYAN}curl -fsSL https://ollama.com/install.sh | sh${NC}"
        fi
        ;;
    3)
        echo ""
        echo -e "  Pick a GGUF model to download:"
        echo -e "    a) ${GREEN}Qwen2.5-1.5B-Q4_K_M${NC}   (~1.1 GB)  ${DIM}← recommended${NC}"
        echo -e "    b) ${BLUE}Phi-3.5-mini-Q4_K_M${NC}    (~2.2 GB)"
        echo -e "    c) ${YELLOW}Mistral-7B-Q4_K_M${NC}      (~4.1 GB, needs 16 GB RAM)"
        read -r -p "  Pick model [a/b/c, default: a]: " gguf_pick
        gguf_pick=${gguf_pick:-a}
        case "$gguf_pick" in
            b)
                MODEL_NAME="Phi-3.5-mini-instruct-Q4_K_M.gguf"
                MODEL_URL="https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf"
                ;;
            c)
                MODEL_NAME="mistral-7b-instruct-v0.3.Q4_K_M.gguf"
                MODEL_URL="https://huggingface.co/bartowski/Mistral-7B-Instruct-v0.3-GGUF/resolve/main/mistral-7b-instruct-v0.3.Q4_K_M.gguf"
                ;;
            *)
                MODEL_NAME="Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
                MODEL_URL="https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
                ;;
        esac
        CHOSEN_MODEL_PATH="./models/$MODEL_NAME"

        if [ -f "$CHOSEN_MODEL_PATH" ]; then
            ok "Model already exists at $CHOSEN_MODEL_PATH — skipping download."
        else
            echo ""
            info "Downloading ${CYAN}${MODEL_NAME}${NC}..."
            info "Source: ${DIM}${MODEL_URL}${NC}"
            echo ""
            if command -v curl >/dev/null; then
                curl -L --progress-bar -o "$CHOSEN_MODEL_PATH" "$MODEL_URL"
            elif command -v wget >/dev/null; then
                wget --show-progress -q -O "$CHOSEN_MODEL_PATH" "$MODEL_URL"
            else
                fail "Neither curl nor wget found. Please install one and retry."
                exit 1
            fi

            if [ -f "$CHOSEN_MODEL_PATH" ] && [ -s "$CHOSEN_MODEL_PATH" ]; then
                SIZE=$(du -h "$CHOSEN_MODEL_PATH" | awk '{print $1}')
                ok "Downloaded ${CYAN}${MODEL_NAME}${NC} (${SIZE})"
            else
                fail "Download failed or file is empty."
                exit 1
            fi
        fi
        ;;
esac

# If the chosen model is a GGUF file, ensure we have the llama-cli runner.
LLM_BIN_PATH_TOML=""
if [[ "$CHOSEN_MODEL_PATH" == *.gguf ]]; then
    if [ -n "$VIGIL_LLM_BIN" ] && [ -f "$VIGIL_LLM_BIN" ]; then
        LLM_BIN_PATH_TOML="$VIGIL_LLM_BIN"
        ok "Using custom llama-cli from env VIGIL_LLM_BIN: $LLM_BIN_PATH_TOML"
    elif ! command -v llama-cli >/dev/null 2>&1 && [ ! -f "./bin/llama-bin/llama-cli" ] && [ ! -f "./bin/llama-bin/bin/llama-cli" ]; then
        info "llama-cli not found in PATH or bin folder. Downloading pre-compiled llama.cpp for Linux..."
        mkdir -p ./bin
        LLAMA_ZIP="./bin/llama-zip.zip"
        if command -v curl >/dev/null; then
            curl -L --progress-bar -o "$LLAMA_ZIP" "https://github.com/ggerganov/llama.cpp/releases/download/b3130/llama-b3130-bin-ubuntu-x64.zip"
        else
            wget --show-progress -q -O "$LLAMA_ZIP" "https://github.com/ggerganov/llama.cpp/releases/download/b3130/llama-b3130-bin-ubuntu-x64.zip"
        fi
        
        if command -v unzip >/dev/null 2>&1; then
            unzip -q -o "$LLAMA_ZIP" -d ./bin/llama-bin
            rm -f "$LLAMA_ZIP"
            
            if [ -f "./bin/llama-bin/bin/llama-cli" ]; then
                chmod +x ./bin/llama-bin/bin/llama-cli
                LLM_BIN_PATH_TOML="./bin/llama-bin/bin/llama-cli"
            else
                chmod +x ./bin/llama-bin/llama-cli
                LLM_BIN_PATH_TOML="./bin/llama-bin/llama-cli"
            fi
            ok "Extracted llama-cli to $LLM_BIN_PATH_TOML"
        else
            warn "unzip is not installed. Skipping automatic extraction of llama-cli."
        fi
    elif [ -f "./bin/llama-bin/bin/llama-cli" ]; then
        LLM_BIN_PATH_TOML="./bin/llama-bin/bin/llama-cli"
    elif [ -f "./bin/llama-bin/llama-cli" ]; then
        LLM_BIN_PATH_TOML="./bin/llama-bin/llama-cli"
    fi
fi

echo ""

# ── Step 3: Generate Config ────────────────────────────────────────────────
echo -e "${BOLD}STEP 3 / 4 — Generating Configuration${NC}"
hline

CONFIG_PATH="./vigil.toml"
SHOULD_WRITE=true

if [ -f "$CONFIG_PATH" ]; then
    read -r -p "  vigil.toml already exists. Overwrite? [y/N]: " ow
    ow=${ow:-n}
    if [ "${ow,,}" != "y" ]; then
        SHOULD_WRITE=false
        info "Keeping existing vigil.toml"
    fi
fi

BIN_PATH_CONFIG=""
if [ -n "${LLM_BIN_PATH_TOML:-}" ]; then
    BIN_PATH_CONFIG="bin_path = \"${LLM_BIN_PATH_TOML}\""
fi

if [ "$SHOULD_WRITE" = true ]; then
    cat <<EOF > "$CONFIG_PATH"
# VIGIL Configuration — generated by install.sh
# Edit this file to tune ingestion, detection, and LLM settings.

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
model_path = "${CHOSEN_MODEL_PATH}"
${BIN_PATH_CONFIG}
max_tokens = 512
temperature = 0.1
n_threads = 4
gpu_layers = 0

[hmac_keys]
ground-station-1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EOF
    ok "Generated ${CYAN}vigil.toml${NC}"
fi

echo ""

# ── Step 4: Build ──────────────────────────────────────────────────────────
echo -e "${BOLD}STEP 4 / 4 — Compiling VIGIL${NC}"
hline

# Remove stale database that can cause deserialization errors
if [ -f "target/vigil-dev.redb" ]; then
    rm -f target/vigil-dev.redb
    info "Removed stale dev database to prevent schema conflicts."
fi

info "Running ${CYAN}cargo build${NC} (this takes ~30-60 seconds on first run)..."
echo ""
if cargo build 2>&1; then
    ok "Build successful!"
else
    fail "Cargo build failed. Check the error above."
    exit 1
fi

echo ""

# ── Done ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}${BOLD}Setup complete!${NC}                                            ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Summarize what was configured
echo -e "  ${BOLD}AI Backend:${NC}"
if [ "$USE_OLLAMA_BACKEND" = true ]; then
    echo -e "    Ollama → real LLM inference with expert system fallback"
elif [ -f "$CHOSEN_MODEL_PATH" ] && [[ "$CHOSEN_MODEL_PATH" == *.gguf ]]; then
    echo -e "    llama-cli + $(basename "$CHOSEN_MODEL_PATH") → real LLM with expert fallback"
else
    echo -e "    Expert System (rule-based) → instant, deterministic, offline"
fi
echo ""
echo -e "  ${BOLD}To start VIGIL, run:${NC}"
echo ""
echo -e "    ${GREEN}cargo run --bin vigil-daemon -- --mode synthetic --events 150${NC}"
echo ""
echo -e "  Then open your browser to: ${CYAN}http://localhost:3000${NC}"
echo ""
hline
echo -e "  ${DIM}Config: ./vigil.toml  •  Models: ./models/  •  DB: target/vigil-dev.redb${NC}"
echo ""
