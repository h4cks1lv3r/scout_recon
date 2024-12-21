#!/bin/bash

# Define constants
REPO_URL="https://github.com/h4cks1lv3r/scout_recon"
INSTALL_DIR="$HOME/scout_recon"
WORDLIST_DIR="$INSTALL_DIR/wordlists"
GO_BIN="/usr/local/go/bin"
GO_PATH="$HOME/go/bin"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y git golang-go build-essential wget unzip python3-pip

# Clone or update the repository
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Cloning scout_recon repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
else
    echo "Repository already exists. Pulling the latest changes..."
    cd "$INSTALL_DIR" && git pull
fi

# Set up Go environment
export PATH="$PATH:$GO_BIN:$GO_PATH"
mkdir -p "$GO_PATH"

# Install tools using Go
TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/OWASP/Amass/v3/..."
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/tomnomnom/waybackurls"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/ffuf/ffuf"
)

for tool in "${TOOLS[@]}"; do
    echo "Installing $(basename "$tool")..."
    go install "$tool" || {
        echo "Error installing $(basename "$tool")"
        exit 1
    }
    echo "Successfully installed $(basename "$tool")"
done

# Verify tools
REQUIRED_TOOLS=("subfinder" "amass" "httpx" "waybackurls" "katana" "ffuf")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command_exists "$tool"; then
        echo "Error: $tool is not installed or not in PATH."
        exit 1
    fi
    echo "$tool is installed."
done

# Create wordlist directory and download wordlists
mkdir -p "$WORDLIST_DIR"
if [ ! -f "$WORDLIST_DIR/combined_wordlist.txt" ]; then
    echo "Downloading combined_wordlist.txt..."
    wget -q "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-medium.txt" -O "$WORDLIST_DIR/directory-list-2.3-medium.txt"
    wget -q "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-big.txt" -O "$WORDLIST_DIR/combined_wordlist.txt"
    echo "Wordlists downloaded."
else
    echo "Wordlists already exist."
fi

# Install Python dependencies
if [ -f "$INSTALL_DIR/kali_scout_recon.py" ]; then
    echo "Installing Python dependencies..."
    pip3 install -r "$INSTALL_DIR/requirements.txt"
else
    echo "Python script not found. Skipping Python dependencies installation."
fi

# Final setup
echo "Setup complete. Add the following paths to your shell configuration file (e.g., ~/.bashrc or ~/.zshrc):"
echo "export PATH=\"$PATH:$GO_BIN:$GO_PATH\""

# Confirmation
echo "Scout Recon is installed at $INSTALL_DIR"
echo "Wordlists are located at $WORDLIST_DIR"
echo "Run kali_scout_recon.py with Python 3 to start your scans."
