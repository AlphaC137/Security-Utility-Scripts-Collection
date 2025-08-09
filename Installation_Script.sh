#!/bin/bash

# ============================================================================
# Security Tools Installation Script
# ============================================================================

set -e

INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="security-tools"
CONFIG_DIR="$HOME/.config/security-tools"

echo "Security Tools Installation Script"
echo "================================="
echo ""

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    echo "Installing system-wide to $INSTALL_DIR"
    INSTALL_SYSTEM=true
else
    echo "Installing to user directory: $HOME/.local/bin"
    INSTALL_DIR="$HOME/.local/bin"
    INSTALL_SYSTEM=false
    
    # Create user bin directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        echo "Added $HOME/.local/bin to PATH in ~/.bashrc"
        echo "Please run: source ~/.bashrc or restart your terminal"
    fi
fi

# Create config directory
mkdir -p "$CONFIG_DIR"

# Install dependencies
echo "Checking and installing dependencies..."

install_package() {
    local package="$1"
    
    if command -v apt >/dev/null 2>&1; then
        if ! dpkg -l | grep -q "^ii.*$package"; then
            echo "Installing $package via apt..."
            if [[ "$INSTALL_SYSTEM" == true ]]; then
                apt update && apt install -y "$package"
            else
                sudo apt update && sudo apt install -y "$package"
            fi
        fi
    elif command -v yum >/dev/null 2>&1; then
        if ! rpm -q "$package" >/dev/null 2>&1; then
            echo "Installing $package via yum..."
            if [[ "$INSTALL_SYSTEM" == true ]]; then
                yum install -y "$package"
            else
                sudo yum install -y "$package"
            fi
        fi
    elif command -v pacman >/dev/null 2>&1; then
        if ! pacman -Q "$package" >/dev/null 2>&1; then
            echo "Installing $package via pacman..."
            if [[ "$INSTALL_SYSTEM" == true ]]; then
                pacman -S --noconfirm "$package"
            else
                sudo pacman -S --noconfirm "$package"
            fi
        fi
    else
        echo "Warning: Package manager not detected. Please install $package manually."
    fi
}

# Essential dependencies
install_package "openssl"
install_package "openssh-client"

# Optional dependencies
echo ""
echo "Installing optional dependencies..."

# QR code support
if command -v apt >/dev/null 2>&1; then
    install_package "qrencode"
elif command -v yum >/dev/null 2>&1; then
    install_package "qrencode"
elif command -v pacman >/dev/null 2>&1; then
    install_package "qrencode"
fi

# Snapshot tools (optional)
if command -v apt >/dev/null 2>&1; then
    # Timeshift for Ubuntu/Debian
    if ! command -v timeshift >/dev/null 2>&1; then
        echo "Timeshift not found. You may want to install it manually for system snapshots."
    fi
elif command -v zypper >/dev/null 2>&1; then
    # Snapper for openSUSE
    install_package "snapper"
fi

# Copy main script
echo ""
echo "Installing security tools script..."

if [[ -f "security_tools.sh" ]]; then
    cp "security_tools.sh" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    echo "Script installed to: $INSTALL_DIR/$SCRIPT_NAME"
else
    echo "Error: security_tools.sh not found in current directory!"
    exit 1
fi

# Create sample configuration files
echo ""
echo "Creating sample configuration files..."

# Certificate monitoring config
cat > "$CONFIG_DIR/certificates.conf" << 'EOF'
# Certificate monitoring configuration
# Format: domain:port (one per line)
# Lines starting with # are comments

# Web servers
google.com:443
github.com:443
stackoverflow.com:443

# Mail servers
# gmail-smtp-in.l.google.com:993
# outlook.office365.com:993

# Custom domains
# example.com:443
# mail.example.com:993
EOF

# SSH hosts config
cat > "$CONFIG_DIR/ssh_hosts.conf" << 'EOF'
# SSH deployment configuration
# Format: hostname user port keyname
# Lines starting with # are comments

# Production servers
# prod-server1 ubuntu 22 id_rsa_prod
# prod-server2 deploy 2222 id_ed25519

# Development servers
# dev-server1 developer 22 id_rsa
EOF

# Update checker config
cat > "$CONFIG_DIR/update.conf" << 'EOF'
# System update configuration

# Snapshot settings
CREATE_SNAPSHOT=true
SNAPSHOT_NAME_PREFIX="auto-update"

# Reboot settings
AUTO_REBOOT=false
REBOOT_DELAY=10

# Notification settings (future feature)
NOTIFY_EMAIL=""
NOTIFY_WEBHOOK=""
EOF

# Create wrapper scripts for individual functions
echo ""
echo "Creating wrapper scripts..."

for func in "generate-password" "manage-ssh-keys" "system-update" "security-scan" "check-certificates" "generate-qr"; do
    cat > "$INSTALL_DIR/$func" << EOF
#!/bin/bash
exec "$INSTALL_DIR/$SCRIPT_NAME" "${func//-/_}" "\$@"
EOF
    chmod +x "$INSTALL_DIR/$func"
done

# Create man pages
echo ""
echo "Creating documentation..."

MANDIR="/usr/local/share/man/man1"
if [[ "$INSTALL_SYSTEM" != true ]]; then
    MANDIR="$HOME/.local/share/man/man1"
fi

mkdir -p "$MANDIR"

cat > "$MANDIR/security-tools.1" << 'EOF'
.TH SECURITY-TOOLS 1 "2024" "Security Tools" "User Commands"
.SH NAME
security-tools \- Collection of security and utility scripts
.SH SYNOPSIS
.B security-tools
.I COMMAND
.RI [ OPTIONS ]
.SH DESCRIPTION
A comprehensive collection of bash scripts for security and system administration tasks.
.SH COMMANDS
.TP
.B generate_password
Generate secure passwords with configurable complexity
.TP
.B manage_ssh_keys
SSH key management and deployment
.TP
.B system_update
System update automation with rollback capability
.TP
.B security_scan
Port scanner and security checker
.TP
.B check_certificates
Certificate expiration monitor
.TP
.B generate_qr
QR code generator for text/URLs
.SH EXAMPLES
.TP
Generate a 16-character password with symbols:
.B security-tools generate_password -l 16 --symbols
.TP
Scan common ports on a host:
.B security-tools security_scan -t 192.168.1.1 -p 22,80,443
.TP
Check certificate expiration:
.B security-tools check_certificates -d example.com
.SH FILES
.TP
.I ~/.config/security-tools/
Configuration directory
.SH AUTHOR
Security Tools Collection
.SH SEE ALSO
ssh-keygen(1), openssl(1), qrencode(1)
EOF

# Update man database if available
if command -v mandb >/dev/null 2>&1 && [[ "$INSTALL_SYSTEM" == true ]]; then
    mandb -q
elif command -v makewhatis >/dev/null 2>&1; then
    makewhatis "$MANDIR" 2>/dev/null || true
fi

echo ""
echo "Installation completed successfully!"
echo ""
echo "Available commands:"
echo "  security-tools                 - Main script"
echo "  generate-password              - Password generator"
echo "  manage-ssh-keys               - SSH key management"
echo "  system-update                 - System updates"
echo "  security-scan                 - Port scanner"
echo "  check-certificates            - Certificate monitor"
echo "  generate-qr                   - QR code generator"
echo ""
echo "Configuration files created in: $CONFIG_DIR"
echo "Documentation: man security-tools"
echo ""

if [[ "$INSTALL_SYSTEM" != true ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "IMPORTANT: Please run 'source ~/.bashrc' or restart your terminal"
    echo "to use the installed commands."
fi

echo ""
echo "Test installation with: security-tools --help"
