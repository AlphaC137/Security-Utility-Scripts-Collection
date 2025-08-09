# Security & Utility Scripts Collection

A comprehensive collection of bash scripts for security and system administration tasks. These scripts provide essential security tools and utilities for system administrators, security professionals, and power users.

## 🛡️ Features

### Password Generator
- Configurable complexity (length, character sets)
- Support for uppercase, lowercase, numbers, and symbols
- Exclude ambiguous characters option
- Batch password generation

### SSH Key Management
- Generate SSH key pairs (RSA, Ed25519, ECDSA)
- Deploy public keys to remote servers
- List and manage existing keys
- Support for custom key names and passphrases

### System Update Automation
- Automated system updates with snapshot creation
- Rollback capability using snapper/timeshift
- Support for multiple package managers (apt, yum, pacman)
- Configurable reboot handling

### Security Scanner
- Port scanning with configurable ranges
- TCP and UDP support
- Multi-threaded scanning for performance
- Service identification
- Multiple output formats

### Certificate Monitor
- Monitor SSL/TLS certificate expiration
- Configurable warning and critical thresholds
- Batch monitoring from configuration files
- Multiple output formats (text, JSON, CSV)

### QR Code Generator
- Generate QR codes for text, URLs, WiFi credentials
- Terminal and PNG output
- Configurable size and error correction
- UTF-8 and ANSI display modes

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/AlphaC137/Security-Utility-Scripts-Collection
chmod +x install.sh
./install.sh
```

### Manual Installation
```bash
# Copy the main script
sudo cp security_tools.sh /usr/local/bin/security-tools
sudo chmod +x /usr/local/bin/security-tools

# Install dependencies (Ubuntu/Debian)
sudo apt install openssl openssh-client qrencode

# Install optional snapshot tools
sudo apt install timeshift  # or snapper for other distros
```

## 🚀 Usage

### Password Generator
```bash
# Generate a simple password
security-tools generate_password

# Generate complex password with symbols
security-tools generate_password -l 16 --symbols

# Generate multiple passwords excluding ambiguous characters
security-tools generate_password -l 12 -c 5 --exclude-ambiguous
```

### SSH Key Management
```bash
# Generate new SSH key
security-tools manage_ssh_keys generate -n mykey -t ed25519

# Deploy key to server
security-tools manage_ssh_keys deploy -s server.example.com -u username -k mykey

# List all SSH keys
security-tools manage_ssh_keys list
```

### System Updates
```bash
# Check for available updates
security-tools system_update check

# Install updates with snapshot
security-tools system_update install

# Install updates without snapshot
security-tools system_update install --no-snapshot

# Rollback to previous snapshot
security-tools system_update rollback
```

### Security Scanning
```bash
# Scan common ports
security-tools security_scan -t 192.168.1.1 -p 22,80,443,993,995

# Scan port range with verbose output
security-tools security_scan -t example.com -p 1-1000 -v

# Save results to file
security-tools security_scan -t 192.168.1.100 -p 1-65535 -o scan_results.txt
```

### Certificate Monitoring
```bash
# Check single certificate
security-tools check_certificates -d example.com

# Check with custom thresholds
security-tools check_certificates -d example.com -w 15 -c 3

# Check multiple certificates from config file
security-tools check_certificates -f ~/.config/security-tools/certificates.conf

# Output in JSON format
security-tools check_certificates -d example.com --format json
```

### QR Code Generation
```bash
# Generate QR code in terminal
security-tools generate_qr -t "Hello, World!"

# Generate QR code for URL and save as PNG
security-tools generate_qr -t "https://example.com" -o qr_code.png

# Generate WiFi QR code
security-tools generate_qr -t "WIFI:T:WPA;S:MyNetwork;P:MyPassword;;"
```

## ⚙️ Configuration

Configuration files are stored in `~/.config/security-tools/`:

### Certificate Monitoring (`certificates.conf`)
```
# Web servers
example.com:443
api.example.com:443

# Mail servers
mail.example.com:993
smtp.example.com:465
```

### SSH Deployment (`ssh_hosts.conf`)
```
# Production servers
prod-server1 ubuntu 22 id_rsa_prod
prod-server2 deploy 2222 id_ed25519
```

### Update Settings (`update.conf`)
```
CREATE_SNAPSHOT=true
SNAPSHOT_NAME_PREFIX="auto-update"
AUTO_REBOOT=false
REBOOT_DELAY=10
```

## 🔧 Dependencies

### Required
- `bash` (4.0+)
- `openssl`
- `openssh-client`

### Optional
- `qrencode` - For QR code generation
- `timeshift` or `snapper` - For system snapshots
- `nmap` - Enhanced port scanning (alternative method)

### Package Manager Support
- **Debian/Ubuntu**: `apt`
- **RHEL/CentOS/Fedora**: `yum`/`dnf`
- **Arch Linux**: `pacman`
- **openSUSE**: `zypper`

## 📖 Examples

### Automated Security Audit
```bash
#!/bin/bash
# Simple security audit script

# Check system updates
echo "=== System Updates ==="
security-tools system_update check

# Scan localhost for open ports
echo -e "\n=== Port Scan ==="
security-tools security_scan -t localhost -p 1-1000

# Check important certificates
echo -e "\n=== Certificate Status ==="
security-tools check_certificates -f ~/.config/security-tools/certificates.conf

# Generate audit report QR code
audit_url="https://audit.example.com/$(hostname)/$(date +%Y%m%d)"
security-tools generate_qr -t "$audit_url" -o "audit_qr_$(date +%Y%m%d).png"
```

### SSH Key Deployment Script
```bash
#!/bin/bash
# Deploy SSH keys to multiple servers

servers=("server1.example.com" "server2.example.com" "server3.example.com")
key_name="deployment_key"

# Generate deployment key if it doesn't exist
if [[ ! -f "$HOME/.ssh/$key_name" ]]; then
    security-tools manage_ssh_keys generate -n "$key_name" -t ed25519 -C "deployment@$(hostname)"
fi

# Deploy to all servers
for server in "${servers[@]}"; do
    echo "Deploying key to $server..."
    security-tools manage_ssh_keys deploy -s "$server" -u deploy -k "$key_name"
done
```

## 🛠️ Advanced Usage

### Custom Port Scanning
```bash
# Scan with custom parameters
security-tools security_scan \
    -t target.example.com \
    -p 1-65535 \
    --threads 200 \
    --timeout 5 \
    -v \
    -o detailed_scan.txt
```

### Batch Certificate Monitoring
```bash
# Create monitoring script for cron
#!/bin/bash
RESULTS=$(security-tools check_certificates -f /etc/security-tools/certificates.conf --format json)

# Parse results and send alerts
echo "$RESULTS" | jq -r '.[] | select(.status != "OK") | "\(.domain): \(.status) - \(.days_until_expiry) days"' | \
while read -r alert; do
    echo "$alert" | mail -s "Certificate Alert" admin@example.com
done
```

### Automated System Maintenance
```bash
#!/bin/bash
# Weekly maintenance script

# Create snapshot before updates
security-tools system_update install --snapshot-name "weekly-maintenance-$(date +%Y%m%d)"

# Security scan of critical systems
for host in web1 db1 mail1; do
    security-tools security_scan -t "$host.internal" -p 22,80,443,3306,25 >> "/var/log/security_scans/$(date +%Y%m%d).log"
done

# Check certificates
security-tools check_certificates -f /etc/maintenance/certificates.conf --format csv >> "/var/log/cert_monitoring/$(date +%Y%m%d).csv"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Security Considerations

- **SSH Keys**: Store private keys securely and use strong passphrases
- **Passwords**: Generated passwords are displayed in terminal - clear history if needed
- **Port Scanning**: Only scan systems you own or have permission to test
- **System Updates**: Always test updates in non-production environments first
- **Snapshots**: Verify snapshot creation before proceeding with system changes

## 🐛 Troubleshooting

### Common Issues

**QR Code generation fails**
```bash
# Install qrencode
sudo apt install qrencode  # Debian/Ubuntu
sudo yum install qrencode  # RHEL/CentOS
sudo pacman -S qrencode    # Arch Linux
```

**SSH key deployment fails**
```bash
# Check SSH connectivity
ssh -p PORT user@server

# Verify public key exists
ls -la ~/.ssh/*.pub
```

**Port scanning is slow**
```bash
# Reduce thread count for stability
security-tools security_scan -t target --threads 50

# Use timeout for faster scanning
security-tools security_scan -t target --timeout 1
```

**Certificate checking fails**
```bash
# Test manual connection
openssl s_client -connect example.com:443 -servername example.com

# Check firewall/network connectivity
telnet example.com 443
```

## 📊 Performance Notes

- **Port Scanning**: Default 100 threads, adjust based on system capabilities
- **Certificate Checking**: Sequential by design to avoid overwhelming servers  
- **Password Generation**: Cryptographically secure random generation
- **SSH Operations**: Standard OpenSSH tools for maximum compatibility

## 🔮 Future Enhancements

- [ ] Web dashboard for monitoring
- [ ] Email/webhook notifications
- [ ] Integration with configuration management tools
- [ ] Database backend for historical data
- [ ] REST API for external integrations
- [ ] Docker containerization
- [ ] Windows PowerShell equivalents
