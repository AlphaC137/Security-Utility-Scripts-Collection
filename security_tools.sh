#!/bin/bash

# ============================================================================
# SECURITY & UTILITY SCRIPTS COLLECTION
# ============================================================================

# 1. PASSWORD GENERATOR WITH CONFIGURABLE COMPLEXITY
# ============================================================================

generate_password() {
    local length=12
    local use_uppercase=true
    local use_lowercase=true
    local use_numbers=true
    local use_symbols=false
    local exclude_ambiguous=false
    local count=1
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--length)
                length="$2"
                shift 2
                ;;
            -c|--count)
                count="$2"
                shift 2
                ;;
            --no-uppercase)
                use_uppercase=false
                shift
                ;;
            --no-lowercase)
                use_lowercase=false
                shift
                ;;
            --no-numbers)
                use_numbers=false
                shift
                ;;
            --symbols)
                use_symbols=true
                shift
                ;;
            --exclude-ambiguous)
                exclude_ambiguous=true
                shift
                ;;
            -h|--help)
                echo "Password Generator"
                echo "Usage: generate_password [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -l, --length N          Password length (default: 12)"
                echo "  -c, --count N           Number of passwords (default: 1)"
                echo "  --no-uppercase          Exclude uppercase letters"
                echo "  --no-lowercase          Exclude lowercase letters"
                echo "  --no-numbers            Exclude numbers"
                echo "  --symbols               Include symbols (!@#$%^&*)"
                echo "  --exclude-ambiguous     Exclude ambiguous chars (0,O,l,1,I)"
                echo "  -h, --help              Show this help"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Build character set
    local charset=""
    if [[ "$use_lowercase" == true ]]; then
        if [[ "$exclude_ambiguous" == true ]]; then
            charset="${charset}abcdefghijkmnopqrstuvwxyz"
        else
            charset="${charset}abcdefghijklmnopqrstuvwxyz"
        fi
    fi
    
    if [[ "$use_uppercase" == true ]]; then
        if [[ "$exclude_ambiguous" == true ]]; then
            charset="${charset}ABCDEFGHJKLMNPQRSTUVWXYZ"
        else
            charset="${charset}ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fi
    fi
    
    if [[ "$use_numbers" == true ]]; then
        if [[ "$exclude_ambiguous" == true ]]; then
            charset="${charset}23456789"
        else
            charset="${charset}0123456789"
        fi
    fi
    
    if [[ "$use_symbols" == true ]]; then
        charset="${charset}!@#$%^&*()_+-=[]{}|;:,.<>?"
    fi
    
    if [[ -z "$charset" ]]; then
        echo "Error: No character types selected!"
        return 1
    fi
    
    # Generate passwords
    for ((i=1; i<=count; i++)); do
        local password=""
        for ((j=0; j<length; j++)); do
            local random_index=$((RANDOM % ${#charset}))
            password="${password}${charset:$random_index:1}"
        done
        echo "$password"
    done
}

# 2. SSH KEY MANAGEMENT AND DEPLOYMENT
# ============================================================================

manage_ssh_keys() {
    local action="$1"
    shift
    
    case "$action" in
        generate)
            ssh_generate_key "$@"
            ;;
        deploy)
            ssh_deploy_key "$@"
            ;;
        list)
            ssh_list_keys "$@"
            ;;
        remove)
            ssh_remove_key "$@"
            ;;
        *)
            echo "SSH Key Management"
            echo "Usage: manage_ssh_keys {generate|deploy|list|remove} [OPTIONS]"
            echo ""
            echo "Commands:"
            echo "  generate    Generate new SSH key pair"
            echo "  deploy      Deploy public key to remote server"
            echo "  list        List available SSH keys"
            echo "  remove      Remove SSH key pair"
            echo ""
            echo "Use 'manage_ssh_keys COMMAND --help' for command-specific help"
            ;;
    esac
}

ssh_generate_key() {
    local key_name="id_rsa"
    local key_type="rsa"
    local key_bits="4096"
    local comment=""
    local passphrase=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                key_name="$2"
                shift 2
                ;;
            -t|--type)
                key_type="$2"
                shift 2
                ;;
            -b|--bits)
                key_bits="$2"
                shift 2
                ;;
            -C|--comment)
                comment="$2"
                shift 2
                ;;
            --passphrase)
                passphrase="$2"
                shift 2
                ;;
            -h|--help)
                echo "Generate SSH Key"
                echo "Usage: manage_ssh_keys generate [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -n, --name NAME         Key name (default: id_rsa)"
                echo "  -t, --type TYPE         Key type (rsa, ed25519, ecdsa)"
                echo "  -b, --bits BITS         Key bits (default: 4096 for RSA)"
                echo "  -C, --comment COMMENT   Key comment"
                echo "  --passphrase PASS       Key passphrase (empty for no passphrase)"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    local key_path="$HOME/.ssh/$key_name"
    
    if [[ -f "$key_path" ]]; then
        read -p "Key $key_path already exists. Overwrite? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Aborted."
            return 1
        fi
    fi
    
    echo "Generating SSH key: $key_path"
    
    local ssh_keygen_args=(-t "$key_type" -f "$key_path")
    
    if [[ "$key_type" == "rsa" ]]; then
        ssh_keygen_args+=(-b "$key_bits")
    fi
    
    if [[ -n "$comment" ]]; then
        ssh_keygen_args+=(-C "$comment")
    fi
    
    if [[ -n "$passphrase" ]]; then
        ssh_keygen_args+=(-N "$passphrase")
    else
        ssh_keygen_args+=(-N "")
    fi
    
    ssh-keygen "${ssh_keygen_args[@]}"
    
    if [[ $? -eq 0 ]]; then
        echo "SSH key generated successfully!"
        echo "Private key: $key_path"
        echo "Public key: $key_path.pub"
        echo ""
        echo "Public key content:"
        cat "$key_path.pub"
    fi
}

ssh_deploy_key() {
    local server=""
    local user="$(whoami)"
    local port="22"
    local key_name="id_rsa"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server)
                server="$2"
                shift 2
                ;;
            -u|--user)
                user="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -k|--key)
                key_name="$2"
                shift 2
                ;;
            -h|--help)
                echo "Deploy SSH Key"
                echo "Usage: manage_ssh_keys deploy [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -s, --server SERVER     Remote server address"
                echo "  -u, --user USER         Remote username (default: current user)"
                echo "  -p, --port PORT         SSH port (default: 22)"
                echo "  -k, --key KEYNAME       Key name (default: id_rsa)"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [[ -z "$server" ]]; then
        echo "Error: Server address required!"
        return 1
    fi
    
    local public_key="$HOME/.ssh/$key_name.pub"
    
    if [[ ! -f "$public_key" ]]; then
        echo "Error: Public key not found: $public_key"
        return 1
    fi
    
    echo "Deploying public key to $user@$server:$port"
    
    ssh-copy-id -i "$public_key" -p "$port" "$user@$server"
    
    if [[ $? -eq 0 ]]; then
        echo "SSH key deployed successfully!"
        echo "Test connection: ssh -p $port $user@$server"
    fi
}

ssh_list_keys() {
    echo "Available SSH keys in $HOME/.ssh/:"
    echo ""
    
    for key in "$HOME/.ssh"/*.pub; do
        if [[ -f "$key" ]]; then
            local private_key="${key%.pub}"
            local key_name="$(basename "$private_key")"
            local key_type="$(ssh-keygen -l -f "$key" 2>/dev/null | awk '{print $4}' | tr -d '()')"
            local key_bits="$(ssh-keygen -l -f "$key" 2>/dev/null | awk '{print $1}')"
            local key_fingerprint="$(ssh-keygen -l -f "$key" 2>/dev/null | awk '{print $2}')"
            
            echo "Key: $key_name"
            echo "  Type: $key_type"
            echo "  Bits: $key_bits"
            echo "  Fingerprint: $key_fingerprint"
            echo "  Private key exists: $([ -f "$private_key" ] && echo "Yes" || echo "No")"
            echo ""
        fi
    done
}

# 3. SYSTEM UPDATE AUTOMATION WITH ROLLBACK
# ============================================================================

system_update() {
    local action="$1"
    shift
    
    case "$action" in
        check)
            update_check "$@"
            ;;
        install)
            update_install "$@"
            ;;
        rollback)
            update_rollback "$@"
            ;;
        list-snapshots)
            update_list_snapshots "$@"
            ;;
        *)
            echo "System Update Manager"
            echo "Usage: system_update {check|install|rollback|list-snapshots} [OPTIONS]"
            echo ""
            echo "Commands:"
            echo "  check           Check for available updates"
            echo "  install         Install updates with snapshot creation"
            echo "  rollback        Rollback to previous snapshot"
            echo "  list-snapshots  List available snapshots"
            ;;
    esac
}

update_check() {
    echo "Checking for system updates..."
    echo ""
    
    if command -v apt >/dev/null 2>&1; then
        # Debian/Ubuntu
        sudo apt update >/dev/null 2>&1
        local updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
        echo "APT: $((updates - 1)) packages can be upgraded"
        
        if [[ $updates -gt 1 ]]; then
            echo ""
            echo "Upgradable packages:"
            apt list --upgradable 2>/dev/null | tail -n +2
        fi
        
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS
        local updates=$(yum check-update --quiet | wc -l)
        echo "YUM: $updates packages can be upgraded"
        
    elif command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        sudo pacman -Sy >/dev/null 2>&1
        local updates=$(pacman -Qu | wc -l)
        echo "Pacman: $updates packages can be upgraded"
        
        if [[ $updates -gt 0 ]]; then
            echo ""
            echo "Upgradable packages:"
            pacman -Qu
        fi
    fi
}

update_install() {
    local create_snapshot=true
    local auto_reboot=false
    local snapshot_name="pre-update-$(date +%Y%m%d-%H%M%S)"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-snapshot)
                create_snapshot=false
                shift
                ;;
            --auto-reboot)
                auto_reboot=true
                shift
                ;;
            --snapshot-name)
                snapshot_name="$2"
                shift 2
                ;;
            -h|--help)
                echo "Install System Updates"
                echo "Usage: system_update install [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --no-snapshot           Don't create snapshot before update"
                echo "  --auto-reboot           Automatically reboot if required"
                echo "  --snapshot-name NAME    Custom snapshot name"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Create snapshot if requested and supported
    if [[ "$create_snapshot" == true ]]; then
        echo "Creating system snapshot: $snapshot_name"
        
        if command -v snapper >/dev/null 2>&1; then
            sudo snapper create --description "$snapshot_name"
        elif command -v timeshift >/dev/null 2>&1; then
            sudo timeshift --create --comments "$snapshot_name"
        else
            echo "Warning: No snapshot tool found (snapper/timeshift). Proceeding without snapshot."
        fi
        echo ""
    fi
    
    # Install updates
    echo "Installing system updates..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt upgrade -y
        
        if [[ "$auto_reboot" == true ]] && [[ -f /var/run/reboot-required ]]; then
            echo "Reboot required. Rebooting in 10 seconds..."
            sleep 10
            sudo reboot
        fi
        
    elif command -v yum >/dev/null 2>&1; then
        sudo yum update -y
        
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Syu --noconfirm
    fi
    
    echo ""
    echo "System update completed!"
    
    if [[ -f /var/run/reboot-required ]]; then
        echo "Reboot required to complete the update process."
    fi
}

update_rollback() {
    echo "Available snapshots for rollback:"
    echo ""
    
    if command -v snapper >/dev/null 2>&1; then
        snapper list
        echo ""
        read -p "Enter snapshot number to rollback to: " snapshot_num
        
        if [[ -n "$snapshot_num" ]]; then
            echo "Rolling back to snapshot $snapshot_num..."
            sudo snapper undochange "$snapshot_num..0"
        fi
        
    elif command -v timeshift >/dev/null 2>&1; then
        sudo timeshift --list
        echo ""
        read -p "Enter snapshot name to restore: " snapshot_name
        
        if [[ -n "$snapshot_name" ]]; then
            echo "Restoring snapshot: $snapshot_name"
            sudo timeshift --restore --snapshot "$snapshot_name"
        fi
        
    else
        echo "No snapshot tool found (snapper/timeshift)."
        echo "Manual rollback required."
    fi
}

# 4. PORT SCANNER AND SECURITY CHECKER
# ============================================================================

security_scan() {
    local target=""
    local port_range="1-65535"
    local scan_type="tcp"
    local threads=100
    local timeout=3
    local output_file=""
    local verbose=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -p|--ports)
                port_range="$2"
                shift 2
                ;;
            --type)
                scan_type="$2"
                shift 2
                ;;
            --threads)
                threads="$2"
                shift 2
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                echo "Security Scanner"
                echo "Usage: security_scan [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -t, --target HOST       Target host/IP to scan"
                echo "  -p, --ports RANGE       Port range (e.g., 1-1000, 22,80,443)"
                echo "  --type TYPE             Scan type (tcp, udp)"
                echo "  --threads N             Number of threads (default: 100)"
                echo "  --timeout N             Timeout in seconds (default: 3)"
                echo "  -o, --output FILE       Output file"
                echo "  -v, --verbose           Verbose output"
                echo ""
                echo "Examples:"
                echo "  security_scan -t 192.168.1.1 -p 1-1000"
                echo "  security_scan -t example.com -p 22,80,443,993,995"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [[ -z "$target" ]]; then
        echo "Error: Target required!"
        return 1
    fi
    
    echo "Starting security scan on $target"
    echo "Port range: $port_range"
    echo "Scan type: $scan_type"
    echo "Threads: $threads"
    echo "Timeout: ${timeout}s"
    echo ""
    
    # Parse port range
    local ports=()
    if [[ "$port_range" == *"-"* ]]; then
        # Range format (e.g., 1-1000)
        local start_port=$(echo "$port_range" | cut -d'-' -f1)
        local end_port=$(echo "$port_range" | cut -d'-' -f2)
        for ((port=start_port; port<=end_port; port++)); do
            ports+=($port)
        done
    else
        # Comma-separated format (e.g., 22,80,443)
        IFS=',' read -ra ports <<< "$port_range"
    fi
    
    local open_ports=()
    local total_ports=${#ports[@]}
    local scanned=0
    
    # Function to scan a single port
    scan_port() {
        local port=$1
        
        if [[ "$scan_type" == "tcp" ]]; then
            if timeout "$timeout" bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
                open_ports+=($port)
                if [[ "$verbose" == true ]]; then
                    echo "Port $port: OPEN"
                fi
            elif [[ "$verbose" == true ]]; then
                echo "Port $port: CLOSED"
            fi
        fi
        
        ((scanned++))
        if (( scanned % 100 == 0 )); then
            echo "Progress: $scanned/$total_ports ports scanned"
        fi
    }
    
    # Run scans in parallel
    echo "Scanning ports..."
    
    for port in "${ports[@]}"; do
        while (( $(jobs -r | wc -l) >= threads )); do
            sleep 0.1
        done
        scan_port "$port" &
    done
    
    # Wait for all background jobs to complete
    wait
    
    # Results
    echo ""
    echo "=== SCAN RESULTS ==="
    echo "Target: $target"
    echo "Ports scanned: $total_ports"
    echo "Open ports: ${#open_ports[@]}"
    
    if [[ ${#open_ports[@]} -gt 0 ]]; then
        echo ""
        echo "Open ports:"
        for port in "${open_ports[@]}"; do
            local service=$(getent services "$port/tcp" 2>/dev/null | awk '{print $1}' || echo "unknown")
            echo "  $port/tcp - $service"
        done
    fi
    
    # Save to file if requested
    if [[ -n "$output_file" ]]; then
        {
            echo "Security Scan Report"
            echo "===================="
            echo "Date: $(date)"
            echo "Target: $target"
            echo "Ports scanned: $total_ports"
            echo "Open ports: ${#open_ports[@]}"
            echo ""
            if [[ ${#open_ports[@]} -gt 0 ]]; then
                echo "Open ports:"
                for port in "${open_ports[@]}"; do
                    local service=$(getent services "$port/tcp" 2>/dev/null | awk '{print $1}' || echo "unknown")
                    echo "  $port/tcp - $service"
                done
            fi
        } > "$output_file"
        echo ""
        echo "Results saved to: $output_file"
    fi
}

# 5. CERTIFICATE EXPIRATION MONITOR
# ============================================================================

check_certificates() {
    local domain=""
    local port="443"
    local warning_days=30
    local critical_days=7
    local config_file=""
    local output_format="text"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -w|--warning)
                warning_days="$2"
                shift 2
                ;;
            -c|--critical)
                critical_days="$2"
                shift 2
                ;;
            -f|--config)
                config_file="$2"
                shift 2
                ;;
            --format)
                output_format="$2"
                shift 2
                ;;
            -h|--help)
                echo "Certificate Expiration Monitor"
                echo "Usage: check_certificates [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -d, --domain DOMAIN     Domain to check"
                echo "  -p, --port PORT         Port number (default: 443)"
                echo "  -w, --warning DAYS      Warning threshold in days (default: 30)"
                echo "  -c, --critical DAYS     Critical threshold in days (default: 7)"
                echo "  -f, --config FILE       Config file with domains to check"
                echo "  --format FORMAT         Output format (text, json, csv)"
                echo ""
                echo "Config file format (one domain per line):"
                echo "  example.com:443"
                echo "  mail.example.com:993"
                echo "  ftp.example.com:21"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    local domains_to_check=()
    
    # Build list of domains to check
    if [[ -n "$config_file" && -f "$config_file" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^#.*$ ]] && domains_to_check+=("$line")
        done < "$config_file"
    elif [[ -n "$domain" ]]; then
        domains_to_check+=("$domain:$port")
    else
        echo "Error: No domain specified and no config file provided!"
        return 1
    fi
    
    local results=()
    
    # Check each domain
    for domain_port in "${domains_to_check[@]}"; do
        local check_domain=$(echo "$domain_port" | cut -d':' -f1)
        local check_port=$(echo "$domain_port" | cut -d':' -f2)
        
        if [[ "$check_port" == "$check_domain" ]]; then
            check_port=443
        fi
        
        echo "Checking certificate for $check_domain:$check_port..."
        
        # Get certificate info
        local cert_info=$(echo | openssl s_client -connect "$check_domain:$check_port" -servername "$check_domain" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
        
        if [[ -n "$cert_info" ]]; then
            local not_after=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2)
            local expiry_date=$(date -d "$not_after" +%s 2>/dev/null)
            local current_date=$(date +%s)
            local days_until_expiry=$(( (expiry_date - current_date) / 86400 ))
            
            local status="OK"
            if [[ $days_until_expiry -le $critical_days ]]; then
                status="CRITICAL"
            elif [[ $days_until_expiry -le $warning_days ]]; then
                status="WARNING"
            fi
            
            results+=("$check_domain:$check_port,$status,$days_until_expiry,$not_after")
            
            if [[ "$output_format" == "text" ]]; then
                echo "  Domain: $check_domain:$check_port"
                echo "  Status: $status"
                echo "  Days until expiry: $days_until_expiry"
                echo "  Expires: $not_after"
                echo ""
            fi
        else
            results+=("$check_domain:$check_port,ERROR,-1,Unable to retrieve certificate")
            if [[ "$output_format" == "text" ]]; then
                echo "  Domain: $check_domain:$check_port"
                echo "  Status: ERROR"
                echo "  Error: Unable to retrieve certificate"
                echo ""
            fi
        fi
    done
    
    # Output results in requested format
    if [[ "$output_format" == "json" ]]; then
        echo "["
        for i in "${!results[@]}"; do
            local result="${results[$i]}"
            local domain_port=$(echo "$result" | cut -d',' -f1)
            local status=$(echo "$result" | cut -d',' -f2)
            local days=$(echo "$result" | cut -d',' -f3)
            local expiry=$(echo "$result" | cut -d',' -f4-)
            
            echo "  {"
            echo "    \"domain\": \"$domain_port\","
            echo "    \"status\": \"$status\","
            echo "    \"days_until_expiry\": $days,"
            echo "    \"expiry_date\": \"$expiry\""
            if [[ $i -lt $((${#results[@]} - 1)) ]]; then
                echo "  },"
            else
                echo "  }"
            fi
        done
        echo "]"
    elif [[ "$output_format" == "csv" ]]; then
        echo "Domain,Status,Days Until Expiry,Expiry Date"
        for result in "${results[@]}"; do
            echo "$result"
        done
    fi
}

# 6. QR CODE GENERATOR
# ============================================================================

generate_qr() {
    local text=""
    local output_file=""
    local size="medium"
    local format="utf8"
    local error_correction="M"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--text)
                text="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -s|--size)
                size="$2"
                shift 2
                ;;
            -f|--format)
                format="$2"
                shift 2
                ;;
            -e|--error-correction)
                error_correction="$2"
                shift 2
                ;;
            -h|--help)
                echo "QR Code Generator"
                echo "Usage: generate_qr [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -t, --text TEXT         Text/URL to encode"
                echo "  -o, --output FILE       Output file (PNG format)"
                echo "  -s, --size SIZE         Size (small, medium, large)"
                echo "  -f, --format FORMAT     Output format (utf8, ansi)"
                echo "  -e, --error-correction  Error correction (L, M, Q, H)"
                echo ""
                echo "Examples:"
                echo "  generate_qr -t 'Hello World'"
                echo "  generate_qr -t 'https://example.com' -o qr.png"
                echo "  generate_qr -t 'WiFi:T:WPA;S:MyNetwork;P:password;;'"
                return 0
                ;;
            *)
                # If no flag, treat as text
                if [[ -z "$text" ]]; then
                    text="$1"
                else
                    echo "Unknown option: $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$text" ]]; then
        read -p "Enter text/URL to encode: " text
    fi
    
    if [[ -z "$text" ]]; then
        echo "Error: No text provided!"
        return 1
    fi
    
    # Check if qrencode is installed
    if ! command -v qrencode >/dev/null 2>&1; then
        echo "Error: qrencode is not installed!"
        echo "Install with: sudo apt install qrencode  # or equivalent for your distro"
        return 1
    fi
    
    # Set size parameters
    case "$size" in
        small) local qr_size=3 ;;
        medium) local qr_size=5 ;;
        large) local qr_size=8 ;;
        *) local qr_size=5 ;;
    esac
    
    echo "Generating QR code for: $text"
    echo ""
    
    if [[ -n "$output_file" ]]; then
        # Generate PNG file
        qrencode -l "$error_correction" -s "$qr_size" -o "$output_file" "$text"
        echo "QR code saved to: $output_file"
    else
        # Display in terminal
        if [[ "$format" == "ansi" ]]; then
            qrencode -l "$error_correction" -t ANSI256 "$text"
        else
            qrencode -l "$error_correction" -t UTF8 "$text"
        fi
    fi
}

# ============================================================================
# MAIN SCRIPT ENTRY POINT
# ============================================================================

show_help() {
    echo "Security & Utility Scripts Collection"
    echo "====================================="
    echo ""
    echo "Available commands:"
    echo "  generate_password        Generate secure passwords"
    echo "  manage_ssh_keys         SSH key management and deployment"
    echo "  system_update           System update automation with rollback"
    echo "  security_scan           Port scanner and security checker"
    echo "  check_certificates      Certificate expiration monitor"
    echo "  generate_qr             QR code generator"
    echo ""
    echo "Usage: ./security_tools.sh COMMAND [OPTIONS]"
    echo "   or: source security_tools.sh  # to load functions"
    echo ""
    echo "Examples:"
    echo "  ./security_tools.sh generate_password -l 16 --symbols"
    echo "  ./security_tools.sh manage_ssh_keys generate -n mykey -t ed25519"
    echo "  ./security_tools.sh security_scan -t 192.168.1.1 -p 1-1000"
    echo "  ./security_tools.sh check_certificates -d example.com"
    echo "  ./security_tools.sh generate_qr -t 'https://example.com'"
    echo ""
    echo "Use 'COMMAND --help' for command-specific help"
}

# Main execution when script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    command="$1"
    shift
    
    case "$command" in
        generate_password)
            generate_password "$@"
            ;;
        manage_ssh_keys)
            manage_ssh_keys "$@"
            ;;
        system_update)
            system_update "$@"
            ;;
        security_scan)
            security_scan "$@"
            ;;
        check_certificates)
            check_certificates "$@"
            ;;
        generate_qr)
            generate_qr "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Unknown command: $command"
            echo "Use './security_tools.sh help' for available commands"
            exit 1
            ;;
    esac
fi
