#!/bin/bash

# ============================================================================
# EXAMPLE USAGE SCRIPTS FOR SECURITY TOOLS
# ============================================================================

# Example 1: Security Audit Script
# ============================================================================

security_audit() {
    local output_dir="./security_audit_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    
    echo "Starting security audit..."
    echo "Output directory: $output_dir"
    echo ""
    
    # System update check
    echo "=== Checking System Updates ==="
    security-tools system_update check > "$output_dir/system_updates.txt" 2>&1
    
    # Port scan localhost
    echo "=== Scanning Local Ports ==="
    security-tools security_scan -t localhost -p 1-10000 -o "$output_dir/port_scan_localhost.txt"
    
    # Check common services on network
    echo "=== Network Service Scan ==="
    local network=$(ip route | grep -E '192\.168\.|10\.|172\.' | head -1 | awk '{print $1}' | cut -d'/' -f1)
    if [[ -n "$network" ]]; then
        # Scan first 10 IPs in subnet for common ports
        for i in {1..10}; do
            local ip="${network%.*}.$i"
            security-tools security_scan -t "$ip" -p 22,80,443,21,25,53,110,993,995 >> "$output_dir/network_scan.txt" 2>&1 &
        done
        wait
    fi
    
    # Certificate checks
    echo "=== Certificate Monitoring ==="
    if [[ -f ~/.config/security-tools/certificates.conf ]]; then
        security-tools check_certificates -f ~/.config/security-tools/certificates.conf --format csv > "$output_dir/certificate_status.csv"
    fi
    
    # Generate summary QR code
    local summary_url="file://$PWD/$output_dir/audit_summary.html"
    security-tools generate_qr -t "$summary_url" -o "$output_dir/audit_qr.png"
    
    # Create HTML summary report
    cat > "$output_dir/audit_summary.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .critical { background-color: #ffebee; }
        .warning { background-color: #fff3e0; }
        .ok { background-color: #e8f5e8; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Security Audit Report</h1>
    <p><strong>Generated:</strong> $(date)</p>
    <p><strong>Host:</strong> $(hostname)</p>
    
    <div class="section">
        <h2>System Updates</h2>
        <pre>$(cat "$output_dir/system_updates.txt")</pre>
    </div>
    
    <div class="section">
        <h2>Local Port Scan</h2>
        <pre>$(head -20 "$output_dir/port_scan_localhost.txt")</pre>
    </div>
    
    <div class="section">
        <h2>Network Scan</h2>
        <pre>$(head -50 "$output_dir/network_scan.txt" 2>/dev/null || echo "No network scan data")</pre>
    </div>
</body>
</html>
EOF
    
    echo ""
    echo "Security audit completed!"
    echo "Results saved to: $output_dir"
    echo "View report: $output_dir/audit_summary.html"
}

# Example 2: SSH Key Deployment Manager
# ============================================================================

ssh_deployment_manager() {
    local action="$1"
    local config_file="$HOME/.config/security-tools/ssh_deployment.conf"
    
    case "$action" in
        setup)
            setup_ssh_deployment
            ;;
        deploy-all)
            deploy_all_keys
            ;;
        test-all)
            test_all_connections
            ;;
        *)
            echo "SSH Deployment Manager"
            echo "Usage: ssh_deployment_manager {setup|deploy-all|test-all}"
            echo ""
            echo "Commands:"
            echo "  setup       Setup deployment configuration"
            echo "  deploy-all  Deploy keys to all configured servers"
            echo "  test-all    Test all SSH connections"
            ;;
    esac
}

setup_ssh_deployment() {
    local config_file="$HOME/.config/security-tools/ssh_deployment.conf"
    
    echo "Setting up SSH deployment configuration..."
    
    # Create deployment key if it doesn't exist
    if [[ ! -f "$HOME/.ssh/id_deployment" ]]; then
        echo "Creating deployment SSH key..."
        security-tools manage_ssh_keys generate -n id_deployment -t ed25519 -C "deployment@$(hostname)"
    fi
    
    # Create configuration file template
    cat > "$config_file" << 'EOF'
# SSH Deployment Configuration
# Format: hostname:port username keyname description
# Lines starting with # are comments

# Production servers
# web1.example.com:22 deploy id_deployment Web Server 1
# web2.example.com:22 deploy id_deployment Web Server 2
# db1.example.com:22 dbadmin id_deployment Database Server

# Development servers  
# dev1.example.com:2222 developer id_deployment Development Server
# test.example.com:22 tester id_deployment Testing Server

# Management servers
# jump.example.com:22 admin id_deployment Jump Server
# monitor.example.com:22 nagios id_deployment Monitoring Server
EOF
    
    echo "Configuration template created: $config_file"
    echo "Edit the file to add your servers, then run:"
    echo "  ssh_deployment_manager deploy-all"
}

deploy_all_keys() {
    local config_file="$HOME/.config/security-tools/ssh_deployment.conf"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Configuration file not found. Run 'setup' first."
        return 1
    fi
    
    echo "Deploying SSH keys to all configured servers..."
    echo ""
    
    local success_count=0
    local fail_count=0
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^#.*$ ]] && continue
        
        local server_port=$(echo "$line" | awk '{print $1}')
        local username=$(echo "$line" | awk '{print $2}')
        local keyname=$(echo "$line" | awk '{print $3}')
        local description=$(echo "$line" | cut -d' ' -f4-)
        
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        
        echo "Deploying to $server ($description)..."
        
        if security-tools manage_ssh_keys deploy -s "$server" -u "$username" -p "$port" -k "$keyname" >/dev/null 2>&1; then
            echo "  ✓ Success"
            ((success_count++))
        else
            echo "  ✗ Failed"
            ((fail_count++))
        fi
        
    done < "$config_file"
    
    echo ""
    echo "Deployment completed: $success_count successful, $fail_count failed"
}

test_all_connections() {
    local config_file="$HOME/.config/security-tools/ssh_deployment.conf"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Configuration file not found. Run 'setup' first."
        return 1
    fi
    
    echo "Testing SSH connections to all configured servers..."
    echo ""
    
    local success_count=0
    local fail_count=0
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^#.*$ ]] && continue
        
        local server_port=$(echo "$line" | awk '{print $1}')
        local username=$(echo "$line" | awk '{print $2}')
        local keyname=$(echo "$line" | awk '{print $3}')
        local description=$(echo "$line" | cut -d' ' -f4-)
        
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        
        echo "Testing $server ($description)..."
        
        if ssh -i "$HOME/.ssh/$keyname" -p "$port" -o ConnectTimeout=10 -o BatchMode=yes "$username@$server" "echo 'Connection OK'" >/dev/null 2>&1; then
            echo "  ✓ Connection successful"
            ((success_count++))
        else
            echo "  ✗ Connection failed"
            ((fail_count++))
        fi
        
    done < "$config_file"
    
    echo ""
    echo "Connection test completed: $success_count successful, $fail_count failed"
}

# Example 3: Automated Maintenance Script
# ============================================================================

automated_maintenance() {
    local maintenance_log="/var/log/automated_maintenance.log"
    local config_dir="$HOME/.config/security-tools"
    local backup_dir="/backup/maintenance/$(date +%Y%m%d)"
    
    # Create backup directory
    sudo mkdir -p "$backup_dir"
    
    # Start logging
    exec 1> >(tee -a "$maintenance_log")
    exec 2>&1
    
    echo "============================================"
    echo "Automated Maintenance Script - $(date)"
    echo "============================================"
    
    # System health check
    echo ""
    echo "=== System Health Check ==="
    df -h
    free -h
    uptime
    
    # Check for system updates
    echo ""
    echo "=== System Update Check ==="
    security-tools system_update check
    
    # Security scans
    echo ""
    echo "=== Security Scan ==="
    
    # Scan localhost
    security-tools security_scan -t localhost -p 1-10000 -o "$backup_dir/localhost_scan.txt"
    
    # Scan configured hosts if available
    if [[ -f "$config_dir/scan_targets.conf" ]]; then
        while IFS= read -r target; do
            [[ -z "$target" || "$target" =~ ^#.*$ ]] && continue
            echo "Scanning $target..."
            security-tools security_scan -t "$target" -p 22,80,443,993,995 >> "$backup_dir/external_scans.txt" 2>&1
        done < "$config_dir/scan_targets.conf"
    fi
    
    # Certificate monitoring
    echo ""
    echo "=== Certificate Monitoring ==="
    if [[ -f "$config_dir/certificates.conf" ]]; then
        security-tools check_certificates -f "$config_dir/certificates.conf" --format csv > "$backup_dir/certificate_status.csv"
        
        # Check for expiring certificates
        local expiring_certs=$(security-tools check_certificates -f "$config_dir/certificates.conf" | grep -E "(WARNING|CRITICAL)")
        if [[ -n "$expiring_certs" ]]; then
            echo "⚠️  ATTENTION: Certificates expiring soon!"
            echo "$expiring_certs"
        fi
    fi
    
    # Generate maintenance report QR code
    echo ""
    echo "=== Generating Report ==="
    local report_url="file://$backup_dir/maintenance_report.html"
    security-tools generate_qr -t "$report_url" -o "$backup_dir/maintenance_qr.png"
    
    # Create maintenance report
    create_maintenance_report "$backup_dir"
    
    echo ""
    echo "Maintenance completed at $(date)"
    echo "Report available at: $backup_dir/maintenance_report.html"
}

create_maintenance_report() {
    local report_dir="$1"
    local report_file="$report_dir/maintenance_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Maintenance Report - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; background: #f9f9f9; }
        .critical { border-left-color: #d32f2f; background: #ffebee; }
        .warning { border-left-color: #f57c00; background: #fff3e0; }
        .success { border-left-color: #388e3c; background: #e8f5e8; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; font-weight: bold; }
        .status-ok { color: #388e3c; font-weight: bold; }
        .status-warning { color: #f57c00; font-weight: bold; }
        .status-critical { color: #d32f2f; font-weight: bold; }
        .qr-code { text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>System Maintenance Report</h1>
            <p><strong>Generated:</strong> $(date)</p>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>IP Address:</strong> $(hostname -I | awk '{print $1}')</p>
        </div>
        
        <div class="section success">
            <h2>System Overview</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Uptime</td><td>$(uptime -p)</td></tr>
                <tr><td>Load Average</td><td>$(uptime | awk -F'load average:' '{print $2}')</td></tr>
                <tr><td>Memory Usage</td><td>$(free -h | grep Mem | awk '{print $3 "/" $2 " (" int($3/$2*100) "%)"}')</td></tr>
                <tr><td>Disk Usage</td><td>$(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 ")"}')</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Security Scan Results</h2>
            $(if [[ -f "$report_dir/localhost_scan.txt" ]]; then
                local open_ports=$(grep "Open ports:" "$report_dir/localhost_scan.txt" | cut -d':' -f2 | tr -d ' ')
                if [[ "$open_ports" -gt 0 ]]; then
                    echo "<p class='status-warning'>Found $open_ports open ports on localhost</p>"
                else
                    echo "<p class='status-ok'>No unexpected open ports found</p>"
                fi
                echo "<pre>$(cat "$report_dir/localhost_scan.txt")</pre>"
            else
                echo "<p>No scan data available</p>"
            fi)
        </div>
        
        <div class="section">
            <h2>Certificate Status</h2>
            $(if [[ -f "$report_dir/certificate_status.csv" ]]; then
                echo "<table>"
                echo "<tr><th>Domain</th><th>Status</th><th>Days Until Expiry</th></tr>"
                tail -n +2 "$report_dir/certificate_status.csv" | while IFS=',' read -r domain status days expiry; do
                    local status_class="status-ok"
                    if [[ "$status" == "WARNING" ]]; then status_class="status-warning"; fi
                    if [[ "$status" == "CRITICAL" ]]; then status_class="status-critical"; fi
                    echo "<tr><td>$domain</td><td class='$status_class'>$status</td><td>$days</td></tr>"
                done
                echo "</table>"
            else
                echo "<p>No certificate data available</p>"
            fi)
        </div>
        
        <div class="section">
            <h2>System Updates</h2>
            <pre>$(security-tools system_update check 2>/dev/null || echo "Unable to check updates")</pre>
        </div>
        
        <div class="qr-code">
            <h3>Quick Access QR Code</h3>
            $(if [[ -f "$report_dir/maintenance_qr.png" ]]; then
                echo "<img src='maintenance_qr.png' alt='QR Code for this report' />"
            fi)
        </div>
        
        <div class="section">
            <h2>Files Generated</h2>
            <ul>
                $(for file in "$report_dir"/*; do
                    if [[ -f "$file" ]]; then
                        local filename=$(basename "$file")
                        local filesize=$(ls -lh "$file" | awk '{print $5}')
                        echo "<li>$filename ($filesize)</li>"
                    fi
                done)
            </ul>
        </div>
        
        <div class="section">
            <h2>Next Maintenance</h2>
            <p><strong>Recommended:</strong> $(date -d '+1 week' +%Y-%m-%d)</p>
            <p><strong>Actions Required:</strong></p>
            <ul>
                <li>Review certificate expiration warnings</li>
                <li>Install pending system updates</li>
                <li>Check disk space usage trends</li>
                <li>Verify backup integrity</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    echo "Maintenance report created: $report_file"
}

# Example 4: Certificate Monitoring with Notifications
# ============================================================================

certificate_monitor_with_alerts() {
    local config_file="$HOME/.config/security-tools/certificates.conf"
    local alert_file="/tmp/cert_alerts_$(date +%Y%m%d).txt"
    local email_recipient=""
    local webhook_url=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --email)
                email_recipient="$2"
                shift 2
                ;;
            --webhook)
                webhook_url="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [[ ! -f "$config_file" ]]; then
        echo "Certificate configuration not found: $config_file"
        return 1
    fi
    
    echo "Certificate monitoring with alerts started at $(date)"
    
    # Check certificates and capture output
    local cert_results=$(security-tools check_certificates -f "$config_file" --format json)
    
    # Parse results for alerts
    local critical_certs=()
    local warning_certs=()
    
    echo "$cert_results" | jq -r '.[] | select(.status == "CRITICAL") | .domain' | while read -r domain; do
        critical_certs+=("$domain")
    done
    
    echo "$cert_results" | jq -r '.[] | select(.status == "WARNING") | .domain' | while read -r domain; do
        warning_certs+=("$domain")
    done
    
    # Generate alert message
    local alert_message=""
    local has_alerts=false
    
    if [[ ${#critical_certs[@]} -gt 0 ]]; then
        alert_message+="🚨 CRITICAL: ${#critical_certs[@]} certificates expire within 7 days!\n"
        for cert in "${critical_certs[@]}"; do
            alert_message+="  - $cert\n"
        done
        has_alerts=true
    fi
    
    if [[ ${#warning_certs[@]} -gt 0 ]]; then
        alert_message+="⚠️  WARNING: ${#warning_certs[@]} certificates expire within 30 days!\n"
        for cert in "${warning_certs[@]}"; do
            alert_message+="  - $cert\n"
        done
        has_alerts=true
    fi
    
    if [[ "$has_alerts" == true ]]; then
        echo -e "$alert_message" | tee "$alert_file"
        
        # Send email alert
        if [[ -n "$email_recipient" ]] && command -v mail >/dev/null 2>&1; then
            echo -e "$alert_message" | mail -s "Certificate Expiration Alert - $(hostname)" "$email_recipient"
            echo "Email alert sent to $email_recipient"
        fi
        
        # Send webhook alert
        if [[ -n "$webhook_url" ]] && command -v curl >/dev/null 2>&1; then
            local webhook_payload=$(jq -n --arg text "$alert_message" --arg hostname "$(hostname)" \
                '{
                    "text": $text,
                    "username": "Certificate Monitor",
                    "hostname": $hostname,
                    "timestamp": (now | todate)
                }')
            
            curl -X POST -H "Content-Type: application/json" -d "$webhook_payload" "$webhook_url"
            echo "Webhook alert sent to $webhook_url"
        fi
    else
        echo "✅ All certificates are healthy"
    fi
    
    # Save full report
    echo "$cert_results" > "/tmp/cert_report_$(date +%Y%m%d_%H%M%S).json"
}

# Example 5: Password Policy Compliance Checker
# ============================================================================

password_policy_check() {
    local policy_file="$HOME/.config/security-tools/password_policy.conf"
    local test_mode=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test)
                test_mode=true
                shift
                ;;
            --policy)
                policy_file="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Create default policy file if it doesn't exist
    if [[ ! -f "$policy_file" ]]; then
        cat > "$policy_file" << 'EOF'
# Password Policy Configuration
MIN_LENGTH=12
REQUIRE_UPPERCASE=true
REQUIRE_LOWERCASE=true
REQUIRE_NUMBERS=true
REQUIRE_SYMBOLS=true
EXCLUDE_AMBIGUOUS=true
EXCLUDE_DICTIONARY_WORDS=true
MIN_ENTROPY_BITS=50
EOF
        echo "Created default policy file: $policy_file"
    fi
    
    # Load policy
    source "$policy_file"
    
    echo "Password Policy Compliance Checker"
    echo "=================================="
    echo "Policy file: $policy_file"
    echo ""
    
    if [[ "$test_mode" == true ]]; then
        # Generate test passwords with different compliance levels
        echo "Generating test passwords..."
        echo ""
        
        # Compliant password
        echo "✅ Compliant password:"
        local compliant_args="-l $MIN_LENGTH"
        [[ "$REQUIRE_SYMBOLS" == true ]] && compliant_args+=" --symbols"
        [[ "$EXCLUDE_AMBIGUOUS" == true ]] && compliant_args+=" --exclude-ambiguous"
        
        security-tools generate_password $compliant_args
        
        echo ""
        echo "❌ Non-compliant passwords:"
        
        # Too short
        echo "  Too short (8 chars):"
        security-tools generate_password -l 8
        
        # No symbols (if required)
        if [[ "$REQUIRE_SYMBOLS" == true ]]; then
            echo "  No symbols:"
            security-tools generate_password -l "$MIN_LENGTH"
        fi
        
        # Only lowercase (if uppercase required)
        if [[ "$REQUIRE_UPPERCASE" == true ]]; then
            echo "  Only lowercase:"
            security-tools generate_password -l "$MIN_LENGTH" --no-uppercase
        fi
        
    else
        # Interactive password checking
        while true; do
            echo -n "Enter password to check (or 'quit' to exit): "
            read -s password
            echo ""
            
            [[ "$password" == "quit" ]] && break
            
            check_password_compliance "$password"
            echo ""
        done
    fi
}

check_password_compliance() {
    local password="$1"
    local compliant=true
    local issues=()
    
    # Check length
    if [[ ${#password} -lt $MIN_LENGTH ]]; then
        issues+=("Password too short (${#password} < $MIN_LENGTH)")
        compliant=false
    fi
    
    # Check character requirements
    if [[ "$REQUIRE_UPPERCASE" == true ]] && [[ ! "$password" =~ [A-Z] ]]; then
        issues+=("Missing uppercase letters")
        compliant=false
    fi
    
    if [[ "$REQUIRE_LOWERCASE" == true ]] && [[ ! "$password" =~ [a-z] ]]; then
        issues+=("Missing lowercase letters")
        compliant=false
    fi
    
    if [[ "$REQUIRE_NUMBERS" == true ]] && [[ ! "$password" =~ [0-9] ]]; then
        issues+=("Missing numbers")
        compliant=false
    fi
    
    if [[ "$REQUIRE_SYMBOLS" == true ]] && [[ ! "$password" =~ [^a-zA-Z0-9] ]]; then
        issues+=("Missing symbols")
        compliant=false
    fi
    
    # Check for ambiguous characters
    if [[ "$EXCLUDE_AMBIGUOUS" == true ]] && [[ "$password" =~ [0OlI1] ]]; then
        issues+=("Contains ambiguous characters (0, O, l, I, 1)")
        compliant=false
    fi
    
    # Simple entropy estimation
    local charset_size=0
    [[ "$password" =~ [a-z] ]] && ((charset_size += 26))
    [[ "$password" =~ [A-Z] ]] && ((charset_size += 26))
    [[ "$password" =~ [0-9] ]] && ((charset_size += 10))
    [[ "$password" =~ [^a-zA-Z0-9] ]] && ((charset_size += 32))
    
    local entropy_bits=$(echo "scale=2; ${#password} * l($charset_size) / l(2)" | bc -l 2>/dev/null || echo "0")
    
    if (( $(echo "$entropy_bits < $MIN_ENTROPY_BITS" | bc -l 2>/dev/null || echo "1") )); then
        issues+=("Insufficient entropy ($entropy_bits < $MIN_ENTROPY_BITS bits)")
        compliant=false
    fi
    
    # Results
    if [[ "$compliant" == true ]]; then
        echo "✅ Password is COMPLIANT"
        echo "   Length: ${#password} characters"
        echo "   Estimated entropy: $entropy_bits bits"
    else
        echo "❌ Password is NON-COMPLIANT"
        echo "   Issues found:"
        for issue in "${issues[@]}"; do
            echo "   - $issue"
        done
    fi
}

# Example 6: Network Security Scanner
# ============================================================================

network_security_scan() {
    local network=""
    local output_dir="./network_scan_$(date +%Y%m%d_%H%M%S)"
    local quick_scan=false
    local stealth_scan=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--network)
                network="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            --quick)
                quick_scan=true
                shift
                ;;
            --stealth)
                stealth_scan=true
                shift
                ;;
            -h|--help)
                echo "Network Security Scanner"
                echo "Usage: network_security_scan [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -n, --network NETWORK   Network to scan (e.g., 192.168.1.0/24)"
                echo "  -o, --output DIR        Output directory"
                echo "  --quick                 Quick scan (common ports only)"
                echo "  --stealth               Stealth scan (slower, less detectable)"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Auto-detect network if not specified
    if [[ -z "$network" ]]; then
        network=$(ip route | grep -E '^192\.168\.|^10\.|^172\.' | head -1 | awk '{print $1}')
        if [[ -z "$network" ]]; then
            echo "Could not auto-detect network. Please specify with -n"
            return 1
        fi
    fi
    
    mkdir -p "$output_dir"
    
    echo "Network Security Scan"
    echo "===================="
    echo "Network: $network"
    echo "Output: $output_dir"
    echo "Started: $(date)"
    echo ""
    
    # Host discovery
    echo "=== Host Discovery ==="
    local active_hosts=()
    
    # Extract network base and range
    local network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local cidr=$(echo "$network" | cut -d'/' -f2)
    
    # Simple ping sweep for /24 networks
    if [[ "$cidr" == "24" ]]; then
        for i in {1..254}; do
            local host="$network_base.$i"
            if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
                active_hosts+=("$host")
                echo "Active host found: $host"
            fi &
            
            # Limit concurrent pings
            if (( $(jobs -r | wc -l) >= 50 )); then
                wait
            fi
        done
        wait
    fi
    
    echo "${#active_hosts[@]} active hosts found" | tee "$output_dir/host_discovery.txt"
    
    # Port scanning
    echo ""
    echo "=== Port Scanning ==="
    
    local port_range="22,80,443,21,25,53,110,143,993,995,3389,5432,3306"
    if [[ "$quick_scan" != true ]]; then
        port_range="1-10000"
    fi
    
    for host in "${active_hosts[@]}"; do
        echo "Scanning $host..."
        
        local scan_args="-t $host -p $port_range"
        if [[ "$stealth_scan" == true ]]; then
            scan_args+=" --threads 10 --timeout 5"
        else
            scan_args+=" --threads 50 --timeout 2"
        fi
        
        security-tools security_scan $scan_args -o "$output_dir/scan_$host.txt" &
        
        # Limit concurrent scans
        if (( $(jobs -r | wc -l) >= 5 )); then
            wait
        fi
    done
    
    wait
    
    # Generate summary report
    echo ""
    echo "=== Generating Summary ==="
    
    local summary_file="$output_dir/network_summary.html"
    generate_network_summary "$output_dir" "${active_hosts[@]}"
    
    # Generate network diagram QR code
    security-tools generate_qr -t "file://$PWD/$summary_file" -o "$output_dir/summary_qr.png"
    
    echo ""
    echo "Network scan completed!"
    echo "Summary report: $summary_file"
    echo "Scan data: $output_dir/"
}

generate_network_summary() {
    local output_dir="$1"
    shift
    local hosts=("$@")
    
    local summary_file="$output_dir/network_summary.html"
    
    cat > "$summary_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Scan Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .host { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .host-header { font-size: 1.2em; font-weight: bold; color: #333; }
        .ports { margin: 10px 0; }
        .port-open { color: #d32f2f; font-weight: bold; }
        .port-closed { color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .summary-stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 15px; background: #f9f9f9; border-radius: 5px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007acc; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Security Scan Summary</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Scanner:</strong> $(hostname)</p>
    </div>
    
    <div class="summary-stats">
        <div class="stat">
            <div class="stat-number">${#hosts[@]}</div>
            <div>Active Hosts</div>
        </div>
        <div class="stat">
            <div class="stat-number">$(find "$output_dir" -name "scan_*.txt" -exec grep -l "Open ports: [1-9]" {} \; | wc -l)</div>
            <div>Hosts with Open Ports</div>
        </div>
        <div class="stat">
            <div class="stat-number">$(find "$output_dir" -name "scan_*.txt" -exec grep -h "Open ports:" {} \; | awk -F: '{sum+=$2} END {print sum+0}')</div>
            <div>Total Open Ports</div>
        </div>
    </div>
    
    <h2>Host Details</h2>
EOF

    for host in "${hosts[@]}"; do
        local scan_file="$output_dir/scan_$host.txt"
        if [[ -f "$scan_file" ]]; then
            echo "    <div class='host'>" >> "$summary_file"
            echo "        <div class='host-header'>$host</div>" >> "$summary_file"
            
            if grep -q "Open ports: 0" "$scan_file"; then
                echo "        <div class='ports'>No open ports detected</div>" >> "$summary_file"
            else
                echo "        <div class='ports'>" >> "$summary_file"
                echo "            <strong>Open Ports:</strong><br>" >> "$summary_file"
                grep -A 50 "Open ports:" "$scan_file" | tail -n +3 | while read -r line; do
                    [[ -z "$line" || "$line" =~ ^=.*$ ]] && break
                    echo "            <span class='port-open'>$line</span><br>" >> "$summary_file"
                done
                echo "        </div>" >> "$summary_file"
            fi
            
            echo "    </div>" >> "$summary_file"
        fi
    done

    cat >> "$summary_file" << 'EOF'
    
    <h2>Recommendations</h2>
    <ul>
        <li>Review all open ports and ensure they are necessary</li>
        <li>Implement firewall rules to restrict access</li>
        <li>Keep services updated and properly configured</li>
        <li>Monitor for unauthorized services</li>
        <li>Use VPN for remote access when possible</li>
    </ul>
</body>
</html>
EOF

    echo "Network summary generated: $summary_file"
}
