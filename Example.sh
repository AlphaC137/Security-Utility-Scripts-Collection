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
    local config_file="$HOME/.config
