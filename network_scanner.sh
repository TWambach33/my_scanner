#!/bin/bash
# Network Vulnerability Scanner

# --- Prerequisite Check ---
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed. Please install it to continue." >&2
    exit 1
fi

# --- Input Validation ---
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
fi

TARGET="$1"
REPORT_FILE="scan_report.txt"

echo "Scanning target: $TARGET"
echo "--------------------------" > "$REPORT_FILE"

# --- Nmap Scan ---
echo "[+] Performing Nmap scan..."
nmap -sV -T4 "$TARGET" >> "$REPORT_FILE"
echo "[+] Scan complete. Report saved to $REPORT_FILE"
