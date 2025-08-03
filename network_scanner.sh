#!/bin/bash
# Network Vulnerability Scanner

# --- Input Validation ---
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
fi

TARGET="$1"
echo "Scanning target: $TARGET"
