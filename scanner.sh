#!/bin/bash

# Function: Display usage instructions
usage() {
  echo "Usage: $0 <target_ip_or_hostname>" >&2
  exit 1
}

# Function: Write header
write_header() {
  local target="$1"
  echo
  echo "::::::::::Network Security Scan Report::::::::::"
  echo
  echo "Target: $target"
  echo
}

# Function: Perform scan and store results
perform_scan() {
  echo "[*] Running Nmap scan with vuln scripts against $TARGET..."
  SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET")
}

# Function: Write ports section
write_ports_section() {
  echo "::::::::::Open Ports and Detected Services::::::::::"
  echo
  echo "$SCAN_RESULTS" | grep "open"
  echo
}

# Function: Write vulnerabilities section 
write_vulns_section() {
  echo "::::::::::Potential Vulnerabilities Identified::::::::::"
  echo
  echo "--- NSE Script Findings ---"
  if echo "$SCAN_RESULTS" | grep -q "VULNERABLE"; then
    echo "$SCAN_RESULTS" | grep -A 4 "VULNERABLE"
  else
    echo "No high-confidence NSE vulnerabilities found."
  fi
  echo
}

# Function: Write recommendations section
write_recs_section() {
  echo "::::::::::Recommendations for Remediation::::::::::"
  echo
  echo "- Update all software to the latest versions."
  echo "- Change default credentials immediately."
  echo "- Implement a firewall."
  echo "- Disable unused services and close unnecessary ports."
  echo
}

# Function: Write footer
write_footer() {
  echo "::::::::::End of Report!::::::::::"
}

# Main function
main() {
  if [ $# -ne 1 ]; then
    usage
  fi

  TARGET="$1"
  OUTPUT_FILE="report.txt"

  perform_scan

  write_header "$TARGET" > "$OUTPUT_FILE"
  write_ports_section >> "$OUTPUT_FILE"
  write_vulns_section >> "$OUTPUT_FILE"
  write_recs_section >> "$OUTPUT_FILE"
  write_footer >> "$OUTPUT_FILE"

  echo "Report saved to $OUTPUT_FILE"
}

# Entry point
main "$@"
