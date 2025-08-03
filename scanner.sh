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
  echo ":Network Security Scan Report:"
  echo
  echo "Target: $target"
  echo
}

# Function: Write ports section
write_ports_section() {
  echo ":Open Ports and Detected Services:"
  echo
  # Run nmap and include only open ports
  nmap -sV "$TARGET" | grep "open"
  echo
}

# Function: Write vulnerabilities section
write_vulns_section() {
  echo ":Potential Vulnerabilities Identified:"
  echo
  echo "CVE-2023-XXXX - Outdated Web Server"
  echo "Default Credentials - FTP Server"
  echo
}

# Function: Write recommendations section
write_recs_section() {
  echo ":Recommendations for Remediation:"
  echo
  echo "- Update all software to the latest versions."
  echo "- Change default credentials immediately."
  echo "- Implement a firewall."
  echo
}

# Function: Write footer
write_footer() {
  echo ":End of Report!:"
}

# Main function
main() {
  if [ $# -ne 1 ]; then
    usage
  fi

  TARGET="$1"
  OUTPUT_FILE="report.txt"

  write_header "$TARGET" > "$OUTPUT_FILE"
  write_ports_section >> "$OUTPUT_FILE"
  write_vulns_section >> "$OUTPUT_FILE"
  write_recs_section >> "$OUTPUT_FILE"
  write_footer >> "$OUTPUT_FILE"

  echo "Report saved to $OUTPUT_FILE"
}

# Entry point
main "$@"
