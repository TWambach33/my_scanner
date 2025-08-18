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
  echo "[*] Running Nmap service/version scan against $TARGET..."
  SCAN_RESULTS=$(nmap -sV "$TARGET")
}

# Function: Write ports section
write_ports_section() {
  echo "::::::::::Open Ports and Detected Services::::::::::"
  echo
  echo "$SCAN_RESULTS" | grep "open"
  echo
}

# Function: Query NVD API
query_nvd() {
  local product="$1"
  local version="$2"
  local results_limit=3

  echo
  echo "Querying NVD for vulnerabilities in: $product $version..."

  local search_query
  search_query=$(echo "$product $version" | sed 's/ /%20/g')

  local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

  local vulnerabilities_json
  vulnerabilities_json=$(curl -s "$nvd_api_url")

  if [[ -z "$vulnerabilities_json" ]]; then
      echo "  [!] Error: Failed to fetch data from NVD. API might be down or unreachable."
      return
  fi
  if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
      echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
      return
  fi
  if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
      echo "  [+] No vulnerabilities found in NVD for this keyword search."
      return
  fi

  echo "$vulnerabilities_json" | jq -r \
      '.vulnerabilities[] |
      "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
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
  echo "--- Analyzing Service Versions ---"

  found=false
  echo "$SCAN_RESULTS" | while read -r line; do
    # Skip lines that are not application services
    if [[ "$line" =~ tcpwrapped|nping-echo|closed|filtered ]]; then
      continue
    fi

    # Extract product name and version
    product_name=$(echo "$line" | awk '{print $3, $4}')
    product_version=$(echo "$line" | awk '{print $5}')

    if [[ -z "$product_name" ]] || [[ -z "$product_version" ]]; then
        continue
    fi

    # Check for known vulnerabilities
    case "$line" in
      *"vsftpd 2.3.4"*)
        echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 is running, which contains a known backdoor (CVE-2011-2523)"
        found=true
        ;;
      *"Apache httpd 2.4.49"*)
        echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 is running, which is vulnerable to path traversal (CVE-2021-41773)"
        found=true
        ;;
      *"OpenSSL 1.0.1"*)
        echo "[!!] VULNERABILITY DETECTED: OpenSSL 1.0.1 is running, which is vulnerable to Heartbleed OpenSSL (CVE-2014-0160)"
        found=true
        ;;
      *"OpenSSH 7.2p2"*)
        echo "[!!] VULNERABILITY DETECTED: OpenSSH 7.2p2 is running, which is vulnerable to user enumeration (CVE-2016-6210)"
        found=true
        ;;
      *"ProFTPD 1.3.5"*)
        echo "[!!] VULNERABILITY DETECTED: ProFTPD 1.3.5 is running, which is vulnerable to arbitrary file read/write via mod_copy (CVE-2015-3306)"
        found=true
        ;;
      *"MySQL 5.5.45"*)
        echo "[!!] VULNERABILITY DETECTED: MySQL 5.5.45 is running, which is vulnerable to remote privilege escalation (CVE-2016-6662)"
        found=true
        ;;
      *"PHP 5.4.45"*)
        echo "[!!] VULNERABILITY DETECTED: PHP 5.4.4545 is running, which contains multiple security issues (CVE-2015-6835)"
        found=true
        ;;
      *"Apache Tomcat 9.0.0.M"*)
        echo "[!!] VULNERABILITY DETECTED: Apache Tomcat 9.0.0.M1–M17 is running, which is vulnerable to remote code execution (CVE-2016-8735)"
        found=true
        ;;
    esac

    # Query NVD only if product/version exists
    query_nvd "$product_name" "$product_version" >> "$OUTPUT_FILE"

  done

  if [ "$found" = false ]; then
    echo "No Known Service Versions Detected."
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
