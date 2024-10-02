# gen_report.py

import sys
import logging
from vulnerability_scanner import (
    configure_logging,
    is_web_server_responsive,
    run_testssl_raw,
    run_nmap_raw,
    run_nikto_raw,
    run_whatweb_raw,
    run_gobuster_raw,
    prepare_raw_data,
    extract_vulnerabilities_from_section,
    parse_vulnerabilities,
    generate_report_with_gpt,
    validate_report,
    save_report,
    clean_up_temp_files
)

def main():
    configure_logging()
    if len(sys.argv) != 2:
        print("Usage: python3 gen_report.py <hostname>")
        sys.exit(1)

    host = sys.argv[1]
    logging.info(f"Starting vulnerability scans on {host}.")

    # Run Nmap scan
    print(f"Running Nmap scan on {host}...")
    nmap_data = run_nmap_raw(host)
    if not nmap_data:
        print("Nmap scan failed. Exiting.")
        sys.exit(1)
    else:
        print("Nmap scan completed successfully.")

    # Decide which scans to run based on Nmap output (simplified)
    scans_to_run = {
        'ssl': '443/tcp' in nmap_data or 'https' in nmap_data.lower(),
        'web': '80/tcp' in nmap_data or 'http' in nmap_data.lower()
    }

    # Initialize variables for raw outputs
    testssl_data = ""
    nikto_data = ""
    whatweb_data = ""
    gobuster_data = ""

    # Run testssl if necessary
    if scans_to_run['ssl']:
        print("\nRunning testssl (testssl.sh)...")
        testssl_data = run_testssl_raw(host)
        if not testssl_data:
            print("testssl failed.")
        else:
            print("testssl completed successfully.")
    else:
        print("\nSSL not detected. Skipping testssl.")

    # Run web-related scans if necessary
    if scans_to_run['web'] and is_web_server_responsive(host):
        print("\nRunning Nikto scan...")
        nikto_data = run_nikto_raw(host)
        if not nikto_data:
            print("Nikto scan failed.")
        else:
            print("Nikto scan completed successfully.")

        print("\nRunning WhatWeb scan...")
        whatweb_data = run_whatweb_raw(host)
        if not whatweb_data:
            print("WhatWeb scan failed.")
        else:
            print("WhatWeb scan completed successfully.")

        print("\nRunning Gobuster scan...")
        gobuster_data = run_gobuster_raw(host)
        if not gobuster_data:
            print("Gobuster scan failed.")
        else:
            print("Gobuster scan completed successfully.")
    else:
        print("\nWeb server not responsive or not detected. Skipping web-related scans.")

    # Prepare raw data sections
    print("\nPreparing raw data for GPT-4 analysis...")
    raw_data_sections = prepare_raw_data(nmap_data, nikto_data, whatweb_data, gobuster_data, testssl_data)

    # Initialize a list to hold all vulnerabilities
    all_vulnerabilities = []

    # Process each section individually
    for section_name, raw_data in raw_data_sections.items():
        # Check if raw_data is empty or indicates that the scan was not run
        if not raw_data.strip():
            print(f"\nNo data for {section_name}. Skipping processing.")
            logging.info(f"No data for {section_name}. Skipping processing.")
            continue  # Skip this section

        print(f"\nExtracting vulnerabilities from {section_name} with GPT-4...")
        gpt_response = extract_vulnerabilities_from_section(section_name, raw_data)
        if not gpt_response:
            print(f"GPT vulnerability extraction failed for {section_name}.")
            continue  # Proceed to the next section

        vulnerabilities = parse_vulnerabilities(gpt_response)
        if vulnerabilities:
            all_vulnerabilities.extend(vulnerabilities)
        else:
            print(f"No vulnerabilities found or parsing failed for {section_name}.")

    # Remove duplicate vulnerabilities (optional)
    unique_vulnerabilities = {v['Finding']: v for v in all_vulnerabilities}.values()

    # Check if any vulnerabilities were found
    if not unique_vulnerabilities:
        print("No vulnerabilities found across all scans. Exiting.")
        logging.info("No vulnerabilities found across all scans.")
        sys.exit(0)

    # Proceed to generate the final report with all vulnerabilities
    print("\nGenerating the final report with GPT-4...")
    report_content = generate_report_with_gpt(host, list(unique_vulnerabilities))
    if not report_content:
        print("GPT report generation failed. Exiting.")
        sys.exit(1)
    else:
        print("Report generated successfully.")

    # Validate the report
    print("\nValidating the report format...")
    is_valid, error_msg = validate_report(report_content)
    if is_valid:
        print("Report format is valid.")
    else:
        print(f"Report format validation failed: {error_msg}")
        print("Saving the report anyway.")

    # Save the report
    output_file = f"vulnerability_report_{host}.md"
    save_report(report_content, output_file)
    print(f"\nComprehensive vulnerability report saved to {output_file}")

    # Clean up temporary files
    clean_up_temp_files()

if __name__ == "__main__":
    main()
