#vuln-process-discovery.py
#This script automates Vulnerability and Rogue Process Discovery
#

import sys
import os
import subprocess
import pandas as pd
import requests
from packaging import version
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""

def query_nvd_for_software(software_name):
    headers = {
        "apiKey": API_KEY
    }
    params = {
        "keywordSearch": software_name,
        "resultsPerPage": 200
    }

    response = requests.get(NVD_API_URL, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Error querying {software_name}: {response.status_code}")
        return []

    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve_id = item['cve']['id']
        for config in item['cve'].get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get("vulnerable", False):
                        cpe = match.get("criteria", "")
                        results.append({
                            "CVE_ID": cve_id,
                            "CPE": cpe
                        })

    return results

def CheckOpenPorts(): #good to have but optional
    return

def VulnerabilityScan():
    #run the powershell script to inventory the software on the system
    #compare the csv file to the known vulnerabilities list
    return

def ProcessDiscovery():
    return

def main():
    print(query_nvd_for_software("steam"))
    return

if __name__ == "__main__":
    main()