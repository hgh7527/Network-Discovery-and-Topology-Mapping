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
import io
import psutil

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""

def is_version_vulnerable(installed_version, start_incl=None, start_excl=None,
                          end_incl=None, end_excl=None):
    try:
        v = version.parse(installed_version)
        if start_incl and v < version.parse(start_incl):
            return False
        if start_excl and v <= version.parse(start_excl):
            return False
        if end_incl and v > version.parse(end_incl):
            return False
        if end_excl and v >= version.parse(end_excl):
            return False
        return True
    except Exception:
        return False

def query_nvd_for_software(software_name, software_version=None):
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
        cve = item['cve']
        cve_id = cve['id']

        # ✅ FIXED: Access metrics directly
        metrics = cve.get('metrics', {})
        severity = "UNKNOWN"
        score = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score = cvss.get("baseScore")
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score = cvss.get("baseScore")
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score = cvss.get("baseScore")

        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get("vulnerable", False):
                        cpe = match.get("criteria", "")
                        start_incl = match.get("versionStartIncluding")
                        start_excl = match.get("versionStartExcluding")
                        end_incl = match.get("versionEndIncluding")
                        end_excl = match.get("versionEndExcluding")

                        # Fallback: extract version from CPE if no range given
                        cpe_parts = cpe.split(":")
                        cpe_version = cpe_parts[5] if len(cpe_parts) > 5 else None

                        if software_version:
                            if any([start_incl, start_excl, end_incl, end_excl]):
                                if not is_version_vulnerable(software_version, start_incl, start_excl, end_incl, end_excl):
                                    continue
                            elif cpe_version and cpe_version not in ["*", "-"]:
                                try:
                                    if version.parse(software_version) != version.parse(cpe_version):
                                        continue
                                except Exception:
                                    continue

                        results.append({
                            "CVE_ID": cve_id,
                            "Severity": severity,
                            "Score": score,
                            "CPE": cpe,
                            "VulnRange": f"{start_incl or start_excl or ''} - {end_incl or end_excl or ''}"
                        })

    return results

def display_vulnerabilities(vuln_list):
    from collections import defaultdict

    # Filter out CVEs with no score or score < 5.0
    filtered = [v for v in vuln_list if v.get('Score') is not None and v['Score'] >= 5.0]

    if not filtered:
        print("✅ No vulnerabilities with CVSS score ≥ 5.0 found.")
        return

    # Group by software
    grouped = defaultdict(list)
    for v in filtered:
        grouped[v['Software']].append(v)

    total = 0

    for software, vulns in grouped.items():
        version = vulns[0].get("InstalledVersion", "Unknown")
        print(f"\n📦 {software.upper()} (v{version}) — {len(vulns)} vulnerabilities\n")
        print(f"{'Severity':<10} {'CVE':<15} {'Score':<6} {'Vuln Range':<25} {'CPE'}")
        print("-" * 100)

        for v in sorted(vulns, key=lambda x: (-x['Score'], x['CVE_ID'])):
            print(f"{v['Severity']:<10} {v['CVE_ID']:<15} {str(v['Score']):<6} {v['VulnRange']:<25} {v['CPE']}")

        total += len(vulns)

    print(f"\n🔒 Total vulnerabilities with CVSS score ≥ 5.0: {total}")

def scan_installed_software(csv_path):
    if not os.path.exists(csv_path):
        print(f"❌ File not found: {csv_path}")
        return []

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["DisplayName", "DisplayVersion"])
    df['DisplayName'] = df['DisplayName'].str.strip().str.lower()
    df['DisplayVersion'] = df['DisplayVersion'].astype(str).str.strip()

    all_results = []

    for _, row in df.iterrows():
        name = row["DisplayName"]
        version_str = row["DisplayVersion"]

        print(f"\n🔍 Scanning {name} v{version_str}...")
        vulns = query_nvd_for_software(name, version_str)
        time.sleep(6)  # Respect NVD rate limit (5 requests / 30 sec)

        for v in vulns:
            v['Software'] = name
            v['InstalledVersion'] = version_str
            all_results.append(v)

    return all_results

def detect_weird_parents():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            parent = psutil.Process(proc.info['ppid']).name()
            if proc.info['name'].lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe']:
                if parent.lower() not in ['explorer.exe', 'services.exe']:
                    suspicious.append((proc.info['name'], proc.pid, parent))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not suspicious:
        print("✅ No suspicious parent-child processes detected.")
    else:
        print("⚠️ Suspicious parent-child process relationships detected:")
        for name, pid, parent in suspicious:
            print(f"🔹 {name} (PID: {pid}) — Parent: {parent}")
    return suspicious

def detect_processes_in_suspicious_paths():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info['exe']
            if exe and any(s in exe.lower() for s in ['\\appdata\\', '\\temp\\', '\\downloads\\']):
                suspicious.append((proc.info['name'], proc.pid, exe))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if not suspicious:
        print("✅ No suspicious process paths detected.")
    else:
        print("⚠️ Processes running from suspicious directories:")
        for name, pid, exe in suspicious:
            print(f"🔹 {name} (PID: {pid})")
            print(f"    Path: {exe}")
    return suspicious

def detect_networked_processes():
    net_procs = set()

    for conn in psutil.net_connections(kind='inet'):
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                net_procs.add((proc.name(), conn.pid, conn.laddr, conn.raddr))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    if not net_procs:
        print("✅ No networked processes detected.")
    else:
        print("~~~ Networked processes ~~~")
        for name, pid, laddr, raddr in net_procs:
            print(f"🔹 {name} (PID: {pid})")
            print(f"    Local Address: {laddr}")
            print(f"    Remote Address: {raddr if raddr else 'None'}")

    return list(net_procs)

def detect_long_running_scripts(min_seconds=600):
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            if proc.info['name'].lower() in ['python.exe', 'wscript.exe', 'powershell.exe']:
                # Calculate how long the process has been running
                runtime = time.time() - proc.info['create_time']
                if runtime > min_seconds:
                    suspicious.append((proc.info['name'], proc.pid, int(runtime)))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not suspicious:
        print("✅ No long-running scripts detected.")
    else:
        print("⚠️ Long-running script interpreters detected:")
        for name, pid, runtime in suspicious:
            mins = runtime // 60
            print(f"🔹 {name} (PID: {pid}) - Running for {mins} minutes")

    return suspicious


def run_sigcheck(sigcheck_path="C:\\Tools\\Sysinternals\\sigcheck.exe"):
    try:
        command = [sigcheck_path, "-accepteula", "-u", "-e"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print("❌ sigcheck failed:", result.stderr)
            return

        print("~~~sigcheck output:~~~")
        print(result.stdout)
        if "No matching" in result.stdout:
            print("✅ No issues found.")
            return
        else:
            print("❌ Issues found.")
            print(result.stdout)
            return

    except Exception as e:
        print(f"❌ Python error: {e}")

def CheckOpenPorts(): #good to have but optional
    return

def VulnerabilityScan():
    #run the powershell script to inventory the software on the system
    #compare the csv file to the known vulnerabilities list from NVD
    results = scan_installed_software("current_software.csv")
    display_vulnerabilities(results)

    if results:
        df = pd.DataFrame([v for v in results if v['Score'] and v['Score'] >= 5.0])
        df = df[["Software", "Severity", "CVE_ID", "Score", "InstalledVersion", "VulnRange", "CPE"]]
        df.to_csv("vulnerability_report_filtered.csv", index=False)
        print("\n📝 Filtered results saved to vulnerability_report_filtered.csv")
    return

def ProcessDiscovery():
    return

def main():
    VulnerabilityScan()
    detect_weird_parents()
    detect_processes_in_suspicious_paths()
    detect_networked_processes()
    detect_long_running_scripts()
    run_sigcheck()

    return

if __name__ == "__main__":
    main()