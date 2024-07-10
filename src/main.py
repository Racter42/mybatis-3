import os
import re
from xml.etree import ElementTree as ET

def check_log4j_vulnerabilities_in_file(content):
    # CVE scores (example values)
    cve_scores = {
        "CVE-2021-44228": 10.0,
        "CVE-2021-45046": 9.0,
        "CVE-2021-45105": 7.5,
        "CVE-2019-17571": 9.8,
        "CVE-2020-9488": 7.5,
        "CVE-2021-4104": 7.5,
        "CVE-2017-5645": 6.8,
        "Potential misconfiguration": 5.0  # Arbitrary lower score for potential misconfigurations
    }

    # Patterns to search for
    vulnerabilities = {
        "Vulnerable Log4j v2 version": {
            "pattern": re.compile(r'log4j\-(2\.14\.[0-9]|[2-9]\.[0-9]+|2\.[1-9]\.[0-9]+|2\.[0-9]\.[1-9]+)\.'),
            "CVE": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]
        },
        "Log4j v1 found, which is vulnerable": {
            "pattern": re.compile(r'log4j\-1\.[0-9]+\.[0-9]+'),
            "CVE": ["CVE-2019-17571"]
        },
        "JndiLookup.class found, possible vulnerability": {
            "pattern": re.compile(r'JndiLookup\.class'),
            "CVE": ["CVE-2021-44228"]
        },
        "JNDI lookup pattern found, possible vulnerability": {
            "pattern": re.compile(r'\$\{jndi:'),
            "CVE": ["CVE-2021-44228"]
        },
        "SMTPAppender found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.SMTPAppender'),
            "CVE": ["CVE-2020-9488"]
        },
        "JMSAppender found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.JMSAppender'),
            "CVE": ["CVE-2021-4104"]
        },
        "SocketServer found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.SocketServer'),
            "CVE": ["CVE-2019-17571"]
        },
        "Chainsaw UDPReceiver found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.chainsaw\.UDPReceiver'),
            "CVE": ["CVE-2017-5645"]
        },
        "Suspicious configuration pattern found: logger.addAppender": {
            "pattern": re.compile(r'logger\.addAppender'),
            "CVE": ["Potential misconfiguration"]
        },
        "Suspicious configuration pattern found: log4j.additivity": {
            "pattern": re.compile(r'log4j\.additivity'),
            "CVE": ["Potential misconfiguration"]
        }
    }

    found_vulnerabilities = []

    # Check for all vulnerabilities
    for description, details in vulnerabilities.items():
        if details["pattern"].search(content):
            for cve in details["CVE"]:
                found_vulnerabilities.append((description, cve, cve_scores.get(cve, 0)))

    return found_vulnerabilities

def check_pom_file_for_vulnerable_versions(file_path):
    vulnerable_versions = {
        "log4j-core": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.14.1", "2.15", "2.16"],
        "log4j-api": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.14.1", "2.15", "2.16"],
        "log4j": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.19"]
    }
    cve_scores = {
        "CVE-2021-44228": 10.0,
        "CVE-2021-45046": 9.0,
        "CVE-2021-45105": 7.5,
        "CVE-2019-17571": 9.8
    }

    found_vulnerabilities = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespace = {'m': 'http://maven.apache.org/POM/4.0.0'}
        
        for dependency in root.findall('.//m:dependency', namespace):
            group_id = dependency.find('m:groupId', namespace)
            artifact_id = dependency.find('m:artifactId', namespace)
            version = dependency.find('m:version', namespace)
            
            if group_id is not None and artifact_id is not None and version is not None:
                group_id_text = group_id.text
                artifact_id_text = artifact_id.text
                version_text = version.text

                if artifact_id_text in vulnerable_versions and version_text in vulnerable_versions[artifact_id_text]:
                    cves = {
                        "log4j-core": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                        "log4j-api": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                        "log4j": ["CVE-2019-17571"]
                    }
                    for cve in cves[artifact_id_text]:
                        found_vulnerabilities.append((f"Vulnerable {artifact_id_text} version: {version_text}", cve, cve_scores.get(cve, 0)))

    except ET.ParseError as e:
        print(f"Could not parse {file_path}: {e}")
    
    return found_vulnerabilities

def check_log4j_vulnerabilities_in_directory(directory_path):
    all_vulnerabilities = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning file: {file_path}")
            try:
                if file == 'pom.xml':
                    vulnerabilities = check_pom_file_for_vulnerable_versions(file_path)
                else:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        vulnerabilities = check_log4j_vulnerabilities_in_file(content)
                
                if vulnerabilities:
                    all_vulnerabilities.append((file_path, vulnerabilities))
            except Exception as e:
                print(f"Could not read file {file_path}: {e}")

    if not all_vulnerabilities:
        print("No vulnerabilities found.")
        return

   # Sort by CVE score
    sorted_vulnerabilities = sorted(
        all_vulnerabilities,
        key=lambda x: max(v[2] for v in x[1]),
        reverse=True
    )

    # Print the results
    print("Vulnerabilities found:")
    for file_path, vulnerabilities in sorted_vulnerabilities:
        print(f"File: {file_path}")
        for description, cve, score in vulnerabilities:
            print(f"  - {description}: {cve} (Score: {score})")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Scan a directory for Log4j vulnerabilities.')
    parser.add_argument('directory', type=str, help='The source directory to scan for vulnerabilities.')
    args = parser.parse_args()

    check_log4j_vulnerabilities_in_directory(args.directory)
