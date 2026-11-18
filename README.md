# SCAP Scanner PowerShell Tool

A comprehensive PowerShell script for running SCAP compliance scans on Windows systems.

## Overview

This tool provides a PowerShell interface for performing Security Content Automation Protocol (SCAP) scans on local Windows systems. It supports multiple SCAP scanning engines, benchmarks, and reporting formats, making it easy to integrate with existing vulnerability management processes.

> **Platform & content notes**
>
> - **Windows:** use `-ScannerType SCC`. OpenSCAP removed Microsoft Windows support on 2022-02-01, so it cannot evaluate Windows hosts.
> - **Windows 11 content:** the current DISA Windows 11 STIG SCAP Benchmark is **Ver 2 Rel 11 (SCAP 1.4)** and requires **SCC 5.15+**. There is no stable public, unauthenticated download URL — DISA's index is DoD-login gated and re-versioned each release, and CIS Windows 11 v5.1.0 SCAP is CIS SecureSuite-only — so the script no longer auto-downloads content. Obtain it manually and pass `-ContentPath` or `-CustomContentFile`.
> - **Linux (Debian/Ubuntu, Fedora/RHEL):** use the [`SCAP-Scan.sh`](SCAP-Scan.sh) companion, which drives OpenSCAP with SCAP Security Guide content.

## Features

- SCC for Windows scanning; OpenSCAP for Linux via the `SCAP-Scan.sh` companion
- Automatic installation of scanning tools (and, on Linux, content)
- Multiple benchmark support (DISA STIGs, NIST 800-53, CIS, etc.)
- Support for custom SCAP content
- Local scanning; remote targets are rejected to prevent mislabeled local results
- Flexible reporting formats (XML, HTML, CSV, PDF)
- Integration with vulnerability management systems
- Detailed logging and progress tracking

## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges (for installation and local scanning)
- Network connectivity to remote systems (for remote scanning)
- Internet connectivity (for downloading tools and content)

## Installation

No installation is required. Simply download the `SCAP-Scanner.ps1` script and run it with appropriate parameters.

For automatic installation of scanning tools, run the script with the `-InstallScanner` parameter:

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC -InstallScanner
```

## Usage

### Basic Usage

To run a basic SCAP scan on the local system with default settings:

```powershell
.\SCAP-Scanner.ps1
```

This will:
1. Install the SCC scanner if not already installed
2. Use installed DISA STIG content (or prompt for download)
3. Scan the local system
4. Generate reports in the default output directory

### Custom Scan

To run a more customized scan:

```powershell
.\SCAP-Scanner.ps1 -ScannerType OpenSCAP `
                   -Benchmark CIS `
                   -TargetHosts "localhost" `
                   -ReportFormat All `
                   -OutputPath "C:\SCAP_Reports"
```

### Using Existing Scanner and Content

If you already have a scanner installed and content available:

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC `
                   -ScannerPath "C:\Program Files\SCAP Compliance Checker" `
                   -ContentPath "C:\SCAP\Content" `
                   -Benchmark NIST_800_53
```

### Using Custom Content

To use custom SCAP content:

```powershell
.\SCAP-Scanner.ps1 -Benchmark Custom `
                   -CustomContentFile "C:\SCAP\Custom\my_custom_benchmark.xml"
```

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| ScannerType | String | Type of SCAP scanner to use (SCC or OpenSCAP) | SCC |
| ScannerPath | String | Path to existing scanner installation | Auto-detected |
| ContentPath | String | Path to existing SCAP content | Auto-detected |
| Benchmark | String | Benchmark to use for scanning | DISA_STIG |
| CustomContentFile | String | Path to custom SCAP content file | None |
| TargetHosts | String[] | List of hosts to scan | Local computer |
| OutputPath | String | Directory for scan reports | .\SCAP_Reports |
| ReportFormat | String | Format for reports (XML, HTML, PDF, CSV, All) | HTML |
| InstallScanner | Switch | Install scanner if not found | False |
| UpdateContent | Switch | Update SCAP content | False |
| ForceInstall | Switch | Force reinstallation of scanner | False |
| SkipRemediationChecks | Switch | Skip remediation checks during scan | False |
| Timeout | Int | Timeout in seconds for scan operations | 3600 |
| ExportToVulnerabilityManager | Switch | Export results to vulnerability management system | False |
| VulnerabilityManagerPath | String | Path to vulnerability manager directory | None |
| InstallMethod | String | Method to install scanner (Chocolatey, DoD, Manual, OpenSCAP) | Chocolatey |
| SccVersion | String | SCC version to install | 5.10.1 |

## Examples

### Basic Scan with DISA STIGs

```powershell
.\SCAP-Scanner.ps1 -Benchmark DISA_STIG
```

### Scan the Local System with CIS Benchmark

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC `
                   -Benchmark CIS `
                   -TargetHosts "localhost" `
                   -ReportFormat HTML
```

### Generate All Report Formats

```powershell
.\SCAP-Scanner.ps1 -ReportFormat All -OutputPath "C:\Reports\SCAP"
```

### Install SCC via Chocolatey

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC `
                   -InstallScanner `
                   -InstallMethod Chocolatey
```

### Install SCC from DoD Sources

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC `
                   -InstallScanner `
                   -InstallMethod DoD `
                   -SccVersion 5.10.1
```

### Export to Vulnerability Management System

```powershell
.\SCAP-Scanner.ps1 -ExportToVulnerabilityManager `
                   -VulnerabilityManagerPath "C:\VulnMgmt"
```

## Troubleshooting

### Common Issues

1. **Scanner installation fails**
   - Ensure you have administrative privileges
   - Check internet connectivity
   - Try a different installation method (e.g., `-InstallMethod Chocolatey`)
   - Try specifying an existing scanner path

2. **Content download fails**
   - Verify internet connectivity
   - Use existing content with `-ContentPath`
   - Check firewall settings
   - For DoD content, you may need to be on a DoD network or have CAC access

3. **Remote scan failures**
   - Ensure PowerShell remoting is enabled on target systems
   - Verify network connectivity
   - Check credentials and permissions

4. **Scanner executes but no results are found**
   - Check the user's SCC Sessions directory: `%USERPROFILE%\SCC\Sessions`
   - Look for results in the specified output directory
   - Review the log file for detailed information

### Logging

The script creates detailed logs in the output directory. Check these logs for troubleshooting information. The default log location is `.\SCAP_Reports\SCAP_Scanner_[timestamp].log`.

### Executable Location

The script automatically searches for scanner executables in several locations:
- Main installation directory 
- Bin subdirectories
- Standard program files locations

If the script cannot find the executable, you can specify the exact path using the `-ScannerPath` parameter.

## Result Files

The SCC scanner typically stores results in the following locations:
1. User's SCC Sessions directory: `%USERPROFILE%\SCC\Sessions\[date_time]\Results`
2. The specified output directory (when using -o parameter)

Result formats may include:
- HTML reports (All-Settings and Non-Compliance)
- XCCDF XML files
- CKL checklist files (for STIG Viewer)
- OVAL results and variables

## Integration

### Vulnerability Management

The script can export scan results to a vulnerability management system by using the `-ExportToVulnerabilityManager` parameter and specifying a directory with `-VulnerabilityManagerPath`.

The exported file is a JSON document that includes:
- Scan metadata (time, scanner, benchmark)
- Target host information
- Detailed test results
- Compliance scores

### Automation

For regular automated scanning, consider:
1. Creating a scheduled task to run the script
2. Using PowerShell workflows for parallel scanning of large environments
3. Integrating with CI/CD pipelines for compliance checks during deployment

## Linux companion: SCAP-Scan.sh

`SCAP-Scan.sh` is a Bash counterpart that runs OpenSCAP on Debian/Ubuntu and
Fedora/RHEL-family hosts using SCAP Security Guide (SSG) content. Unlike Windows
SCAP content, SSG ships in the distro packages, so the script can install and
locate content automatically.

```bash
# Install OpenSCAP + SSG, scan with a CIS profile, all report formats
sudo ./SCAP-Scan.sh --install --benchmark cis --format all

# List available profiles in the auto-detected datastream
./SCAP-Scan.sh --list-profiles

# Explicit profile and content, with a JSON summary
sudo ./SCAP-Scan.sh \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --content /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml \
  --export ./VulnMgmt
```

Key options: `--benchmark` (keyword match: cis, stig, pci-dss, ospp, standard,
anssi, hipaa), `--profile` (explicit id), `--content` (datastream), `--format`
(xml|html|arf|all), `--timeout`, `--tailoring`, `--export`, `--install`,
`--list-profiles`. Like the Windows script it scans the local host only, and it
treats `oscap` exit code 2 (one or more rules failed) as a completed evaluation,
not a scanner error.

## Full host auditor: linux-security-scan.sh

`linux-security-scan.sh` is a hybrid Linux security scanner for Debian/Ubuntu and
Fedora/RHEL families. It runs native checks using standard OS commands (no
mandatory installs, works offline) and also uses external tools when present
(Lynis, Trivy/Grype, rkhunter, chkrootkit, AIDE, and `SCAP-Scan.sh`/oscap).

Coverage: **configuration hardening** (SSH, sysctl, firewall, auditd, file
permissions, password policy), **accounts & auth** (UID 0, empty passwords,
duplicate UIDs, NOPASSWD sudo), **network exposure** (listening/publicly-bound
ports vs firewall), **vulnerability/CVE** (pending security updates; optional
Trivy), and **rootkit/file-integrity** (promiscuous NICs, deleted-binary
processes, rkhunter/chkrootkit, AIDE).

```bash
# Full audit, all report formats, into ./SecurityScan_Reports
sudo ./linux-security-scan.sh

# Only network + vuln checks, JSON output
sudo ./linux-security-scan.sh --only network,vuln --format json

# Deep mode (full-fs walk, Trivy/rkhunter/AIDE/Lynis if installed)
sudo ./linux-security-scan.sh --deep
```

Options: `--output-dir`, `--format` (text|json|html|all), `--only`/`--skip`
(groups: hardening, accounts, network, vuln, rootkit, integrity),
`--no-external` (native only), `--deep`. It writes a text log, a JSON report,
and a styled HTML report, and exits non-zero when any HIGH finding is present so
CI/cron can gate on it. Run as root for full coverage.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

This script is provided as-is with no warranties.

## Acknowledgments

- DISA for STIG content
- NIST for SCAP specifications
- OpenSCAP and SCC development teams

## Execution fixes and validation

Scanner paths are honored, including executable paths and paths containing spaces.
Scans enforce `-Timeout`, reject unsupported remote targets, and fail when no reports
are produced. SCC reports are read only from a unique directory under `-OutputPath`;
old SCC sessions are never treated as evidence of a new scan. If your SCC version
ignores its output option, the script fails rather than reusing an earlier report.
OpenSCAP always saves XML for subsequent conversion and treats exit code 2 as a
completed evaluation with failed or unknown rules, not scanner failure.
`-SkipRemediationChecks` is retained for compatibility; OpenSCAP evaluation does
not request remediation. Remote execution is not implemented: run the script on
each target locally. `Success` means scanning completed, not that the host complies.

Run the dependency-free regression checks without installation or elevation:

```powershell
pwsh -NoProfile -File tests/Scan.Tests.ps1
```

These checks parse the full script and exercise isolated functions with mocked
processes and temporary reports. They do not validate Windows elevation, scanner
installation/downloads, real SCC/OpenSCAP runs, or PDF rendering. `All` currently
requests the scanner's native outputs; it does not run every format converter.


### Follow-up review fixes

HTML/PDF conversion uses the configured scanner and enforces the timeout and
exit code. Existing native reports are reused. Converted files are included in
`OutputFiles`; a failed requested conversion marks the scan result `Failed`.
OpenSCAP HTML requests require both nonempty XML and HTML reports. SCC log-only
output is rejected. Standard XCCDF results from either scanner use the same
namespace-aware parser for CSV and vulnerability-manager JSON. Export rejects
empty findings and creates its destination directory when needed.

The regression checks also cover these reporting and export paths with mocked
processes. No Windows elevation, installation, live scanner, or PDF-rendering
validation is implied.
