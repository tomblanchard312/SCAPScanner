# SCAP Scanner PowerShell Tool

A comprehensive PowerShell script for running SCAP compliance scans on Windows systems.

## Overview

This tool provides a PowerShell interface for performing Security Content Automation Protocol (SCAP) scans on local and remote Windows systems. It supports multiple SCAP scanning engines, benchmarks, and reporting formats, making it easy to integrate with existing vulnerability management processes.

## Features

- Support for multiple SCAP scanning engines (SCC and OpenSCAP)
- Automatic installation of scanning tools and content
- Multiple benchmark support (DISA STIGs, NIST 800-53, CIS, etc.)
- Support for custom SCAP content
- Local and remote scanning capabilities
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
                   -TargetHosts "Server01", "Server02" `
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

### Scan Multiple Remote Servers with CIS Benchmark

```powershell
.\SCAP-Scanner.ps1 -ScannerType SCC `
                   -Benchmark CIS `
                   -TargetHosts "Server01", "Server02", "Server03" `
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

## License

This project is licensed under the MIT License. See the LICENSE file for details.

This script is provided as-is with no warranties.

## Acknowledgments

- DISA for STIG content
- NIST for SCAP specifications
- OpenSCAP and SCC development teams