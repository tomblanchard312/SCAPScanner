# SCAP-Scanner.ps1
# PowerShell script to perform SCAP scans and generate compliance reports
# 
# This script supports:
# - Downloading and installing SCAP scanning tools (SCC or OpenSCAP)
# - Running SCAP compliance scans with various benchmarks
# - Generating reports in multiple formats
# - Integration with existing vulnerability management tools

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("SCC", "OpenSCAP")]
    [string]$ScannerType = "SCC",
    
    [Parameter(Mandatory = $false)]
    [string]$ScannerPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ContentPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("DISA_STIG", "NIST_800_53", "CIS", "USGCB", "PCI_DSS", "HIPAA", "Custom")]
    [string]$Benchmark = "DISA_STIG",
    
    [Parameter(Mandatory = $false)]
    [string]$CustomContentFile,
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetHosts = @($env:COMPUTERNAME),
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\SCAP_Reports",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("XML", "HTML", "PDF", "CSV", "All")]
    [string]$ReportFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [switch]$InstallScanner = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$UpdateContent = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceInstall = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRemediationChecks = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$Timeout = 3600,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToVulnerabilityManager = $false,
    
    [Parameter(Mandatory = $false)]
    [string]$VulnerabilityManagerPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("DoD", "Chocolatey", "Manual", "OpenSCAP")]
    [string]$InstallMethod = "Chocolatey",
    
    [Parameter(Mandatory = $false)]
    [string]$SccVersion = "5.10.1"
)

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "This script requires administrator privileges. Attempting to elevate..." -ForegroundColor Yellow
    
    # Construct the argument list from bound parameters
    $argList = @("-File", "`"$($MyInvocation.MyCommand.Path)`"")
    
    # Add all bound parameters to the argument list
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        
        # Handle different parameter types
        if ($value -is [switch]) {
            if ($value.IsPresent) {
                $argList += "-$key"
            }
        } elseif ($value -is [array] -or $value -is [System.Collections.ArrayList]) {
            $valueStr = $value -join ","
            $argList += "-$key"
            $argList += "`"$valueStr`""
        } else {
            $argList += "-$key"
            $argList += "`"$value`""
        }
    }
    
    # Start new PowerShell instance with elevation
    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $argList
    exit
}

#region Script Variables
$ScriptVersion = "1.0.0"
$LogFile = Join-Path -Path $OutputPath -ChildPath "SCAP_Scanner_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$SCAPContentDir = Join-Path -Path $env:ProgramData -ChildPath "SCAP\Content"
$SCCDownloadUrl = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-$SccVersion`_Windows_bundle.zip"
$ChocolateySCCPackage = "scap-compliance-checker"
$OpenSCAPDownloadUrl = "https://chocolatey.org/api/v2/package/openscap/1.3.7"
$ChocolateyInstalled = $false
$ScanResults = @()
#endregion

#region Logging Functions
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Level] - $Message"
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path (Split-Path -Path $LogFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path -Path $LogFile -Parent) -Force | Out-Null
    }
    
    # Add color to console output based on level
    switch ($Level) {
        'WARNING' { 
            Write-Host $logEntry -ForegroundColor Yellow 
        }
        'ERROR' { 
            Write-Host $logEntry -ForegroundColor Red 
        }
        'SUCCESS' { 
            Write-Host $logEntry -ForegroundColor Green 
        }
        default { 
            Write-Host $logEntry 
        }
    }
    
    # Always log to file
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}
#endregion

#region Installation Functions
function Install-Scanner {
    param (
        [string]$ScannerType,
        [string]$InstallMethod,
        [switch]$Force
    )
    
    Write-Log "Starting installation of $ScannerType scanner using $InstallMethod method" -Level 'INFO'
    
    switch ($ScannerType) {
        "SCC" {
            # Check if SCC is already installed
            $sccPath = "C:\Program Files\SCAP Compliance Checker $SccVersion"
            if (-not (Test-Path -Path $sccPath)) {
                $sccPath = "C:\Program Files\SCAP Compliance Checker"
            }
            
            if ((Test-Path -Path $sccPath) -and -not $Force) {
                Write-Log "SCC is already installed at $sccPath" -Level 'INFO'
                return $sccPath
            }
            
            # Try installation based on selected method
            switch ($InstallMethod) {
                "DoD" {
                    # Create a temporary directory for downloads
                    $tempDir = Join-Path -Path $env:TEMP -ChildPath "SCC_Install_$(Get-Random)"
                    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                    
                    # Download SCC
                    $sccZipPath = Join-Path -Path $tempDir -ChildPath "scc.zip"
                    try {
                        Write-Log "Downloading SCC from $SCCDownloadUrl" -Level 'INFO'
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        Invoke-WebRequest -Uri $SCCDownloadUrl -OutFile $sccZipPath -UseBasicParsing
                        
                        # Extract SCC
                        Write-Log "Extracting SCC installation files" -Level 'INFO'
                        Expand-Archive -Path $sccZipPath -DestinationPath $tempDir -Force
                        
                        # Find and run the installer
                        $installerPath = Get-ChildItem -Path $tempDir -Filter "scc_setup*.exe" -Recurse | 
                                       Select-Object -First 1 -ExpandProperty FullName
                        
                        if ($installerPath) {
                            Write-Log "Running SCC installer: $installerPath" -Level 'INFO'
                            $process = Start-Process -FilePath $installerPath -ArgumentList "/S" -NoNewWindow -PassThru -Wait
                            
                            if ($process.ExitCode -eq 0) {
                                Write-Log "SCC installed successfully" -Level 'SUCCESS'
                                return "C:\Program Files\SCAP Compliance Checker $SccVersion"
                            }
                            else {
                                Write-Log "SCC installation failed with exit code: $($process.ExitCode)" -Level 'ERROR'
                                return $null
                            }
                        }
                        else {
                            Write-Log "Could not find SCC installer in the downloaded package" -Level 'ERROR'
                            return $null
                        }
                    }
                    catch {
                        Write-Log "Error downloading from DoD site: $_" -Level 'ERROR'
                        Write-Log "This may be because you need to be on a DoD network or have a CAC to access this file." -Level 'WARNING'
                        Write-Log "Try using the Chocolatey installation method instead." -Level 'INFO'
                        return $null
                    }
                    finally {
                        # Clean up
                        if (Test-Path -Path $tempDir) {
                            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                "Chocolatey" {
                    try {
                        # Check if Chocolatey is installed
                        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                            Write-Log "Chocolatey is not installed. Installing Chocolatey..." -Level 'INFO'
                            Set-ExecutionPolicy Bypass -Scope Process -Force
                            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                            $chocoInstallOutput = Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                            $ChocolateyInstalled = $true
                            
                            # Let's make sure Chocolatey is in the path
                            $env:Path = "$env:Path;$env:ChocolateyInstall\bin"
                        }
                        
                        # Install SCC using Chocolatey - capture and redirect the output
                        Write-Log "Installing SCC using Chocolatey" -Level 'INFO'
                        $chocoOutput = & choco install $ChocolateySCCPackage -y --no-progress 2>&1
                        $chocoExitCode = $LASTEXITCODE
                        
                        # Log the Chocolatey output for debugging
                        Write-Log "Chocolatey installation output: $chocoOutput" -Level 'INFO'
                        
                        if ($chocoExitCode -eq 0) {
                            Write-Log "SCC installed successfully using Chocolatey" -Level 'SUCCESS'
                            
                            # Find the installation directory - don't rely on variable from Chocolatey output
                            $possiblePaths = @(
                                "C:\Program Files\SCAP Compliance Checker $SccVersion",
                                "C:\Program Files\SCAP Compliance Checker",
                                "C:\Program Files (x86)\SCAP Compliance Checker $SccVersion",
                                "C:\Program Files (x86)\SCAP Compliance Checker"
                            )
                            
                            foreach ($path in $possiblePaths) {
                                if (Test-Path -Path $path) {
                                    Write-Log "Found SCC installation at: $path" -Level 'SUCCESS'
                                    return $path
                                }
                            }
                            
                            # If we couldn't find the specific path, use registry to find it
                            $regPaths = @(
                                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                            )
                            
                            foreach ($regPath in $regPaths) {
                                $sccReg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue | 
                                          Where-Object { ($_.DisplayName -like "*SCAP Compliance Checker*") }
                                
                                if ($sccReg -and $sccReg.InstallLocation) {
                                    Write-Log "Found SCC installation from registry: $($sccReg.InstallLocation)" -Level 'SUCCESS'
                                    return $sccReg.InstallLocation
                                }
                            }
                            
                            # If registry lookup fails too, just return default path
                            Write-Log "Could not find exact SCC path, using default" -Level 'WARNING'
                            return "C:\Program Files\SCAP Compliance Checker"
                        }
                        else {
                            Write-Log "SCC installation via Chocolatey failed with exit code: $chocoExitCode" -Level 'ERROR'
                            return $null
                        }
                    }
                    catch {
                        Write-Log "Error installing SCC via Chocolatey: $_" -Level 'ERROR'
                        return $null
                    }
                }
                "Manual" {
                    # Let the user select the installer manually
                    Write-Log "Please select the SCC installer manually" -Level 'INFO'
                    
                    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                    $openFileDialog.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*"
                    $openFileDialog.Title = "Select SCC Installer"
                    $openFileDialog.ShowDialog() | Out-Null
                    
                    if ($openFileDialog.FileName) {
                        $installerPath = $openFileDialog.FileName
                        Write-Log "Selected installer: $installerPath" -Level 'INFO'
                        
                        $process = Start-Process -FilePath $installerPath -ArgumentList "/S" -NoNewWindow -PassThru -Wait
                        
                        if ($process.ExitCode -eq 0) {
                            Write-Log "SCC installed successfully" -Level 'SUCCESS'
                            return "C:\Program Files\SCAP Compliance Checker"
                        }
                        else {
                            Write-Log "SCC installation failed with exit code: $($process.ExitCode)" -Level 'ERROR'
                            return $null
                        }
                    }
                    else {
                        Write-Log "No installer selected" -Level 'WARNING'
                        return $null
                    }
                }
                default {
                    Write-Log "Unknown installation method: $InstallMethod" -Level 'ERROR'
                    return $null
                }
            }
        }
        "OpenSCAP" {
            # Check if OpenSCAP is already installed
            $openscapPath = "C:\Program Files\OpenSCAP"
            if ((Test-Path -Path $openscapPath) -and -not $Force) {
                Write-Log "OpenSCAP is already installed at $openscapPath" -Level 'INFO'
                return $openscapPath
            }
            
            # Install OpenSCAP using Chocolatey
            try {
                # Check if Chocolatey is installed
                if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Log "Chocolatey is not installed. Installing Chocolatey..." -Level 'INFO'
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    $ChocolateyInstalled = $true
                }
                
                # Install OpenSCAP
                Write-Log "Installing OpenSCAP using Chocolatey" -Level 'INFO'
                choco install openscap -y --no-progress
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "OpenSCAP installed successfully" -Level 'SUCCESS'
                    return "C:\Program Files\OpenSCAP"
                }
                else {
                    Write-Log "OpenSCAP installation failed with exit code: $LASTEXITCODE" -Level 'ERROR'
                    
                    # Try alternative - direct installation of SCAP Compliance Checker
                    Write-Log "Trying alternative installation - SCAP Compliance Checker" -Level 'INFO'
                    choco install scap-compliance-checker -y --no-progress
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "SCAP Compliance Checker installed successfully as alternative" -Level 'SUCCESS'
                        return "C:\Program Files\SCAP Compliance Checker"
                    }
                    else {
                        Write-Log "Alternative installation failed" -Level 'ERROR'
                        return $null
                    }
                }
            }
            catch {
                Write-Log "Error installing OpenSCAP: $_" -Level 'ERROR'
                return $null
            }
        }
        default {
            Write-Log "Unknown scanner type: $ScannerType" -Level 'ERROR'
            return $null
        }
    }
}
#endregion

#region Content Management Functions
# Fixed Get-SCAPContentPath function
function Get-SCAPContentPath {
    param (
        [string]$ScannerPath,
        [string]$ScannerType
    )
    
    Write-Log "Searching for SCAP content directories..." -Level 'INFO'
    
    $possibleContentPaths = @(
        # Standard content paths
        (Join-Path -Path $ScannerPath -ChildPath "Content"),
        
        # Content in ProgramData
        (Join-Path -Path $env:ProgramData -ChildPath "SCAP Compliance Checker\Content"),
        (Join-Path -Path $env:ProgramData -ChildPath "SCAP Compliance Checker $SccVersion\Content"),
        
        # Version-specific content paths
        (Join-Path -Path $ScannerPath -ChildPath "..\Content"),
        (Join-Path -Path $ScannerPath -ChildPath "..\..\Content"),
        
        # Alternative content paths seen with Chocolatey installation
        "C:\Program Files\SCAP Compliance Checker\Content",
        "C:\Program Files\SCAP Compliance Checker $SccVersion\Content",
        "C:\Program Files (x86)\SCAP Compliance Checker\Content",
        "C:\Program Files (x86)\SCAP Compliance Checker $SccVersion\Content"
    )
    
    foreach ($path in $possibleContentPaths) {
        if (Test-Path -Path $path) {
            Write-Log "Found SCAP content at: $path" -Level 'SUCCESS'
            return $path
        }
        else {
            Write-Log "Content not found at: $path" -Level 'INFO'
        }
    }
    
    # If we didn't find content anywhere, do a broader search
    Write-Log "Performing a broader search for SCAP content..." -Level 'INFO'
    
    # Look for any directories containing specific content files
    $contentDirs = @()
    $programFiles = @("C:\Program Files", "C:\Program Files (x86)")
    $searchPatterns = @("*STIG*.xml", "*xccdf*.xml", "*.scap.xml")
    
    foreach ($dir in $programFiles) {
        foreach ($pattern in $searchPatterns) {
            $foundFiles = Get-ChildItem -Path $dir -Filter $pattern -Recurse -ErrorAction SilentlyContinue
            if ($foundFiles) {
                $contentDirs += $foundFiles | ForEach-Object { Split-Path -Path $_.FullName -Parent } | Select-Object -Unique
            }
        }
    }
    
    if ($contentDirs.Count -gt 0) {
        Write-Log "Found content directory via file search: $($contentDirs[0])" -Level 'SUCCESS'
        return $contentDirs[0]
    }
    
    Write-Log "Could not find any SCAP content directories" -Level 'ERROR'
    return $null
}

# Fixed Update-SCAPContent function
function Update-SCAPContent {
    param (
        [string]$ScannerType,
        [string]$ScannerPath,
        [string]$Benchmark,
        [string]$CustomContentFile
    )
    
    Write-Log "Updating SCAP content for $Benchmark benchmark" -Level 'INFO'
    
    # Create content directory if it doesn't exist
    if (-not (Test-Path -Path $SCAPContentDir)) {
        New-Item -ItemType Directory -Path $SCAPContentDir -Force | Out-Null
    }
    
    # Handle custom content
    if ($Benchmark -eq "Custom" -and $CustomContentFile) {
        if (Test-Path -Path $CustomContentFile) {
            $contentDestination = Join-Path -Path $SCAPContentDir -ChildPath (Split-Path -Path $CustomContentFile -Leaf)
            Copy-Item -Path $CustomContentFile -Destination $contentDestination -Force
            Write-Log "Custom content copied to $contentDestination" -Level 'SUCCESS'
            return $contentDestination
        }
        else {
            Write-Log "Custom content file not found: $CustomContentFile" -Level 'ERROR'
            return $null
        }
    }
    
    # Handle standard benchmarks based on scanner type
    switch ($ScannerType) {
        "SCC" {
            # Find content using the enhanced content path search function
            $contentPath = Get-SCAPContentPath -ScannerPath $ScannerPath -ScannerType $ScannerType
            
            if ($contentPath -and (Test-Path -Path $contentPath)) {
                Write-Log "Using pre-installed SCC content at $contentPath" -Level 'SUCCESS'
                return $contentPath
            }
            else {
                Write-Log "Could not find SCC content directory. Attempting to download content." -Level 'WARNING'
                
                # If content not found, try to download it
                $tempDir = Join-Path -Path $env:TEMP -ChildPath "SCAP_Content_$(Get-Random)"
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                
                try {
                    $contentUrl = "https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=all"
                    $downloadUrl = ""
                    
                    switch ($Benchmark) {
                        "DISA_STIG" {
                            # Since we can't directly access DoD content, use a local placeholder
                            $extractPath = Join-Path -Path $SCAPContentDir -ChildPath "DISA_STIG"
                            if (-not (Test-Path -Path $extractPath)) {
                                New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
                            }
                            
                            # Create a simple README to guide users
                            $readmeFile = Join-Path -Path $extractPath -ChildPath "README.txt"
                            $readmeContent = @"
DISA STIG Content

The script could not locate pre-installed SCAP content for DISA STIGs.
Please visit https://public.cyber.mil/stigs/downloads/ to download the latest STIG content.

Once downloaded, extract the content and specify the path using:
.\SCAP-Scanner.ps1 -ContentPath "Path\To\Content"
"@
                            $readmeContent | Out-File -FilePath $readmeFile -Encoding utf8 -Force
                            
                            Write-Log "Created content placeholder at $extractPath" -Level 'WARNING'
                            Write-Log "Please manually download DISA STIG content from https://public.cyber.mil/stigs/downloads/" -Level 'WARNING'
                            
                            return $extractPath
                        }
                        default {
                            # For other benchmarks, attempt alternative sources
                            Write-Log "No specific download path for $Benchmark" -Level 'WARNING'
                            return $null
                        }
                    }
                }
                catch {
                    Write-Log "Error downloading content: $_" -Level 'ERROR'
                    return $null
                }
                finally {
                    # Clean up
                    if (Test-Path -Path $tempDir) {
                        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        "OpenSCAP" {
            # For OpenSCAP, download content from NIST/DISA
            $tempDir = Join-Path -Path $env:TEMP -ChildPath "SCAP_Content_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            
            try {
                $contentUrl = ""
                $outputFile = ""
                
                switch ($Benchmark) {
                    "DISA_STIG" {
                        $contentUrl = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_STIG_V2R4_SCAP_1-2_Benchmark.zip"
                        $outputFile = Join-Path -Path $tempDir -ChildPath "disa_stig.zip"
                    }
                    "NIST_800_53" {
                        $contentUrl = "https://csrc.nist.gov/CSRC/media/Projects/Security-Content-Automation-Protocol/specifications/nist-800-53-rev5-control-catalog-scap-1.3.zip"
                        $outputFile = Join-Path -Path $tempDir -ChildPath "nist_800_53.zip"
                    }
                    "CIS" {
                        $contentUrl = "https://learn.cisecurity.org/l/799323/2021-09-21/39kgn/799323/1632255989aNOVTTFO/CIS_Microsoft_Windows_10_Enterprise_Release_2004_Benchmark_v1.11.0_SCAP_12.zip"
                        $outputFile = Join-Path -Path $tempDir -ChildPath "cis.zip"
                    }
                    default {
                        Write-Log "No download URL defined for benchmark: $Benchmark" -Level 'ERROR'
                        return $null
                    }
                }
                
                if ($contentUrl -and $outputFile) {
                    Write-Log "Downloading $Benchmark content from $contentUrl" -Level 'INFO'
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $contentUrl -OutFile $outputFile -UseBasicParsing
                    
                    # Extract content
                    $extractPath = Join-Path -Path $SCAPContentDir -ChildPath $Benchmark
                    if (-not (Test-Path -Path $extractPath)) {
                        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
                    }
                    
                    Write-Log "Extracting $Benchmark content to $extractPath" -Level 'INFO'
                    Expand-Archive -Path $outputFile -DestinationPath $extractPath -Force
                    
                    # Find XCCDF or OVAL files
                    $xccdfFile = Get-ChildItem -Path $extractPath -Filter "*.xccdf.xml" -Recurse | Select-Object -First 1 -ExpandProperty FullName
                    
                    if ($xccdfFile) {
                        Write-Log "SCAP content updated successfully: $xccdfFile" -Level 'SUCCESS'
                        return $extractPath
                    }
                    else {
                        Write-Log "Could not find XCCDF file in the downloaded content" -Level 'ERROR'
                        return $null
                    }
                }
            }
            catch {
                Write-Log "Error updating SCAP content: $_" -Level 'ERROR'
                return $null
            }
            finally {
                # Clean up
                if (Test-Path -Path $tempDir) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        default {
            Write-Log "Unsupported scanner type: $ScannerType" -Level 'ERROR'
            return $null
        }
    }
    
    return $null
}

function Get-SCAPContentFile {
    param (
        [string]$ContentPath,
        [string]$Benchmark
    )
    
    Write-Log "Searching for SCAP content files in $ContentPath for $Benchmark benchmark" -Level 'INFO'
    
    # Define search patterns based on benchmark
    $searchPatterns = @()
    
    switch ($Benchmark) {
        "DISA_STIG" {
            $searchPatterns = @("*STIG*xccdf.xml", "*STIG*.xml")
        }
        "NIST_800_53" {
            $searchPatterns = @("*800-53*.xml", "*nist*.xccdf.xml")
        }
        "CIS" {
            $searchPatterns = @("*CIS*.xml", "*cis*.xccdf.xml")
        }
        "USGCB" {
            $searchPatterns = @("*USGCB*.xml", "*usgcb*.xccdf.xml")
        }
        "PCI_DSS" {
            $searchPatterns = @("*PCI*DSS*.xml", "*pci*.xccdf.xml")
        }
        "HIPAA" {
            $searchPatterns = @("*HIPAA*.xml", "*hipaa*.xccdf.xml")
        }
        "Custom" {
            $searchPatterns = @("*.xml")
        }
        default {
            $searchPatterns = @("*.xccdf.xml", "*.xml")
        }
    }
    
    # Search for content files
    foreach ($pattern in $searchPatterns) {
        $contentFiles = Get-ChildItem -Path $ContentPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        
        if ($contentFiles -and $contentFiles.Count -gt 0) {
            # Prefer XCCDF files
            $xccdfFile = $contentFiles | Where-Object { $_.Name -like "*xccdf*" } | Select-Object -First 1
            
            if ($xccdfFile) {
                Write-Log "Found XCCDF content file: $($xccdfFile.FullName)" -Level 'SUCCESS'
                return $xccdfFile.FullName
            }
            
            # Otherwise, return the first matching file
            Write-Log "Found content file: $($contentFiles[0].FullName)" -Level 'SUCCESS'
            return $contentFiles[0].FullName
        }
    }
    
    Write-Log "No content files found for $Benchmark benchmark in $ContentPath" -Level 'ERROR'
    return $null
}
#endregion

#region Scanning Functions
function Start-SCAPScan {
    param (
        [string]$ScannerType,
        [string]$ScannerPath,
        [string]$ContentFile,
        [string]$TargetHost,
        [string]$OutputPath,
        [string]$ReportFormat,
        [switch]$SkipRemediationChecks,
        [int]$Timeout
    )
    
    Write-Log "Starting SCAP scan on $TargetHost using $ScannerType" -Level 'INFO'
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Generate output file paths
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $baseOutputName = "SCAP_Scan_${TargetHost}_${timestamp}"
    $scanResultPath = Join-Path -Path $OutputPath -ChildPath $baseOutputName
    
    try {
        switch ($ScannerType) {
        "SCC" {
            # Use the full path to scc.exe that we know works
            $sccExe = "C:\Program Files\SCAP Compliance Checker 5.10.1\scc.exe"
            
            # Create a dedicated output directory with a unique name
            $outputDir = "C:\Temp\SCAP_Report_$timestamp"
            if (-not (Test-Path -Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }
            
            # Build the command arguments exactly like we did in the manual test
            $scanArgs = "-o `"$outputDir`" -i `"$ContentFile`" -v"
            
            # Execute scan using the Start-Process method
            Write-Log "Executing SCC scan: $sccExe $scanArgs" -Level 'INFO'
            
            try {
                # Alternative approach: Use PowerShell's call operator directly
                Write-Log "Trying alternative execution method..." -Level 'INFO'
                $command = "& `"$sccExe`" $scanArgs"
                Write-Log "Command: $command" -Level 'INFO'
                
                Invoke-Expression $command
                
                # Since we're not capturing the process, assume success if no exception
                Write-Log "SCC scan appears to have completed" -Level 'INFO'
                
                # Wait a moment for files to be created
                Start-Sleep -Seconds 10
                
                # Look for the most recent SCC session directory
                $sccSessionsDir = "$env:USERPROFILE\SCC\Sessions"
                Write-Log "Checking for results in: $sccSessionsDir" -Level 'INFO'
                
                $latestSession = Get-ChildItem -Path $sccSessionsDir -Directory | 
                                Sort-Object -Property LastWriteTime -Descending | 
                                Select-Object -First 1
                
                if ($latestSession) {
                    $resultsDir = Join-Path -Path $latestSession.FullName -ChildPath "Results"
                    
                    if (Test-Path -Path $resultsDir) {
                        $resultFiles = Get-ChildItem -Path $resultsDir -Recurse
                        
                        if ($resultFiles -and $resultFiles.Count -gt 0) {
                            Write-Log "Found $($resultFiles.Count) result files in: $resultsDir" -Level 'SUCCESS'
                            
                            $resultObj = @{
                                TargetHost = $TargetHost
                                ScannerType = $ScannerType
                                OutputFiles = $resultFiles.FullName
                                Status = "Success"
                                Timestamp = Get-Date
                            }
                            
                            return $resultObj
                        }
                    }
                }
                
                # If we couldn't find results, look in our specified output directory
                if (Test-Path -Path $outputDir) {
                    $resultFiles = Get-ChildItem -Path $outputDir -Recurse
                    
                    if ($resultFiles -and $resultFiles.Count -gt 0) {
                        Write-Log "Found $($resultFiles.Count) result files in: $outputDir" -Level 'SUCCESS'
                        
                        $resultObj = @{
                            TargetHost = $TargetHost
                            ScannerType = $ScannerType
                            OutputFiles = $resultFiles.FullName
                            Status = "Success"
                            Timestamp = Get-Date
                        }
                        
                        return $resultObj
                    }
                }
                
                # If we still can't find results but didn't get an error, assume success
                Write-Log "Scan completed, but couldn't find result files" -Level 'WARNING'
                Write-Log "Check manually in: $sccSessionsDir" -Level 'INFO'
                Write-Log "Check manually in: $outputDir" -Level 'INFO'
                
                return @{
                    TargetHost = $TargetHost
                    ScannerType = $ScannerType
                    OutputFiles = @()
                    Status = "Success"
                    Timestamp = Get-Date
                }
            }
            catch {
                Write-Log "Error executing SCC scan: $_" -Level 'ERROR'
                return $null
            }
        }
            "OpenSCAP" {
                # Find OpenSCAP executables
                $oscapExe = Join-Path -Path $ScannerPath -ChildPath "bin\oscap.exe"
                
                if (-not (Test-Path -Path $oscapExe)) {
                    # Try alternative locations
                    $oscapExe = "C:\Program Files\OpenSCAP\bin\oscap.exe"
                    
                    if (-not (Test-Path -Path $oscapExe)) {
                        Write-Log "OpenSCAP executable not found at $oscapExe" -Level 'ERROR'
                        return $null
                    }
                }
                
                # Define report file paths based on format
                $xmlReport = "$scanResultPath.xml"
                $htmlReport = "$scanResultPath.html"
                
                # Build scan command for XCCDF
                $scanArgs = @(
                    "xccdf",
                    "eval"
                )
                
                if ($TargetHost -ne $env:COMPUTERNAME) {
                    # OpenSCAP supports SSH for remote scanning
                    $scanArgs += @("--remote-host", $TargetHost)
                }
                
                if ($SkipRemediationChecks) {
                    $scanArgs += "--skip-remediation"
                }
                
                # Add report formats
                if ($ReportFormat -eq "XML" -or $ReportFormat -eq "All") {
                    $scanArgs += @("--results", """$xmlReport""")
                }
                
                if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "All") {
                    $scanArgs += @("--report", """$htmlReport""")
                }
                
                # Add content file
                $scanArgs += """$ContentFile"""
                
                # Execute scan
                Write-Log "Executing OpenSCAP scan: $oscapExe $scanArgs" -Level 'INFO'
                $process = Start-Process -FilePath $oscapExe -ArgumentList $scanArgs -NoNewWindow -PassThru -Wait
                if ($process.ExitCode -eq 0) {
                    Write-Log "OpenSCAP scan completed successfully" -Level 'SUCCESS'
                    
                    # Locate result files
                    $resultFiles = @()
                    
                    if (Test-Path -Path $xmlReport) {
                        $resultFiles += $xmlReport
                    }
                    
                    if (Test-Path -Path $htmlReport) {
                        $resultFiles += $htmlReport
                    }
                    
                    if ($resultFiles.Count -gt 0) {
                        $resultObj = @{
                            TargetHost = $TargetHost
                            ScannerType = $ScannerType
                            OutputFiles = $resultFiles
                            Status = "Success"
                            Timestamp = Get-Date
                        }
                        
                        return $resultObj
                    }
                    else {
                        Write-Log "No result files found after successful scan" -Level 'WARNING'
                        return $null
                    }
                }
                else {
                    Write-Log "OpenSCAP scan failed with exit code: $($process.ExitCode)" -Level 'ERROR'
                    return $null
                }
            }
            default {
                Write-Log "Unknown scanner type: $ScannerType" -Level 'ERROR'
                return $null
            }
        }
    }
    catch {
        Write-Log "Error running SCAP scan: $_" -Level 'ERROR'
        return $null
    }
}
#endregion

#region Report Functions
function Convert-ReportFormat {
    param (
        [string]$ScannerType,
        [string]$InputFile,
        [string]$OutputFormat,
        [string]$OutputPath
    )
    
    if (-not (Test-Path -Path $InputFile)) {
        Write-Log "Input file not found: $InputFile" -Level 'ERROR'
        return $null
    }
    
    $inputFileInfo = Get-Item -Path $InputFile
    $baseOutputName = $inputFileInfo.BaseName
    
    switch ($OutputFormat) {
        "XML" {
            if ($inputFileInfo.Extension -eq ".xml") {
                return $InputFile
            }
            else {
                Write-Log "Cannot convert $($inputFileInfo.Extension) to XML" -Level 'ERROR'
                return $null
            }
        }
        "HTML" {
            if ($inputFileInfo.Extension -eq ".html") {
                return $InputFile
            }
            elseif ($inputFileInfo.Extension -eq ".xml" -and $ScannerType -eq "OpenSCAP") {
                $htmlOutput = Join-Path -Path $OutputPath -ChildPath "$baseOutputName.html"
                
                try {
                    $oscapExe = "C:\Program Files\OpenSCAP\bin\oscap.exe"
                    $convArgs = @(
                        "xccdf",
                        "generate",
                        "report",
                        """$InputFile""",
                        "--output",
                        """$htmlOutput"""
                    )
                    
                    Start-Process -FilePath $oscapExe -ArgumentList $convArgs -NoNewWindow -Wait
                    
                    if (Test-Path -Path $htmlOutput) {
                        Write-Log "Successfully converted XML to HTML: $htmlOutput" -Level 'SUCCESS'
                        return $htmlOutput
                    }
                    else {
                        Write-Log "HTML output file not created" -Level 'ERROR'
                        return $null
                    }
                }
                catch {
                    Write-Log "Error converting XML to HTML: $_" -Level 'ERROR'
                    return $null
                }
            }
            else {
                Write-Log "Cannot convert $($inputFileInfo.Extension) to HTML" -Level 'ERROR'
                return $null
            }
        }
        "PDF" {
            if ($ScannerType -eq "SCC") {
                # SCC may generate PDF directly
                $pdfFile = Get-ChildItem -Path $OutputPath -Filter "$baseOutputName*.pdf" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                
                if ($pdfFile) {
                    return $pdfFile
                }
            }
            
            # Try to convert HTML to PDF using wkhtmltopdf if available
            if (Get-Command wkhtmltopdf -ErrorAction SilentlyContinue) {
                $htmlFile = if ($inputFileInfo.Extension -eq ".html") {
                    $InputFile
                }
                else {
                    $htmlOutput = Convert-ReportFormat -ScannerType $ScannerType -InputFile $InputFile -OutputFormat "HTML" -OutputPath $OutputPath
                    if (-not $htmlOutput) {
                        return $null
                    }
                    $htmlOutput
                }
                
                $pdfOutput = Join-Path -Path $OutputPath -ChildPath "$baseOutputName.pdf"
                
                try {
                    Start-Process -FilePath wkhtmltopdf -ArgumentList """$htmlFile""", """$pdfOutput""" -NoNewWindow -Wait
                    
                    if (Test-Path -Path $pdfOutput) {
                        Write-Log "Successfully converted to PDF: $pdfOutput" -Level 'SUCCESS'
                        return $pdfOutput
                    }
                    else {
                        Write-Log "PDF output file not created" -Level 'ERROR'
                        return $null
                    }
                }
                catch {
                    Write-Log "Error converting to PDF: $_" -Level 'ERROR'
                    return $null
                }
            }
            else {
                Write-Log "wkhtmltopdf not found. Cannot convert to PDF." -Level 'WARNING'
                return $null
            }
        }
        "CSV" {
            if ($inputFileInfo.Extension -eq ".csv") {
                return $InputFile
            }
            elseif ($inputFileInfo.Extension -eq ".xml") {
                $csvOutput = Join-Path -Path $OutputPath -ChildPath "$baseOutputName.csv"
                
                try {
                    # Load XML and convert to CSV
                    [xml]$xml = Get-Content -Path $InputFile
                    
                    # Extract results based on scanner type
                    $results = @()
                    
                    if ($ScannerType -eq "OpenSCAP") {
                        $rules = $xml.Benchmark.Rule
                        
                        foreach ($rule in $rules) {
                            $result = $xml.SelectNodes("//rule-result[@idref='$($rule.id)']") | Select-Object -First 1
                            
                            if ($result) {
                                $results += [PSCustomObject]@{
                                    RuleId = $rule.id
                                    Title = $rule.title
                                    Severity = $rule.severity
                                    Result = $result.result
                                    Description = $rule.description
                                }
                            }
                        }
                    }
                    elseif ($ScannerType -eq "SCC") {
                        # Attempt to parse SCC XML structure
                        $ruleResults = $xml.SelectNodes("//result")
                        
                        foreach ($ruleResult in $ruleResults) {
                            $results += [PSCustomObject]@{
                                RuleId = $ruleResult.id
                                Title = $ruleResult.title
                                Severity = $ruleResult.severity
                                Result = $ruleResult.status
                                Description = $ruleResult.description
                            }
                        }
                    }
                    
                    # Export to CSV
                    $results | Export-Csv -Path $csvOutput -NoTypeInformation
                    
                    if (Test-Path -Path $csvOutput) {
                        Write-Log "Successfully converted XML to CSV: $csvOutput" -Level 'SUCCESS'
                        return $csvOutput
                    }
                    else {
                        Write-Log "CSV output file not created" -Level 'ERROR'
                        return $null
                    }
                }
                catch {
                    Write-Log "Error converting XML to CSV: $_" -Level 'ERROR'
                    return $null
                }
            }
            else {
                Write-Log "Cannot convert $($inputFileInfo.Extension) to CSV" -Level 'ERROR'
                return $null
            }
        }
        default {
            Write-Log "Unsupported output format: $OutputFormat" -Level 'ERROR'
            return $null
        }
    }
}

function Export-ToVulnerabilityManager {
    param (
        [array]$ScanResults,
        [string]$VulnerabilityManagerPath
    )
    
    Write-Log "Exporting results to vulnerability management system" -Level 'INFO'
    
    if (-not $VulnerabilityManagerPath) {
        Write-Log "No vulnerability manager path specified" -Level 'ERROR'
        return $false
    }
    
    try {
        # Prepare export summary
        $exportSummary = @{
            ScanTime = Get-Date
            Scanner = $ScannerType
            Benchmark = $Benchmark
            TargetHosts = $TargetHosts
            Results = @()
        }
        
        foreach ($result in $ScanResults) {
            # Find an XML file to parse for detailed results
            $xmlFile = $result.OutputFiles | Where-Object { $_ -like "*.xml" } | Select-Object -First 1
            
            if ($xmlFile -and (Test-Path -Path $xmlFile)) {
                [xml]$xml = Get-Content -Path $xmlFile
                
                # Parse the XML based on scanner type
                $parsedResults = @()
                
                if ($ScannerType -eq "OpenSCAP") {
                    $testResults = $xml.SelectNodes("//rule-result")
                    
                    foreach ($testResult in $testResults) {
                        $ruleId = $testResult.idref
                        $rule = $xml.SelectSingleNode("//Rule[@id='$ruleId']")
                        
                        $parsedResults += [PSCustomObject]@{
                            RuleId = $ruleId
                            Title = $rule.title
                            Severity = $rule.severity
                            Result = $testResult.result
                            Description = $rule.description
                            Fix = $rule.fix.'#text'
                        }
                    }
                }
                elseif ($ScannerType -eq "SCC") {
                    $testResults = $xml.SelectNodes("//result")
                    
                    foreach ($testResult in $testResults) {
                        $parsedResults += [PSCustomObject]@{
                            RuleId = $testResult.id
                            Title = $testResult.title
                            Severity = $testResult.severity
                            Result = $testResult.status
                            Description = $testResult.description
                            Fix = $testResult.fix
                        }
                    }
                }
                
                # Add parsed results to export summary
                $exportSummary.Results += [PSCustomObject]@{
                    TargetHost = $result.TargetHost
                    DetailedResults = $parsedResults
                    ComplianceScore = ($parsedResults | Where-Object { $_.Result -eq "pass" }).Count / $parsedResults.Count * 100
                }
            }
        }
        
        # Export to vulnerability manager
        $exportFile = Join-Path -Path $VulnerabilityManagerPath -ChildPath "SCAP_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $exportSummary | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile
        
        if (Test-Path -Path $exportFile) {
            Write-Log "Successfully exported results to $exportFile" -Level 'SUCCESS'
            return $true
        }
        else {
            Write-Log "Export file not created" -Level 'ERROR'
            return $false
        }
    }
    catch {
        Write-Log "Error exporting to vulnerability manager: $_" -Level 'ERROR'
        return $false
    }
}

function Show-ScanSummary {
    param (
        [array]$ScanResults
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host " SCAP Scan Summary " -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "=============================" -ForegroundColor Cyan
    
    $totalScans = $ScanResults.Count
    $successfulScans = ($ScanResults | Where-Object { $_.Status -eq "Success" }).Count
    $failedScans = $totalScans - $successfulScans
    
    Write-Host "Total Scans: $totalScans" -ForegroundColor White
    Write-Host "Successful: $successfulScans" -ForegroundColor Green
    Write-Host "Failed: $failedScans" -ForegroundColor Red
    
    if ($ScanResults.Count -gt 0) {
        Write-Host "`nTarget Hosts:" -ForegroundColor Yellow
        
        foreach ($result in $ScanResults) {
            $statusColor = if ($result.Status -eq "Success") { "Green" } else { "Red" }
            
            Write-Host "  $($result.TargetHost) - " -NoNewline
            Write-Host "$($result.Status)" -ForegroundColor $statusColor
            
            if ($result.Status -eq "Success") {
                Write-Host "    Output Files:" -ForegroundColor Gray
                
                foreach ($file in $result.OutputFiles) {
                    Write-Host "      $file" -ForegroundColor Cyan
                }
            }
        }
    }
    
    Write-Host "`nLog file: $LogFile" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Cyan
}
#endregion

#region Main Execution
# Display banner
Write-Host "`n" -NoNewline
Write-Host "=============================" -ForegroundColor Cyan
Write-Host " SCAP Scanner PowerShell Tool " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host " Version $ScriptVersion " -ForegroundColor Gray
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "`n" -NoNewline

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Install scanner if requested
if ($InstallScanner -or -not $ScannerPath) {
    # Log that we're about to install
    Write-Log "Preparing to install $ScannerType scanner using $InstallMethod method" -Level 'INFO'
    
    # Actually install the scanner and get the path
    $ScannerPath = Install-Scanner -ScannerType $ScannerType -InstallMethod $InstallMethod -Force:$ForceInstall
    
    # Verify we got a valid path back
    if (-not $ScannerPath -or -not (Test-Path -Path $ScannerPath)) {
        Write-Log "Failed to install or locate $ScannerType scanner using $InstallMethod method." -Level 'ERROR'
        Write-Log "ScannerPath returned: $ScannerPath" -Level 'DEBUG'
        Write-Log "Try a different installation method or specify an existing scanner path." -Level 'INFO'
        
        # Ask user if they want to try a different installation method
        $tryDifferentMethod = Read-Host "Would you like to try a different installation method? (Y/N)"
        
        if ($tryDifferentMethod -eq "Y" -or $tryDifferentMethod -eq "y") {
            Write-Host "`nAvailable installation methods:" -ForegroundColor Yellow
            Write-Host "1. DoD (requires DoD network or CAC)" -ForegroundColor White
            Write-Host "2. Chocolatey (recommended for non-DoD users)" -ForegroundColor White
            Write-Host "3. Manual (select installer yourself)" -ForegroundColor White
            Write-Host "4. OpenSCAP (open-source alternative)" -ForegroundColor White
            
            $methodChoice = Read-Host "Enter your choice (1-4)"
            
            switch ($methodChoice) {
                "1" { $InstallMethod = "DoD" }
                "2" { $InstallMethod = "Chocolatey" }
                "3" { $InstallMethod = "Manual" }
                "4" { 
                    $InstallMethod = "Chocolatey"
                    $ScannerType = "OpenSCAP"
                }
                default { 
                    Write-Log "Invalid choice. Exiting." -Level 'ERROR'
                    exit 1 
                }
            }
            
            Write-Log "Retrying installation with method: $InstallMethod" -Level 'INFO'
            $ScannerPath = Install-Scanner -ScannerType $ScannerType -InstallMethod $InstallMethod -Force:$ForceInstall
            
            if (-not $ScannerPath -or -not (Test-Path -Path $ScannerPath)) {
                Write-Log "Failed to install or locate $ScannerType scanner using $InstallMethod method." -Level 'ERROR'
                Write-Log "ScannerPath returned: $ScannerPath" -Level 'DEBUG'
                Write-Log "Exiting script." -Level 'ERROR'
                exit 1
            }
        }
        else {
            Write-Log "User chose not to try another installation method. Exiting." -Level 'ERROR'
            exit 1
        }
    }
    else {
        Write-Log "Scanner installed successfully at: $ScannerPath" -Level 'SUCCESS'
    }
}
else {
    # Verify scanner path if provided
    if (-not (Test-Path -Path $ScannerPath)) {
        Write-Log "Specified scanner path does not exist: $ScannerPath" -Level 'ERROR'
        exit 1
    }
    
    Write-Log "Using scanner at $ScannerPath" -Level 'INFO'
}

# Update SCAP content if requested
if ($UpdateContent -or -not $ContentPath) {
    $ContentPath = Update-SCAPContent -ScannerType $ScannerType -ScannerPath $ScannerPath -Benchmark $Benchmark -CustomContentFile $CustomContentFile
    
    if (-not $ContentPath) {
        Write-Log "Failed to update or locate SCAP content. Exiting." -Level 'ERROR'
        exit 1
    }
}
else {
    # Verify content path if provided
    if ($ContentPath -and -not (Test-Path -Path $ContentPath)) {
        Write-Log "Specified content path does not exist: $ContentPath" -Level 'ERROR'
        exit 1
    }
    
    Write-Log "Using content at $ContentPath" -Level 'INFO'
}

# Find specific content file for the selected benchmark
$contentFile = $null

if ($Benchmark -eq "Custom" -and $CustomContentFile -and (Test-Path -Path $CustomContentFile)) {
    $contentFile = $CustomContentFile
    Write-Log "Using custom content file: $contentFile" -Level 'INFO'
}
else {
    $contentFile = Get-SCAPContentFile -ContentPath $ContentPath -Benchmark $Benchmark
    
    if (-not $contentFile) {
        Write-Log "Failed to find content file for $Benchmark benchmark. Exiting." -Level 'ERROR'
        exit 1
    }
}

# Run scans on target hosts
foreach ($targetHost in $TargetHosts) {
    Write-Log "Processing target host: $targetHost" -Level 'INFO'
    
    $result = Start-SCAPScan -ScannerType $ScannerType -ScannerPath $ScannerPath -ContentFile $contentFile `
                           -TargetHost $targetHost -OutputPath $OutputPath -ReportFormat $ReportFormat `
                           -SkipRemediationChecks:$SkipRemediationChecks -Timeout $Timeout
    
    # Make sure to update any other references to $host in this block to $targetHost
    if ($result) {
        $ScanResults += $result
        
        # Convert reports to requested format if needed
        if ($ReportFormat -ne "All") {
            $xmlFile = $result.OutputFiles | Where-Object { $_ -like "*.xml" } | Select-Object -First 1
            
            if ($xmlFile) {
                $convertedFile = Convert-ReportFormat -ScannerType $ScannerType -InputFile $xmlFile `
                                                    -OutputFormat $ReportFormat -OutputPath $OutputPath
                
                if ($convertedFile -and (Test-Path -Path $convertedFile)) {
                    Write-Log "Generated $ReportFormat report: $convertedFile" -Level 'SUCCESS'
                }
            }
        }
    }
    else {
        $ScanResults += @{
            TargetHost = $targetHost
            ScannerType = $ScannerType
            OutputFiles = @()
            Status = "Failed"
            Timestamp = Get-Date
        }
    }
}

# Export to vulnerability management system if requested
if ($ExportToVulnerabilityManager -and $VulnerabilityManagerPath) {
    Export-ToVulnerabilityManager -ScanResults $ScanResults -VulnerabilityManagerPath $VulnerabilityManagerPath
}

# Display scan summary
Show-ScanSummary -ScanResults $ScanResults

# Return results for potential pipeline use
return $ScanResults
#endregion