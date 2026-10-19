$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../SCAP-Scanner.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
# Load functions only: never execute startup, elevation, or installation.
foreach ($name in @('Get-ScannerExecutable', 'Get-XccdfResults', 'Start-SCAPScan', 'Convert-ReportFormat', 'Export-ToVulnerabilityManager', 'Complete-ScanReports')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    Invoke-Expression $definition.Extent.Text
}
function Write-Log { param($Message, $Level) }
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
$script:launches = 0
$script:exitCode = 0
$script:completed = $true
$script:makeReport = $true
$script:reportName = 'result.xml'
$script:stopped = $false
function wkhtmltopdf {}
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$NoNewWindow, [switch]$PassThru, $ErrorAction)
    $script:launches++
    $script:exe = $FilePath
    $script:arguments = $ArgumentList
    if ($script:makeReport) {
        if ($ArgumentList -is [array]) {
            $option = if ($ArgumentList -contains '--results') { '--results' } else { '--output' }
            $index = [array]::IndexOf($ArgumentList, $option)
            $destination = if ($FilePath -eq 'wkhtmltopdf') { $ArgumentList[-1] } else { $ArgumentList[$index + 1] }
            Set-Content -LiteralPath $destination.Trim('"') -Value '<TestResult/>'
        } else {
            $reportDir = [regex]::Match($ArgumentList, '-o "([^"]+)"').Groups[1].Value
            Set-Content -LiteralPath (Join-Path $reportDir $script:reportName) -Value '<TestResult/>'
        }
    }
    $process = [pscustomobject]@{ ExitCode = $script:exitCode; Id = 12345 }
    $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $script:wait = $Milliseconds; return $script:completed }
    return $process
}
function Stop-Process { param($Id, [switch]$Force, $ErrorAction) $script:stopped = $true }
try {
    $scanner = Join-Path $root 'scanner with spaces.exe'
    Set-Content $scanner ''
    $params = @{
        ScannerType = 'SCC'; ScannerPath = $scanner; ContentFile = 'content with spaces.xml'
        TargetHost = 'localhost'; OutputPath = $root; ReportFormat = 'CSV'; Timeout = 3
    }
    $result = Start-SCAPScan @params
    Assert ($result.Status -eq 'Success') 'SCC report must succeed'
    Assert ($script:exe -eq $scanner) 'Custom executable must be used'
    Assert ($script:wait -eq 3000) 'Timeout must be enforced in milliseconds'
    Assert (@($result.OutputFiles).Count -eq 1) 'Only files from this scan must be returned'
    $script:reportName = 'scanner.log'
    Assert ($null -eq (Start-SCAPScan @params)) 'SCC log file alone cannot establish scan success'
    $script:reportName = 'result.xml'
    $script:makeReport = $false
    Assert ($null -eq (Start-SCAPScan @params)) 'Old reports cannot establish success'
    $script:makeReport = $true
    $script:exitCode = 1
    Assert ($null -eq (Start-SCAPScan @params)) 'SCC nonzero exit must fail'
    $script:completed = $false
    Assert ($null -eq (Start-SCAPScan @params)) 'Timeout must fail'
    Assert $script:stopped 'Timed out scanner must be stopped'
    $before = $script:launches
    $params.TargetHost = 'remote.example'
    Assert ($null -eq (Start-SCAPScan @params)) 'Unsupported remote scan must fail'
    Assert ($script:launches -eq $before) 'Remote target must never launch a local scan'
    $params.TargetHost = 'localhost'
    $params.ScannerType = 'OpenSCAP'
    $script:completed = $true
    $script:exitCode = 2
    $result = Start-SCAPScan @params
    Assert ($result.Status -eq 'Success') 'OpenSCAP findings exit code must preserve results'
    Assert ($script:arguments -contains '--results') 'CSV/PDF workflows need XML results'
    Assert ($script:arguments -notcontains '--skip-remediation') 'Unsupported option must not be passed'
    $params.ReportFormat = 'HTML'
    Assert ($null -eq (Start-SCAPScan @params)) 'Missing requested HTML must fail scan'
    $params.ReportFormat = 'CSV'
    $script:exitCode = 1
    Assert ($null -eq (Start-SCAPScan @params)) 'OpenSCAP execution error must fail'
    $converter = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Convert-ReportFormat'
    }, $true)
    Invoke-Expression $converter.Extent.Text
    $xml = Join-Path $root 'xccdf.xml'
    Set-Content $xml @'
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <Group id="group"><Rule id="rule1" severity="high"><title>Nested rule</title><description>Check</description></Rule></Group>
  <TestResult id="test"><rule-result idref="rule1"><result>fail</result></rule-result></TestResult>
</Benchmark>
'@
    $csv = Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat CSV -OutputPath $root
    $rows = @(Import-Csv $csv)
    Assert ($rows.Count -eq 1 -and $rows[0].Title -eq 'Nested rule' -and $rows[0].Result -eq 'fail') 'Namespaced grouped XCCDF rules must export'
    $sccCsv = Convert-ReportFormat -ScannerType SCC -InputFile $xml -OutputFormat CSV -OutputPath $root
    Assert (@(Import-Csv $sccCsv).Count -eq 1) 'SCC XCCDF must use the same namespaced parser'
    $ScannerType = 'OpenSCAP'
    $exportDir = Join-Path $root 'new export directory'
    $scan = @{ TargetHost = 'localhost'; OutputFiles = @($xml); Status = 'Success' }
    Assert (Export-ToVulnerabilityManager -ScanResults @($scan) -VulnerabilityManagerPath $exportDir) 'Export must parse namespaced XCCDF and create destination'
    $exportFile = Get-ChildItem $exportDir -Filter '*.json'
    $export = Get-Content $exportFile.FullName -Raw | ConvertFrom-Json
    Assert ($export.Results[0].DetailedResults[0].RuleId -eq 'rule1') 'Export must preserve rule findings'
    Assert ($export.Results[0].ComplianceScore -eq 0) 'Failed rule must yield zero compliance'
    $script:exitCode = 0
    $html = Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat HTML -OutputPath $root -ScannerPath $scanner -Timeout 3
    Assert ($html -and $script:exe -eq $scanner) 'HTML conversion must honor scanner path'
    $pdf = Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat PDF -OutputPath $root -ScannerPath $scanner -Timeout 3
    Assert ($pdf -and $script:exe -eq 'wkhtmltopdf') 'PDF conversion must run with the configured scanner for its HTML step'
    $script:exitCode = 1
    Assert ($null -eq (Convert-ReportFormat -ScannerType OpenSCAP -InputFile $html -OutputFormat PDF -OutputPath $root -ScannerPath $scanner)) 'Failed PDF converter must reject stale output'
    $script:exitCode = 0
    $before = $script:launches
    $scanWithHtml = @{ TargetHost = 'localhost'; ScannerType = 'SCC'; OutputFiles = @($xml, $html); Status = 'Success' }
    Complete-ScanReports -ScanResult $scanWithHtml -ReportFormat HTML -OutputPath $root -ScannerPath $scanner -Timeout 3
    Assert ($script:launches -eq $before -and $scanWithHtml.Status -eq 'Success') 'Existing native HTML must not be regenerated'
    $scanNeedsHtml = @{ TargetHost = 'localhost'; ScannerType = 'OpenSCAP'; OutputFiles = @($xml); Status = 'Success' }
    Complete-ScanReports -ScanResult $scanNeedsHtml -ReportFormat HTML -OutputPath $root -ScannerPath $scanner -Timeout 3
    Assert ($scanNeedsHtml.OutputFiles -contains $html) 'Converted report must be included in scan results'
    $script:exitCode = 1
    $scanNeedsHtml.OutputFiles = @($xml)
    Complete-ScanReports -ScanResult $scanNeedsHtml -ReportFormat HTML -OutputPath $root -ScannerPath $scanner -Timeout 3
    Assert ($scanNeedsHtml.Status -eq 'Failed') 'Failed conversion must mark requested report workflow as failed'
    $script:exitCode = 1
    Assert ($null -eq (Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat HTML -OutputPath $root -ScannerPath $scanner)) 'Conversion exit failure must reject an existing output'
    $script:completed = $false
    $script:stopped = $false
    Assert ($null -eq (Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat HTML -OutputPath $root -ScannerPath $scanner -Timeout 3)) 'Conversion timeout must fail'
    Assert $script:stopped 'Timed out converter must be stopped'
    $directoryScanner = Join-Path $root 'installation/bin'
    New-Item -ItemType Directory $directoryScanner -Force | Out-Null
    $binScanner = Join-Path $directoryScanner 'oscap.exe'
    Set-Content $binScanner ''
    Assert ((Get-ScannerExecutable OpenSCAP (Split-Path $directoryScanner)) -eq $binScanner) 'Scanner bin directory must resolve'
    Set-Content $xml '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>'
    Assert ($null -eq (Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat CSV -OutputPath $root)) 'Empty results cannot establish conversion success'
    Assert (-not (Export-ToVulnerabilityManager -ScanResults @($scan) -VulnerabilityManagerPath $exportDir)) 'Empty XCCDF must fail export without division by zero'
    Write-Host 'All scan regression checks passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
