$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../SCAP-Scanner.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
# Load only the function under test: never elevate, install, or scan this host.
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-SCAPScan'
}, $true)
Invoke-Expression $function.Extent.Text
function Write-Log { param($Message, $Level) }
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
$script:launches = 0
$script:exitCode = 0
$script:completed = $true
$script:makeReport = $true
$script:stopped = $false
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$NoNewWindow, [switch]$PassThru, $ErrorAction)
    $script:launches++
    $script:exe = $FilePath
    $script:arguments = $ArgumentList
    if ($script:makeReport) {
        if ($ArgumentList -is [array]) {
            $index = [array]::IndexOf($ArgumentList, '--results')
            Set-Content -LiteralPath $ArgumentList[$index + 1].Trim('"') -Value '<TestResult/>'
        } else {
            $reportDir = [regex]::Match($ArgumentList, '-o "([^"]+)"').Groups[1].Value
            Set-Content -LiteralPath (Join-Path $reportDir 'result.xml') -Value '<TestResult/>'
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
    Set-Content $xml '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>'
    Assert ($null -eq (Convert-ReportFormat -ScannerType OpenSCAP -InputFile $xml -OutputFormat CSV -OutputPath $root)) 'Empty results cannot establish conversion success'
    Write-Host 'All scan regression checks passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
