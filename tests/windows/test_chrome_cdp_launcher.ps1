<#
.SYNOPSIS
Validates the Chrome CDP launcher security contract without launching Chrome,
SSH, Python, or any network service.

.DESCRIPTION
The launcher is parsed as PowerShell AST data.  These checks keep its sealed
gateway Chrome arguments and SSH host-verification rules from drifting while
remaining safe for an offline Windows GitHub Actions runner.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-True {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Get-ParsedLauncher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $Source,
        [ref]$tokens,
        [ref]$errors
    )
    return [pscustomobject]@{
        Ast = $ast
        Errors = @($errors)
    }
}

function Get-FunctionAst {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Ast,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $matches = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true))
    Assert-True -Condition ($matches.Count -eq 1) -Message "expected one $Name function"
    return $matches[0]
}

function Get-StringValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Ast
    )

    return @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
    }, $true) | ForEach-Object { $_.Value })
}

function Get-GatewayChromeArgumentValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Ast
    )

    $assignments = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$chromeArguments' -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::PlusEquals -and
        $node.Extent.Text.Contains('--host-resolver-rules')
    }, $true))
    Assert-True -Condition ($assignments.Count -eq 1) -Message 'expected one sealed-gateway Chrome argument group'
    return Get-StringValues -Ast $assignments[0].Right
}

function Get-LauncherOutputObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Ast
    )

    $outputPipelines = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.PipelineAst] -and
        $node.Extent.Text.Contains('ConvertTo-Json -Compress | Write-Output')
    }, $true))
    Assert-True -Condition ($outputPipelines.Count -eq 3) -Message 'expected one JSON output pipeline for each launcher mode'

    $outputObjects = @($outputPipelines | ForEach-Object {
        $objects = @($_.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.HashtableAst]
        }, $true))
        Assert-True -Condition ($objects.Count -eq 1) -Message 'expected one JSON output object per launcher mode'
        $objects[0]
    })
    return $outputObjects
}

function Get-LauncherContractFailures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $parsed = Get-ParsedLauncher -Source $Source
    $failures = [System.Collections.Generic.List[string]]::new()
    if ($parsed.Errors.Count -ne 0) {
        $failures.Add('launcher contains PowerShell parser errors')
        return $failures.ToArray()
    }

    $gatewayValues = Get-GatewayChromeArgumentValues -Ast $parsed.Ast
    $hostResolver = '"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"'
    if (@($gatewayValues | Where-Object { $_ -eq $hostResolver }).Count -ne 1) {
        $failures.Add('gateway Chrome arguments must have one quoted host-resolver value')
    }
    if (@($gatewayValues | Where-Object { $_.Contains([string][char]96) }).Count -ne 0) {
        $failures.Add('gateway Chrome arguments must not pass a literal backtick')
    }

    $requiredGatewayValues = @(
        '--proxy-server=http://127.0.0.1:$gatewayProxyPort',
        '--proxy-bypass-list=<-loopback>',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--disable-quic',
        '--dns-prefetch-disable',
        '--disable-extensions'
    )
    foreach ($value in $requiredGatewayValues) {
        if (@($gatewayValues | Where-Object { $_ -eq $value }).Count -ne 1) {
            $failures.Add("gateway Chrome arguments must contain exactly one $value")
        }
    }
    foreach ($forbidden in @(
        '--no-proxy-server',
        '--proxy-auto-detect',
        '--proxy-pac-url',
        '--load-extension',
        '--disable-extensions-except',
        '--enable-extensions'
    )) {
        if (@($gatewayValues | Where-Object { $_ -eq $forbidden }).Count -ne 0) {
            $failures.Add("gateway Chrome arguments must not contain $forbidden")
        }
    }

    $sealedSwitches = Get-FunctionAst -Ast $parsed.Ast -Name 'Assert-SealedChromeSwitches'
    $sealedText = $sealedSwitches.Extent.Text
    foreach ($requiredCheck in @(
        'Get-ChromeSwitchCount',
        'Test-ChromeExactSwitchValue',
        '--proxy-server',
        '--proxy-bypass-list',
        '--host-resolver-rules',
        '--force-webrtc-ip-handling-policy',
        'disable_non_proxied_udp',
        '--disable-extensions',
        '--no-proxy-server',
        '--proxy-auto-detect',
        '--proxy-pac-url',
        '--load-extension',
        '--disable-extensions-except',
        '--enable-extensions'
    )) {
        if (-not $sealedText.Contains($requiredCheck)) {
            $failures.Add("sealed Chrome switch verification is missing $requiredCheck")
        }
    }

    $chromeReuse = Get-FunctionAst -Ast $parsed.Ast -Name 'Assert-DedicatedChromeProcess'
    $chromeReuseText = $chromeReuse.Extent.Text
    foreach ($requiredCheck in @(
        'Test-DedicatedChromeProcessCommand',
        '-ProxyPort $ProxyPort'
    )) {
        if (-not $chromeReuseText.Contains($requiredCheck)) {
            $failures.Add("Chrome session reuse delegation is missing $requiredCheck")
        }
    }

    $chromeCommand = Get-FunctionAst -Ast $parsed.Ast -Name 'Test-DedicatedChromeProcessCommand'
    $chromeCommandText = $chromeCommand.Extent.Text
    foreach ($requiredCheck in @(
        'Get-ChromeSwitchCount',
        'Test-ChromeExactSwitchValue',
        '--remote-debugging-address',
        '--remote-debugging-port',
        '--user-data-dir',
        'Assert-SealedChromeSwitches'
    )) {
        if (-not $chromeCommandText.Contains($requiredCheck)) {
            $failures.Add("Chrome session reuse verification is missing $requiredCheck")
        }
    }

    foreach ($functionName in @(
        'Start-LoopbackSshTunnel',
        'Test-RemoteLoopbackCdpTunnel',
        'Test-RemoteGatewayStatusTunnel'
    )) {
        $sshFunction = Get-FunctionAst -Ast $parsed.Ast -Name $functionName
        if (-not $sshFunction.Extent.Text.Contains("'StrictHostKeyChecking=yes'")) {
            $failures.Add("$functionName must require StrictHostKeyChecking=yes")
        }
        if ($sshFunction.Extent.Text.Contains('StrictHostKeyChecking=no')) {
            $failures.Add("$functionName must not disable SSH host verification")
        }
    }

    $outputObjects = @(Get-LauncherOutputObjects -Ast $parsed.Ast)
    $startObjects = @($outputObjects | Where-Object {
        @($_.KeyValuePairs | ForEach-Object { $_.Item1.Value }) -contains 'chrome_started_at'
    })
    Assert-True -Condition ($startObjects.Count -eq 1) -Message 'expected one start-mode JSON output object'
    $outputFields = @($startObjects[0].KeyValuePairs | ForEach-Object { $_.Item1.Value })
    foreach ($requiredField in @('chrome_pid', 'ssh_pid', 'ssh_stderr_log', 'gateway_pid')) {
        if (@($outputFields | Where-Object { $_ -eq $requiredField }).Count -ne 1) {
            $failures.Add("launcher output must contain exactly one $requiredField field")
        }
    }
    foreach ($sensitiveField in @(
        'cdp_url',
        'ssh_target',
        'remote_forward',
        'gateway_policy_sha256',
        'gateway_boot_nonce'
    )) {
        $sensitiveMatches = @($outputObjects | ForEach-Object {
            $_.KeyValuePairs | ForEach-Object { $_.Item1.Value }
        } | Where-Object { $_ -eq $sensitiveField })
        if ($sensitiveMatches.Count -ne 0) {
            $failures.Add("launcher output must not contain sensitive field $sensitiveField")
        }
    }

    return $failures.ToArray()
}

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$launcherPath = Join-Path $repositoryRoot 'rookery\bin\start-chrome-cdp.ps1'
Assert-True -Condition (Test-Path -LiteralPath $launcherPath -PathType Leaf) -Message "launcher was not found at $launcherPath"
$source = Get-Content -LiteralPath $launcherPath -Raw -Encoding utf8

$parsed = Get-ParsedLauncher -Source $source
Assert-True -Condition ($parsed.Errors.Count -eq 0) -Message "launcher parser errors: $($parsed.Errors.Extent.Text -join '; ')"
$failures = @(Get-LauncherContractFailures -Source $source)
Assert-True -Condition ($failures.Count -eq 0) -Message ('launcher contract failures: ' + ($failures -join '; '))

# The mutation keeps valid PowerShell but breaks one security-critical Chrome argument.
$mutatedSource = $source.Replace(
    '"--proxy-server=http://127.0.0.1:$gatewayProxyPort"',
    '"--proxy-server=direct://"'
)
Assert-True -Condition ($mutatedSource -ne $source) -Message 'negative fixture did not modify the launcher source'
$mutatedParsed = Get-ParsedLauncher -Source $mutatedSource
Assert-True -Condition ($mutatedParsed.Errors.Count -eq 0) -Message 'negative fixture must remain valid PowerShell'
$mutatedFailures = @(Get-LauncherContractFailures -Source $mutatedSource)
Assert-True -Condition ($mutatedFailures.Count -gt 0) -Message 'negative fixture unexpectedly passed the launcher contract'
Assert-True -Condition (@($mutatedFailures | Where-Object { $_ -match 'proxy-server' }).Count -gt 0) -Message 'negative fixture did not fail the proxy-server contract'

$sensitiveOutputMutation = $source.Replace(
    'chrome_pid = $chromeProcessId',
    "cdp_url = `$cdpUrl`n    chrome_pid = `$chromeProcessId"
)
Assert-True -Condition ($sensitiveOutputMutation -ne $source) -Message 'sensitive-output fixture did not modify the launcher source'
$sensitiveOutputParsed = Get-ParsedLauncher -Source $sensitiveOutputMutation
Assert-True -Condition ($sensitiveOutputParsed.Errors.Count -eq 0) -Message 'sensitive-output fixture must remain valid PowerShell'
$sensitiveOutputFailures = @(Get-LauncherContractFailures -Source $sensitiveOutputMutation)
Assert-True -Condition (@($sensitiveOutputFailures | Where-Object { $_ -match 'cdp_url' }).Count -gt 0) -Message 'sensitive-output fixture did not fail the output privacy contract'

Write-Output 'Chrome CDP launcher contract passed.'
