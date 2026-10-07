<#
.SYNOPSIS
Starts or verifies a dedicated local Chrome DevTools session and a loopback-only reverse SSH tunnel.

.DESCRIPTION
Rookery's CDP mode requires Chrome DevTools at http://127.0.0.1:<Port> on the
workstation.  This helper starts Chrome with a non-default profile under the
current user's local application data, verifies the DevTools endpoint, and
forwards the same loopback port to the remote node with SSH remote forwarding.
It never accepts passwords or host keys on the command line.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidatePattern('^(?:[A-Za-z0-9][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$SshTarget,

    [ValidateSet('Start', 'Health', 'Stop')]
    [string]$Mode = 'Start',

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$WslDistribution,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$WslUser,

    [string]$IdentityFile,

    [ValidateRange(1, 65535)]
    [int]$SshPort = 22,

    [ValidateRange(1024, 65535)]
    [int]$Port = 9001,

    [ValidateRange(1, 60)]
    [int]$HealthTimeoutSeconds = 15,

    [ValidateRange(1, 10)]
    [int]$TunnelStartupSeconds = 3,

    [ValidateRange(2, 30)]
    [int]$RemoteProbeTimeoutSeconds = 8,

    [string]$GatewayPolicyPath,

    [ValidateRange(1024, 65535)]
    [int]$GatewayProxyPort = 9002,

    [ValidateRange(1024, 65535)]
    [int]$GatewayStatusPort = 9003,

    [string]$ChromeExecutable,

    [string]$UserDataDir = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Rookery\chrome-cdp')
)

$ErrorActionPreference = 'Stop'
$cdpUrl = "http://127.0.0.1:$Port"
$versionUrl = "$cdpUrl/json/version"
$maximumVersionBytes = 65536

function Get-ChromeExecutable {
    [CmdletBinding()]
    param(
        [string]$RequestedPath
    )

    $candidates = @()
    if ($RequestedPath) {
        $candidates += $RequestedPath
    }
    else {
        $fromPath = Get-Command -Name 'chrome.exe' -ErrorAction SilentlyContinue
        if ($fromPath) {
            $candidates += $fromPath.Source
        }
        $candidates += @(
            (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Google\Chrome\Application\chrome.exe')
        )
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $resolved = (Resolve-Path -LiteralPath $candidate).Path
            if ((Split-Path -Leaf $resolved) -notmatch '^chrome\.exe$') {
                throw "ChromeExecutable must name chrome.exe, received '$resolved'."
            }
            return $resolved
        }
    }

    throw 'Google Chrome was not found. Install it or pass -ChromeExecutable with the full path to chrome.exe.'
}

function Resolve-DedicatedProfilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $drive = [System.IO.DriveInfo]::new($pathRoot)
    if ($fullPath.StartsWith('\\') -or $drive.DriveType -eq [System.IO.DriveType]::Network) {
        throw 'UserDataDir must be a local workstation path, not a network share.'
    }
    $defaultProfiles = @(
        (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Google\Chrome\User Data'),
        (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Google\Chrome\User Data')
    ) | ForEach-Object {
        [System.IO.Path]::GetFullPath($_).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    }

    $insideDefaultProfile = @(
        $defaultProfiles | Where-Object {
            $fullPath -eq $_ -or
            $fullPath.StartsWith(
                $_ + [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
    ).Count -gt 0
    if ($insideDefaultProfile) {
        throw "UserDataDir must be a dedicated non-default Chrome profile. '$fullPath' is a default Chrome profile."
    }

    if (Test-Path -LiteralPath $fullPath) {
        $item = Get-Item -LiteralPath $fullPath -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'UserDataDir must name a regular local directory, not a file or reparse point.'
        }
    }

    return $fullPath
}

function Resolve-SshIdentityFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw 'IdentityFile must name an existing absolute local private key file on the workstation.'
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
        $drive = [System.IO.DriveInfo]::new($pathRoot)
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    }
    catch {
        throw 'IdentityFile must name an existing absolute local private key file on the workstation.'
    }

    if (
        $drive.DriveType -eq [System.IO.DriveType]::Network -or
        -not ($item -is [System.IO.FileInfo]) -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    ) {
        throw 'IdentityFile must name a regular local private key file, not a network or reparse-point target.'
    }

    return $item.FullName
}

function Get-LoopbackListener {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LocalPort
    )

    try {
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -match '^No matching MSFT_NetTCPConnection objects found') {
            return $null
        }
        throw "Cannot inspect local TCP port $LocalPort with Get-NetTCPConnection: $($_.Exception.Message)"
    }

    if ($listeners.Count -eq 0) {
        return $null
    }

    $nonLoopback = @($listeners | Where-Object { $_.LocalAddress -ne '127.0.0.1' })
    if ($nonLoopback.Count -gt 0) {
        throw "TCP port $LocalPort is listening on a non-loopback address. Refusing to use a remotely reachable DevTools endpoint."
    }

    $processIds = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    if ($processIds.Count -ne 1) {
        throw "TCP port $LocalPort has multiple loopback listeners. Refusing to select a DevTools process."
    }

    return [int]$processIds[0]
}

function Invoke-LoopbackCdpProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [int]$ExpectedPort = $Port
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    # CDP is loopback-only. Ambient proxy settings must never redirect this probe.
    $handler.UseProxy = $false
    $handler.Proxy = $null
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $response = $null
    $stream = $null
    $memory = $null

    try {
        $response = $client.GetAsync($Url).GetAwaiter().GetResult()
        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
            return [pscustomobject]@{ State = 'conflict'; Message = "received HTTP $([int]$response.StatusCode)" }
        }
        if ($response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt $maximumVersionBytes) {
            return [pscustomobject]@{ State = 'conflict'; Message = 'returned an oversized /json/version response' }
        }

        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = [System.IO.MemoryStream]::new()
        $buffer = [byte[]]::new(8192)
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) {
                break
            }
            if (($memory.Length + $read) -gt $maximumVersionBytes) {
                return [pscustomobject]@{ State = 'conflict'; Message = 'returned an oversized /json/version response' }
            }
            $memory.Write($buffer, 0, $read)
        }

        return Test-CdpVersionPayload -Body ([System.Text.Encoding]::UTF8.GetString($memory.ToArray())) -ExpectedPort $ExpectedPort
    }
    catch {
        return [pscustomobject]@{ State = 'unavailable'; Message = $_.Exception.Message }
    }
    finally {
        if ($memory) { $memory.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}

function Test-CdpVersionPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedPort
    )

    try {
        $version = $Body | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ State = 'conflict'; Message = 'returned invalid JSON from /json/version' }
    }

    if (-not ($version.Browser -is [string]) -or $version.Browser -notmatch '^Chrome/\d+') {
        return [pscustomobject]@{ State = 'conflict'; Message = 'did not identify itself as Google Chrome' }
    }
    if (-not ($version.'Protocol-Version' -is [string]) -or [string]::IsNullOrWhiteSpace($version.'Protocol-Version')) {
        return [pscustomobject]@{ State = 'conflict'; Message = 'omitted Protocol-Version' }
    }
    if (-not ($version.webSocketDebuggerUrl -is [string])) {
        return [pscustomobject]@{ State = 'conflict'; Message = 'omitted webSocketDebuggerUrl' }
    }

    try {
        $webSocketUrl = [System.Uri]$version.webSocketDebuggerUrl
    }
    catch {
        return [pscustomobject]@{ State = 'conflict'; Message = 'returned an invalid webSocketDebuggerUrl' }
    }
    if ($webSocketUrl.Scheme -ne 'ws' -or $webSocketUrl.Host -ne '127.0.0.1' -or $webSocketUrl.Port -ne $ExpectedPort) {
        return [pscustomobject]@{ State = 'conflict'; Message = 'returned a non-loopback webSocketDebuggerUrl' }
    }

    return [pscustomobject]@{ State = 'ready'; Message = 'Chrome DevTools is ready' }
}

function Resolve-GatewayPolicyPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw 'GatewayPolicyPath must name an existing absolute private policy file on the workstation.'
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\') -or -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'GatewayPolicyPath must name an existing absolute private policy file on the workstation.'
    }
    return (Resolve-Path -LiteralPath $fullPath).Path
}

function Get-PythonExecutable {
    [CmdletBinding()]
    param()

    foreach ($name in @('python.exe', 'python')) {
        $candidate = Get-Command -Name $name -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.Source) {
            $resolvedExecutable = (& $candidate.Source -I -S -B -c "import pathlib,sys;print(pathlib.Path(sys.executable).resolve())" 2>$null).Trim()
            if (
                $LASTEXITCODE -eq 0 -and
                $resolvedExecutable -and
                (Test-Path -LiteralPath $resolvedExecutable -PathType Leaf)
            ) {
                return (Resolve-Path -LiteralPath $resolvedExecutable).Path
            }
        }
    }
    throw 'Python was not found. Sealed gateway mode requires a Python 3.11 or newer interpreter.'
}

function Get-GatewayPolicyDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Python,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    $digestScript = "import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);d=json.loads(p.read_bytes().decode('utf-8'));s=d.get('scope');isinstance(s,dict) or sys.exit(2);s.pop('compiled_at',None);print(hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest())"
    $digest = (& $Python -I -S -B -c $digestScript $PolicyPath 2>$null).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'GatewayPolicyPath could not be parsed into its canonical policy digest.'
    }
    if ($digest -notmatch '^[0-9a-f]{64}$') {
        throw 'GatewayPolicyPath did not produce a valid canonical policy digest.'
    }
    return $digest
}

function Invoke-GatewayStatusProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$StatusPort,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDigest,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $handler.Proxy = $null
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $response = $null
    $stream = $null
    $memory = $null
    try {
        $response = $client.GetAsync("http://127.0.0.1:$StatusPort/status").GetAwaiter().GetResult()
        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK -or $response.Content.Headers.ContentLength -gt $maximumVersionBytes) {
            return [pscustomobject]@{ State = 'conflict'; Message = 'gateway status response was not acceptable' }
        }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = [System.IO.MemoryStream]::new()
        $buffer = [byte[]]::new(8192)
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            if (($memory.Length + $read) -gt $maximumVersionBytes) {
                return [pscustomobject]@{ State = 'conflict'; Message = 'gateway status response was oversized' }
            }
            $memory.Write($buffer, 0, $read)
        }
        $body = [System.Text.Encoding]::UTF8.GetString($memory.ToArray())
        $jsonArguments = @{ ErrorAction = 'Stop' }
        if ((Get-Command -Name 'ConvertFrom-Json').Parameters.ContainsKey('DateKind')) {
            $jsonArguments.DateKind = 'String'
        }
        $status = $body | ConvertFrom-Json @jsonArguments
        $statusKeys = @($status.PSObject.Properties.Name | Sort-Object) -join ','
        $counterKeys = @($status.counters.PSObject.Properties.Name | Sort-Object) -join ','
        $listenerKeys = @($status.listeners.PSObject.Properties.Name | Sort-Object) -join ','
        if (
            $statusKeys -ne 'boot_nonce,counters,expires_at,listeners,policy_sha256,schema_version' -or
            $counterKeys -ne 'accepted,bytes,completed,connected,failed,refused' -or
            $listenerKeys -ne 'proxy,status' -or
            $status.schema_version -ne '1' -or
            $status.boot_nonce -notmatch '^[0-9a-f]{64}$' -or
            $status.policy_sha256 -ne $PolicyDigest -or
            $status.listeners.proxy -ne "127.0.0.1:$ProxyPort" -or
            $status.listeners.status -ne "127.0.0.1:$StatusPort" -or
            -not ($status.expires_at -is [string]) -or
            [string]::IsNullOrWhiteSpace($status.expires_at) -or
            -not $status.counters
        ) {
            return [pscustomobject]@{ State = 'conflict'; Message = 'gateway status did not match the sealed policy and listeners' }
        }
        foreach ($name in @('accepted', 'refused', 'connected', 'completed', 'failed', 'bytes')) {
            if ($null -eq $status.counters.$name -or $status.counters.$name -is [bool] -or [Int64]$status.counters.$name -lt 0) {
                return [pscustomobject]@{ State = 'conflict'; Message = 'gateway status counters were invalid' }
            }
        }
        return [pscustomobject]@{ State = 'ready'; Message = 'gateway status is ready'; Status = $status }
    }
    catch {
        return [pscustomobject]@{ State = 'unavailable'; Message = $_.Exception.Message }
    }
    finally {
        if ($memory) { $memory.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-ChromeSwitchCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine,

        [Parameter(Mandatory = $true)]
        [string]$SwitchName
    )

    $pattern = '(?i)(?:^|[\s"])' + [regex]::Escape($SwitchName) + '(?==|\s|"|$)'
    return @([regex]::Matches($CommandLine, $pattern)).Count
}

function Test-ChromeExactSwitchValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine,

        [Parameter(Mandatory = $true)]
        [string]$SwitchName,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedValue
    )

    $escapedSwitch = [regex]::Escape($SwitchName)
    $escapedValue = [regex]::Escape($ExpectedValue)
    $unquotedPattern = '(?i)(?:^|\s)' + $escapedSwitch + '=' + $escapedValue + '(?=$|\s)'
    $quotedPattern = '(?i)(?:^|\s)"' + $escapedSwitch + '=' + $escapedValue + '"(?=$|\s)'
    return [regex]::IsMatch($CommandLine, $unquotedPattern) -or [regex]::IsMatch($CommandLine, $quotedPattern)
}

function Assert-SealedChromeSwitches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort
    )

    $singleSwitches = @(
        '--proxy-server', '--proxy-bypass-list', '--host-resolver-rules',
        '--force-webrtc-ip-handling-policy', '--disable-quic', '--dns-prefetch-disable',
        '--disable-extensions'
    )
    foreach ($switchName in $singleSwitches) {
        if ((Get-ChromeSwitchCount -CommandLine $CommandLine -SwitchName $switchName) -ne 1) {
            throw 'Chrome does not have one unambiguous sealed-gateway switch for every network control.'
        }
    }
    foreach ($forbidden in @('--no-proxy-server', '--proxy-auto-detect', '--proxy-pac-url', '--load-extension', '--disable-extensions-except', '--enable-extensions')) {
        if ((Get-ChromeSwitchCount -CommandLine $CommandLine -SwitchName $forbidden) -gt 0) {
            throw 'Chrome has a conflicting proxy control.'
        }
    }
    if (
        -not (Test-ChromeExactSwitchValue -CommandLine $CommandLine -SwitchName '--proxy-server' -ExpectedValue "http://127.0.0.1:$ProxyPort") -or
        -not (Test-ChromeExactSwitchValue -CommandLine $CommandLine -SwitchName '--proxy-bypass-list' -ExpectedValue '<-loopback>') -or
        -not (Test-ChromeExactSwitchValue -CommandLine $CommandLine -SwitchName '--host-resolver-rules' -ExpectedValue 'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1') -or
        -not (Test-ChromeExactSwitchValue -CommandLine $CommandLine -SwitchName '--force-webrtc-ip-handling-policy' -ExpectedValue 'disable_non_proxied_udp') -or
        $CommandLine -notmatch '(?i)(?:^|[\s"])--disable-quic(?=$|[\s"])' -or
        $CommandLine -notmatch '(?i)(?:^|[\s"])--dns-prefetch-disable(?=$|[\s"])' -or
        $CommandLine -notmatch '(?i)(?:^|[\s"])--disable-extensions(?=$|[\s"])'
    ) {
        throw 'Chrome sealed-gateway switches do not have their exact required values.'
    }
}

function Test-DedicatedChromeProcessCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $true)]
        [int]$LocalPort,

        [int]$ProxyPort = 0
    )

    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    if ($process.ProcessName -notmatch '^chrome$') {
        throw "TCP port $LocalPort belongs to '$($process.ProcessName)', not Chrome."
    }

    $processDetails = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
    if (-not $processDetails.CommandLine) {
        throw "Cannot verify the Chrome command line for process $ProcessId."
    }

    foreach ($switchName in @('--remote-debugging-address', '--remote-debugging-port', '--user-data-dir')) {
        if ((Get-ChromeSwitchCount -CommandLine $processDetails.CommandLine -SwitchName $switchName) -ne 1) {
            throw "Chrome on port $LocalPort has ambiguous CDP or profile switches."
        }
    }
    if (
        -not (Test-ChromeExactSwitchValue -CommandLine $processDetails.CommandLine -SwitchName '--remote-debugging-address' -ExpectedValue '127.0.0.1') -or
        -not (Test-ChromeExactSwitchValue -CommandLine $processDetails.CommandLine -SwitchName '--remote-debugging-port' -ExpectedValue ([string]$LocalPort)) -or
        -not (Test-ChromeExactSwitchValue -CommandLine $processDetails.CommandLine -SwitchName '--user-data-dir' -ExpectedValue $ProfilePath)
    ) {
        throw "Chrome on port $LocalPort is not using this helper's loopback CDP settings and dedicated profile."
    }
    if ($ProxyPort -gt 0) {
        Assert-SealedChromeSwitches -CommandLine $processDetails.CommandLine -ProxyPort $ProxyPort
    }

    return $process
}

function Assert-DedicatedChromeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LocalPort,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [int]$ProxyPort = 0
    )

    $processId = Get-LoopbackListener -LocalPort $LocalPort
    if ($null -eq $processId) {
        throw "Chrome reported a DevTools endpoint but no loopback listener was found on port $LocalPort."
    }
    $process = Test-DedicatedChromeProcessCommand -ProcessId $processId -ProfilePath $ProfilePath -LocalPort $LocalPort -ProxyPort $ProxyPort
    return $process.Id
}

function Wait-ForDedicatedChrome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LocalPort,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [int]$ProxyPort = 0
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastMessage = 'Chrome did not provide a DevTools endpoint.'
    while ([DateTime]::UtcNow -lt $deadline) {
        $probe = Invoke-LoopbackCdpProbe -Url "http://127.0.0.1:$LocalPort/json/version" -TimeoutSeconds 2
        if ($probe.State -eq 'ready') {
            try {
                return Assert-DedicatedChromeProcess -LocalPort $LocalPort -ProfilePath $ProfilePath -ProxyPort $ProxyPort
            }
            catch {
                $lastMessage = $_.Exception.Message
            }
        }
        else {
            $lastMessage = $probe.Message
        }
        Start-Sleep -Milliseconds 250
    }

    throw "Chrome CDP did not become ready on 127.0.0.1:$LocalPort within $TimeoutSeconds seconds: $lastMessage"
}

function Start-LoopbackSshTunnel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [int]$SshPort,

        [string]$IdentityFile,

        [Parameter(Mandatory = $true)]
        [int[]]$TunnelPorts,

        [Parameter(Mandatory = $true)]
        [int]$StartupSeconds,

        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $ssh = Get-Command -Name 'ssh.exe' -ErrorAction Stop
    if ($TunnelPorts.Count -eq 0 -or @($TunnelPorts | Select-Object -Unique).Count -ne $TunnelPorts.Count) {
        throw 'SSH tunnel ports must be a non-empty unique list.'
    }
    $stderrLog = Join-Path $LogDirectory ("ssh-reverse-" + ($TunnelPorts -join '-') + '.stderr.log')
    $arguments = @(
        '-N',
        '-p', [string]$SshPort,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', "ConnectTimeout=$StartupSeconds",
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3'
    )
    if ($IdentityFile) {
        # Start-Process joins ArgumentList, so quote a path that may contain spaces.
        $arguments += @('-i', "`"$IdentityFile`"")
    }
    foreach ($tunnelPort in $TunnelPorts) {
        $arguments += @('-R', "127.0.0.1:$tunnelPort`:127.0.0.1:$tunnelPort")
    }
    $arguments += $Target
    $sshProcess = Start-Process -FilePath $ssh.Source -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardError $stderrLog
    if ($sshProcess.WaitForExit($StartupSeconds * 1000)) {
        throw "SSH tunnel exited before it was ready. Inspect '$stderrLog' and verify SSH host trust and key-based access for '$Target'."
    }

    return [pscustomobject]@{
        ProcessId = $sshProcess.Id
        StartedAt = $sshProcess.StartTime.ToUniversalTime()
        ErrorLog = $stderrLog
    }
}

function Test-GatewayProcessCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$GatewayProgram,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort
    )

    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    if ($process.ProcessName -notmatch '^python(?:\.exe)?$') {
        throw "Gateway listener belongs to '$($process.ProcessName)', not Python."
    }
    $details = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
    $required = @(
        '-I', '-S', '-B', $GatewayProgram, '--policy', $PolicyPath,
        '--proxy-port', [string]$ProxyPort, '--status-port', [string]$StatusPort
    )
    foreach ($argument in $required) {
        if (-not $details.CommandLine -or $details.CommandLine.IndexOf($argument, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "Gateway process $ProcessId does not have the required sealed-gateway command line."
        }
    }
    return $process
}

function Assert-SealedGatewayProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort,

        [Parameter(Mandatory = $true)]
        [string]$GatewayProgram,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    $proxyProcessId = Get-LoopbackListener -LocalPort $ProxyPort
    $statusProcessId = Get-LoopbackListener -LocalPort $StatusPort
    if ($null -eq $proxyProcessId -or $null -eq $statusProcessId -or $proxyProcessId -ne $statusProcessId) {
        throw 'The sealed gateway does not own both expected loopback listeners.'
    }
    return Test-GatewayProcessCommand -ProcessId $statusProcessId -GatewayProgram $GatewayProgram -PolicyPath $PolicyPath -ProxyPort $ProxyPort -StatusPort $StatusPort
}

function Wait-ForSealedGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort,

        [Parameter(Mandatory = $true)]
        [string]$GatewayProgram,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDigest,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastMessage = 'gateway status did not become available'
    while ([DateTime]::UtcNow -lt $deadline) {
        $status = Invoke-GatewayStatusProbe -StatusPort $StatusPort -ProxyPort $ProxyPort -PolicyDigest $PolicyDigest -TimeoutSeconds 2
        if ($status.State -eq 'ready') {
            try {
                $process = Assert-SealedGatewayProcess -ProxyPort $ProxyPort -StatusPort $StatusPort -GatewayProgram $GatewayProgram -PolicyPath $PolicyPath
                return [pscustomobject]@{ Process = $process; Status = $status.Status }
            }
            catch {
                $lastMessage = $_.Exception.Message
            }
        }
        else {
            $lastMessage = $status.Message
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Sealed gateway did not become ready within $TimeoutSeconds seconds: $lastMessage"
}

function Start-SealedGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Python,

        [Parameter(Mandatory = $true)]
        [string]$GatewayProgram,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDigest,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $stderrLog = Join-Path $LogDirectory "sealed-gateway-$StatusPort.stderr.log"
    $quotedProgram = "`"$GatewayProgram`""
    $quotedPolicy = "`"$PolicyPath`""
    $process = Start-Process -FilePath $Python -ArgumentList @('-I', '-S', '-B', $quotedProgram, '--policy', $quotedPolicy, '--proxy-port', $ProxyPort, '--status-port', $StatusPort) -WindowStyle Hidden -PassThru -RedirectStandardError $stderrLog
    if ($process.WaitForExit(500)) {
        throw "Sealed gateway exited before it was ready. Inspect '$stderrLog'."
    }
    try {
        $ready = Wait-ForSealedGateway -ProxyPort $ProxyPort -StatusPort $StatusPort -GatewayProgram $GatewayProgram -PolicyPath $PolicyPath -PolicyDigest $PolicyDigest -TimeoutSeconds $TimeoutSeconds
        if ($ready.Process.Id -ne $process.Id) {
            throw 'A different process claimed the sealed gateway listeners.'
        }
    }
    catch {
        try {
            $identity = Test-GatewayProcessCommand -ProcessId $process.Id -GatewayProgram $GatewayProgram -PolicyPath $PolicyPath -ProxyPort $ProxyPort -StatusPort $StatusPort
            if ($identity.StartTime.ToUniversalTime() -eq $process.StartTime.ToUniversalTime()) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
            }
        }
        catch {
            # A process that cannot be identified is never stopped by this launcher.
        }
        throw
    }
    return [pscustomobject]@{
        ProcessId = $process.Id
        StartedAt = $process.StartTime.ToUniversalTime()
        PolicyDigest = $PolicyDigest
        BootNonce = $ready.Status.boot_nonce
        ErrorLog = $stderrLog
    }
}

function Stop-NewGatewayProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Gateway,

        [Parameter(Mandatory = $true)]
        [string]$GatewayProgram,

        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort
    )

    $process = Test-GatewayProcessCommand -ProcessId $Gateway.ProcessId -GatewayProgram $GatewayProgram -PolicyPath $PolicyPath -ProxyPort $ProxyPort -StatusPort $StatusPort
    if ($process.StartTime.ToUniversalTime() -eq $Gateway.StartedAt) {
        Stop-Process -Id $Gateway.ProcessId -Force -ErrorAction Stop
    }
}

function Stop-NewChromeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Chrome,

        [Parameter(Mandatory = $true)]
        [int]$CdpPort,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [int]$ProxyPort = 0
    )

    $process = Test-DedicatedChromeProcessCommand -ProcessId $Chrome.ProcessId -ProfilePath $ProfilePath -LocalPort $CdpPort -ProxyPort $ProxyPort
    if ($process.StartTime.ToUniversalTime() -eq $Chrome.StartedAt) {
        Stop-Process -Id $Chrome.ProcessId -Force -ErrorAction Stop
    }
}

function Test-RemoteLoopbackCdpTunnel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [int]$SshPort,

        [string]$IdentityFile,

        [Parameter(Mandatory = $true)]
        [int]$TunnelPort,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $ssh = Get-Command -Name 'ssh.exe' -ErrorAction Stop
    $stdoutLog = Join-Path $LogDirectory "ssh-reverse-$TunnelPort.probe.stdout.log"
    $stderrLog = Join-Path $LogDirectory "ssh-reverse-$TunnelPort.probe.stderr.log"
    $remoteUrl = "http://127.0.0.1:$TunnelPort/json/version"
    $pythonSource = "import sys,urllib.request;R=type('R',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda *a:None});u='$remoteUrl';o=urllib.request.build_opener(urllib.request.ProxyHandler({}),R());d=o.open(u,timeout=$TimeoutSeconds).read($($maximumVersionBytes + 1));len(d)<=$maximumVersionBytes or sys.exit('oversized CDP response');sys.stdout.write(d.decode('utf-8'))"
    $encodedSource = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pythonSource))
    $remoteCommand = "python3 -c `"import base64;exec(base64.b64decode('$encodedSource'))`""
    # Preserve the remote command as one SSH argument so no shell parses operator input.
    $remoteCommandArgument = '"' + $remoteCommand.Replace('"', '\"') + '"'
    $arguments = @(
        '-p', [string]$SshPort,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "ConnectTimeout=$TimeoutSeconds",
        '-o', 'RequestTTY=no',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3'
    )
    if ($IdentityFile) {
        $arguments += @('-i', "`"$IdentityFile`"")
    }
    $arguments += @($Target, $remoteCommandArgument)
    $probeProcess = Start-Process -FilePath $ssh.Source -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    if (-not $probeProcess.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
        throw "Remote loopback CDP probe exceeded its $TimeoutSeconds-second timeout."
    }
    if ($probeProcess.ExitCode -ne 0) {
        throw "Remote loopback CDP probe failed. Inspect '$stderrLog' and verify Python 3 plus SSH access on '$Target'."
    }

    $body = Get-Content -LiteralPath $stdoutLog -Raw -Encoding utf8
    if ($body.Length -gt $maximumVersionBytes) {
        throw "Remote loopback CDP probe returned more than $maximumVersionBytes bytes."
    }
    $probe = Test-CdpVersionPayload -Body $body -ExpectedPort $TunnelPort
    if ($probe.State -ne 'ready') {
        throw "Remote loopback CDP probe did not validate the tunnel: $($probe.Message)"
    }
}

function Stop-NewTunnelProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Tunnel
    )

    $process = Get-Process -Id $Tunnel.ProcessId -ErrorAction SilentlyContinue
    if ($process -and $process.StartTime.ToUniversalTime() -eq $Tunnel.StartedAt) {
        Stop-Process -Id $Tunnel.ProcessId -Force -ErrorAction Stop
    }
}

function Test-RemoteGatewayStatusTunnel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [int]$SshPort,

        [string]$IdentityFile,

        [Parameter(Mandatory = $true)]
        [int]$StatusPort,

        [Parameter(Mandatory = $true)]
        [int]$ProxyPort,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDigest,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $ssh = Get-Command -Name 'ssh.exe' -ErrorAction Stop
    $stdoutLog = Join-Path $LogDirectory "ssh-reverse-$StatusPort.gateway-status.stdout.log"
    $stderrLog = Join-Path $LogDirectory "ssh-reverse-$StatusPort.gateway-status.stderr.log"
    $remoteUrl = "http://127.0.0.1:$StatusPort/status"
    $pythonSource = "import sys,urllib.request;R=type('R',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda *a:None});u='$remoteUrl';o=urllib.request.build_opener(urllib.request.ProxyHandler({}),R());d=o.open(u,timeout=$TimeoutSeconds).read($($maximumVersionBytes + 1));len(d)<=$maximumVersionBytes or sys.exit('oversized gateway status');sys.stdout.write(d.decode('utf-8'))"
    $encodedSource = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pythonSource))
    $remoteCommand = "python3 -c `"import base64;exec(base64.b64decode('$encodedSource'))`""
    $remoteCommandArgument = '"' + $remoteCommand.Replace('"', '\"') + '"'
    $arguments = @(
        '-p', [string]$SshPort,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "ConnectTimeout=$TimeoutSeconds",
        '-o', 'RequestTTY=no',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3'
    )
    if ($IdentityFile) {
        $arguments += @('-i', "`"$IdentityFile`"")
    }
    $arguments += @($Target, $remoteCommandArgument)
    $probeProcess = Start-Process -FilePath $ssh.Source -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    if (-not $probeProcess.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
        throw "Remote sealed-gateway status probe exceeded its $TimeoutSeconds-second timeout."
    }
    if ($probeProcess.ExitCode -ne 0) {
        throw "Remote sealed-gateway status probe failed. Inspect '$stderrLog'."
    }
    $body = Get-Content -LiteralPath $stdoutLog -Raw -Encoding utf8
    if ($body.Length -gt $maximumVersionBytes) {
        throw "Remote sealed-gateway status probe returned more than $maximumVersionBytes bytes."
    }
    $jsonArguments = @{ ErrorAction = 'Stop' }
    if ((Get-Command -Name 'ConvertFrom-Json').Parameters.ContainsKey('DateKind')) {
        $jsonArguments.DateKind = 'String'
    }
    $status = $body | ConvertFrom-Json @jsonArguments
    if (
        $status.schema_version -ne '1' -or
        $status.boot_nonce -notmatch '^[0-9a-f]{64}$' -or
        $status.policy_sha256 -ne $PolicyDigest -or
        $status.listeners.proxy -ne "127.0.0.1:$ProxyPort" -or
        $status.listeners.status -ne "127.0.0.1:$StatusPort"
    ) {
        throw 'Remote sealed-gateway status did not match the local sealed gateway.'
    }
    return $status
}

function Get-FileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Test-BridgeBundle {
    [CmdletBinding()]
    param()

    $root = Split-Path -Parent $PSScriptRoot
    $metadataPath = Join-Path $root 'bridge-bundle.json'
    if (Test-Path -LiteralPath (Join-Path $root '.bridge-bundle-incomplete')) {
        throw 'Bridge bundle publication is incomplete.'
    }
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        return $null
    }
    $metadataItem = Get-Item -LiteralPath $metadataPath -Force
    if ($metadataItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'Bridge bundle metadata must be a regular file.'
    }
    $jsonArguments = @{ ErrorAction = 'Stop' }
    if ((Get-Command -Name 'ConvertFrom-Json').Parameters.ContainsKey('DateKind')) { $jsonArguments.DateKind = 'String' }
    try { $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding utf8 | ConvertFrom-Json @jsonArguments }
    catch { throw 'Bridge bundle metadata is invalid.' }
    if ($metadata.schema_version -ne '1' -or -not $metadata.release -or -not ($metadata.files -is [System.Collections.IEnumerable])) {
        throw 'Bridge bundle metadata has an unsupported schema.'
    }
    $seen = @{}
    foreach ($row in @($metadata.files)) {
        if (-not $row -or -not ($row.path -is [string]) -or -not ($row.sha256 -is [string]) -or $row.path -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or $row.path.Contains('..') -or $row.sha256 -notmatch '^[0-9a-f]{64}$' -or $seen.ContainsKey($row.path)) {
            throw 'Bridge bundle metadata has an invalid file record.'
        }
        $seen[$row.path] = $true
        $path = Join-Path $root ($row.path -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint -or (Get-FileSha256 -Path $path) -ne $row.sha256) {
            throw 'Bridge bundle file verification failed.'
        }
    }
    foreach ($required in @('bin/start-chrome-cdp.ps1', 'bin/browser-scope-gateway.py')) {
        if (-not $seen.ContainsKey($required)) { throw 'Bridge bundle is missing a required bridge file.' }
    }
    return [pscustomobject]@{ Root = $root; MetadataPath = $metadataPath; Sha256 = Get-FileSha256 -Path $metadataPath; ReleaseVersion = $metadata.release.version; ArchiveSha256 = $metadata.release.archive_sha256; ManifestSha256 = $metadata.release.manifest_sha256 }
}

function Resolve-WslSshTarget {
    [CmdletBinding()]
    param([string]$Target, [string]$Distribution, [string]$User)
    if ($Target -and ($Distribution -or $User)) { throw 'Specify SshTarget or WslDistribution and WslUser, not both.' }
    if ($Target) { return $Target }
    if (-not $Distribution -or -not $User) { throw 'Start mode requires SshTarget or both WslDistribution and WslUser.' }
    $wsl = Get-Command -Name 'wsl.exe' -ErrorAction Stop
    $output = & $wsl.Source -d $Distribution -u $User --exec /bin/sh -lc 'ip -4 route get 1.1.1.1 2>/dev/null | awk ''{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}''' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve the current WSL IPv4 address.' }
    $address = @($output | Where-Object { $_ -match '^(?:\d{1,3}\.){3}\d{1,3}$' } | Select-Object -First 1)
    if ($address.Count -ne 1 -or $address[0] -eq '127.0.0.1') { throw 'Unable to resolve the current WSL IPv4 address.' }
    return "$User@$($address[0])"
}

function Convert-OwnershipTimestamp {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)
    try { return [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
    catch { throw 'Bridge ownership record has an invalid timestamp.' }
}

function Get-BridgeOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ProfilePath)
    $path = Join-Path $ProfilePath 'rookery-external-processes.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'No regular bridge ownership record exists for this profile.' }
    $jsonArguments = @{ ErrorAction = 'Stop' }
    if ((Get-Command -Name 'ConvertFrom-Json').Parameters.ContainsKey('DateKind')) { $jsonArguments.DateKind = 'String' }
    try { $record = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json @jsonArguments }
    catch { throw 'Bridge ownership record is invalid.' }
    if ($record.schema_version -ne '2' -or $record.profile_path -ne $ProfilePath -or -not $record.chrome -or -not $record.tunnel -or -not $record.bundle) { throw 'Bridge ownership record does not support guarded operations.' }
    return [pscustomobject]@{ Path = $path; Record = $record }
}

function Assert-OwnedBridge {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][pscustomobject]$Ownership, [Parameter(Mandatory = $true)][string]$ProfilePath)
    $record = $Ownership.Record
    if ($record.bundle.metadata_sha256) {
        $currentBundle = Test-BridgeBundle
        if (-not $currentBundle -or $currentBundle.Sha256 -ne $record.bundle.metadata_sha256) {
            throw 'Bridge bundle binding does not match the ownership record.'
        }
    }
    $chromeStart = Convert-OwnershipTimestamp -Value $record.chrome.started_at
    $chrome = Test-DedicatedChromeProcessCommand -ProcessId ([int]$record.chrome.pid) -ProfilePath $ProfilePath -LocalPort ([int]$record.cdp_port) -ProxyPort $(if ($record.gateway) { $gatewayProxyPort } else { 0 })
    if ($chrome.StartTime.ToUniversalTime() -ne $chromeStart) { throw 'Chrome identity does not match the bridge ownership record.' }
    $tunnelStart = Convert-OwnershipTimestamp -Value $record.tunnel.started_at
    $tunnel = Get-Process -Id ([int]$record.tunnel.pid) -ErrorAction Stop
    if ($tunnel.ProcessName -notmatch '^ssh$' -or $tunnel.StartTime.ToUniversalTime() -ne $tunnelStart) { throw 'SSH tunnel identity does not match the bridge ownership record.' }
    $gateway = $null
    if ($record.gateway) {
        $gatewayStart = Convert-OwnershipTimestamp -Value $record.gateway.started_at
        $gateway = Assert-SealedGatewayProcess -ProxyPort $gatewayProxyPort -StatusPort ([int]$record.gateway.status_port) -GatewayProgram ([string]$record.gateway.program_path) -PolicyPath ([string]$record.gateway.policy_path)
        if ($gateway.Id -ne [int]$record.gateway.pid -or $gateway.StartTime.ToUniversalTime() -ne $gatewayStart) { throw 'Gateway identity does not match the bridge ownership record.' }
    }
    return [pscustomobject]@{ Chrome = $chrome; Tunnel = $tunnel; Gateway = $gateway }
}

function Get-OwnedBridgeForStop {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][pscustomobject]$Ownership, [Parameter(Mandatory = $true)][string]$ProfilePath)
    $record = $Ownership.Record
    if ($record.bundle.metadata_sha256) {
        $currentBundle = Test-BridgeBundle
        if (-not $currentBundle -or $currentBundle.Sha256 -ne $record.bundle.metadata_sha256) {
            throw 'Bridge bundle binding does not match the ownership record.'
        }
    }
    $chrome = Get-Process -Id ([int]$record.chrome.pid) -ErrorAction SilentlyContinue
    if ($chrome) {
        $chrome = Test-DedicatedChromeProcessCommand -ProcessId $chrome.Id -ProfilePath $ProfilePath -LocalPort ([int]$record.cdp_port) -ProxyPort $(if ($record.gateway) { $gatewayProxyPort } else { 0 })
        if ($chrome.StartTime.ToUniversalTime() -ne (Convert-OwnershipTimestamp -Value $record.chrome.started_at)) { throw 'Chrome identity does not match the bridge ownership record.' }
    }
    $tunnel = Get-Process -Id ([int]$record.tunnel.pid) -ErrorAction SilentlyContinue
    if ($tunnel -and ($tunnel.ProcessName -notmatch '^ssh$' -or $tunnel.StartTime.ToUniversalTime() -ne (Convert-OwnershipTimestamp -Value $record.tunnel.started_at))) { throw 'SSH tunnel identity does not match the bridge ownership record.' }
    $gateway = $null
    if ($record.gateway) {
        $gateway = Get-Process -Id ([int]$record.gateway.pid) -ErrorAction SilentlyContinue
        if ($gateway) {
            $gateway = Test-GatewayProcessCommand -ProcessId $gateway.Id -GatewayProgram ([string]$record.gateway.program_path) -PolicyPath ([string]$record.gateway.policy_path) -ProxyPort $gatewayProxyPort -StatusPort ([int]$record.gateway.status_port)
            if ($gateway.StartTime.ToUniversalTime() -ne (Convert-OwnershipTimestamp -Value $record.gateway.started_at)) { throw 'Gateway identity does not match the bridge ownership record.' }
        }
    }
    return [pscustomobject]@{ Chrome = $chrome; Tunnel = $tunnel; Gateway = $gateway }
}

function Stop-VerifiedBridgeProcess {
    [CmdletBinding()]
    param([pscustomobject]$Process)
    if (-not $Process) { return }
    $current = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
    if (-not $current) { return }
    if ($current.StartTime.ToUniversalTime() -ne $Process.StartTime.ToUniversalTime()) { throw 'Bridge process identity changed before stop.' }
    Stop-Process -Id $current.Id -Force -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $remaining = Get-Process -Id $current.Id -ErrorAction SilentlyContinue
    } while ($remaining -and [DateTime]::UtcNow -lt $deadline)
    if ($remaining) { throw 'Bridge process did not stop.' }
}

$profilePath = Resolve-DedicatedProfilePath -Path $UserDataDir
$bundle = Test-BridgeBundle

if ($Mode -eq 'Health' -or $Mode -eq 'Stop') {
    $ownership = Get-BridgeOwnership -ProfilePath $profilePath
    if ($ownership.Record.gateway) {
        $recordProxyPort = if ($ownership.Record.gateway.PSObject.Properties.Name -contains 'proxy_port') {
            [int]$ownership.Record.gateway.proxy_port
        }
        else {
            9002
        }
        $recordStatusPort = [int]$ownership.Record.gateway.status_port
        if ($PSBoundParameters.ContainsKey('GatewayProxyPort') -and $GatewayProxyPort -ne $recordProxyPort) {
            throw 'Gateway proxy port does not match the bridge ownership record.'
        }
        if ($PSBoundParameters.ContainsKey('GatewayStatusPort') -and $GatewayStatusPort -ne $recordStatusPort) {
            throw 'Gateway status port does not match the bridge ownership record.'
        }
        $GatewayProxyPort = $recordProxyPort
        $GatewayStatusPort = $recordStatusPort
        if ($GatewayProxyPort -eq $GatewayStatusPort) {
            throw 'Gateway proxy and status ports in the ownership record must differ.'
        }
    }
    if ($Mode -eq 'Health') {
        if ($PSBoundParameters.ContainsKey('Port') -and $Port -ne [int]$ownership.Record.cdp_port) {
            throw 'Health CDP port does not match the bridge ownership record.'
        }
        if ($PSBoundParameters.ContainsKey('GatewayPolicyPath')) {
            if (-not $ownership.Record.gateway) { throw 'Health supplied a gateway policy for a bridge without a gateway.' }
            $healthPolicy = Resolve-GatewayPolicyPath -Path $GatewayPolicyPath
            $healthPython = Get-PythonExecutable
            $healthPolicyDigest = Get-GatewayPolicyDigest -Python $healthPython -PolicyPath $healthPolicy
            if (
                $healthPolicy -ne [string]$ownership.Record.gateway.policy_path -or
                $healthPolicyDigest -ne [string]$ownership.Record.gateway.policy_sha256
            ) {
                throw 'Health gateway policy does not match the bridge ownership record.'
            }
        }
        $identities = Assert-OwnedBridge -Ownership $ownership -ProfilePath $profilePath
        $probe = Invoke-LoopbackCdpProbe -Url "http://127.0.0.1:$($ownership.Record.cdp_port)/json/version" -TimeoutSeconds 2 -ExpectedPort ([int]$ownership.Record.cdp_port)
        if ($probe.State -ne 'ready') { throw "Bridge CDP health check failed: $($probe.Message)" }
        if ($ownership.Record.gateway) {
            $status = Invoke-GatewayStatusProbe -StatusPort ([int]$ownership.Record.gateway.status_port) -ProxyPort $gatewayProxyPort -PolicyDigest ([string]$ownership.Record.gateway.policy_sha256) -TimeoutSeconds 2
            if ($status.State -ne 'ready') { throw "Bridge gateway health check failed: $($status.Message)" }
        }
        [pscustomobject]@{ mode = 'health'; ok = $true; ownership_record = $ownership.Path; cdp_port = [int]$ownership.Record.cdp_port; chrome_pid = $identities.Chrome.Id; ssh_pid = $identities.Tunnel.Id; gateway_pid = if ($identities.Gateway) { $identities.Gateway.Id } else { $null }; gateway_proxy_port = if ($ownership.Record.gateway) { $GatewayProxyPort } else { $null }; gateway_status_port = if ($ownership.Record.gateway) { $GatewayStatusPort } else { $null }; bundle_sha256 = $ownership.Record.bundle.metadata_sha256 } | ConvertTo-Json -Compress | Write-Output
        return
    }
    $identities = Get-OwnedBridgeForStop -Ownership $ownership -ProfilePath $profilePath
    Stop-VerifiedBridgeProcess -Process $identities.Tunnel
    Stop-VerifiedBridgeProcess -Process $identities.Gateway
    Stop-VerifiedBridgeProcess -Process $identities.Chrome
    Remove-Item -LiteralPath $ownership.Path -Force -ErrorAction Stop
    [pscustomobject]@{ mode = 'stop'; ok = $true; profile_path = $profilePath } | ConvertTo-Json -Compress | Write-Output
    return
}

$startOwnershipPath = Join-Path $profilePath 'rookery-external-processes.json'
if (Test-Path -LiteralPath $startOwnershipPath) {
    throw 'A bridge ownership record already exists. Use Health or guarded Stop before Start.'
}

$SshTarget = Resolve-WslSshTarget -Target $SshTarget -Distribution $WslDistribution -User $WslUser
$sshIdentityFile = if ($IdentityFile) { Resolve-SshIdentityFilePath -Path $IdentityFile } else { $null }
$null = New-Item -ItemType Directory -Path $profilePath -Force

$gateway = $null
$gatewayProgram = $null
$gatewayPolicy = $null
$tunnel = $null
$createdChrome = $null
$ownershipTemporary = $null
try {
    if ($GatewayPolicyPath) {
        if ($gatewayProxyPort -eq $gatewayStatusPort) {
            throw 'Gateway proxy and status ports must differ.'
        }
        if ($Port -in @($gatewayProxyPort, $gatewayStatusPort)) {
            throw 'The CDP port must differ from the sealed gateway proxy and status ports.'
        }
        $gatewayPolicy = Resolve-GatewayPolicyPath -Path $GatewayPolicyPath
        $python = Get-PythonExecutable
        $gatewayProgram = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'browser-scope-gateway.py')).Path
        $policyDigest = Get-GatewayPolicyDigest -Python $python -PolicyPath $gatewayPolicy
        $profilePolicyBinding = Join-Path $profilePath '.rookery-gateway-policy.sha256'
        if (Test-Path -LiteralPath $profilePolicyBinding) {
            $bindingItem = Get-Item -LiteralPath $profilePolicyBinding -Force
            if ($bindingItem.PSIsContainer -or ($bindingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw 'The dedicated Chrome profile policy binding is not a regular local file.'
            }
            $boundPolicyDigest = (Get-Content -LiteralPath $profilePolicyBinding -Raw -Encoding ascii).Trim()
            if ($boundPolicyDigest -ne $policyDigest) {
                throw 'The dedicated Chrome profile is bound to a different gateway policy.'
            }
        }
        else {
            $profileInUse = @(
                Get-CimInstance -ClassName Win32_Process -Filter "Name = 'chrome.exe'" -ErrorAction Stop |
                    Where-Object {
                        $_.CommandLine -and
                        (Test-ChromeExactSwitchValue -CommandLine $_.CommandLine -SwitchName '--user-data-dir' -ExpectedValue $profilePath)
                    }
            ).Count -gt 0
            $existingProfileEntries = @(Get-ChildItem -LiteralPath $profilePath -Force -ErrorAction Stop)
            if ($profileInUse -or $existingProfileEntries.Count -gt 0) {
                throw 'An unbound dedicated Chrome profile must be new and empty before its first sealed-gateway policy binding.'
            }
            [System.IO.File]::WriteAllText(
                $profilePolicyBinding,
                $policyDigest + [Environment]::NewLine,
                [System.Text.Encoding]::ASCII
            )
        }
        $existingProxy = Get-LoopbackListener -LocalPort $gatewayProxyPort
        $existingStatus = Get-LoopbackListener -LocalPort $gatewayStatusPort
        $gatewayStatus = Invoke-GatewayStatusProbe -StatusPort $gatewayStatusPort -ProxyPort $gatewayProxyPort -PolicyDigest $policyDigest -TimeoutSeconds 2
        if ($gatewayStatus.State -eq 'ready') {
            $gatewayProcess = Assert-SealedGatewayProcess -ProxyPort $gatewayProxyPort -StatusPort $gatewayStatusPort -GatewayProgram $gatewayProgram -PolicyPath $gatewayPolicy
            $gateway = [pscustomobject]@{ ProcessId = $gatewayProcess.Id; StartedAt = $gatewayProcess.StartTime.ToUniversalTime(); PolicyDigest = $policyDigest; BootNonce = $gatewayStatus.Status.boot_nonce; ErrorLog = $null; Created = $false }
        }
        elseif ($null -ne $existingProxy -or $null -ne $existingStatus -or $gatewayStatus.State -eq 'conflict') {
            throw "Sealed gateway ports are occupied or returned an invalid status: $($gatewayStatus.Message)"
        }
        else {
            $gateway = Start-SealedGateway -Python $python -GatewayProgram $gatewayProgram -PolicyPath $gatewayPolicy -PolicyDigest $policyDigest -ProxyPort $gatewayProxyPort -StatusPort $gatewayStatusPort -TimeoutSeconds $HealthTimeoutSeconds -LogDirectory $profilePath
            $gateway | Add-Member -NotePropertyName Created -NotePropertyValue $true
        }
    }

    $existingListener = Get-LoopbackListener -LocalPort $Port
    $probe = Invoke-LoopbackCdpProbe -Url $versionUrl -TimeoutSeconds 2
    $chromeProcessId = $null
    $proxyPort = if ($gateway) { $gatewayProxyPort } else { 0 }
    if ($probe.State -eq 'ready') {
        $chromeProcessId = Assert-DedicatedChromeProcess -LocalPort $Port -ProfilePath $profilePath -ProxyPort $proxyPort
    }
    elseif ($null -ne $existingListener -or $probe.State -eq 'conflict') {
        throw "TCP port $Port is already in use by a service that is not this dedicated Chrome CDP session: $($probe.Message)"
    }
    else {
        $chrome = Get-ChromeExecutable -RequestedPath $ChromeExecutable
        $chromeArguments = @('--remote-debugging-address=127.0.0.1', "--remote-debugging-port=$Port", "`"--user-data-dir=$profilePath`"", '--no-first-run', '--no-default-browser-check')
        if ($gateway) {
            $chromeArguments += @("--proxy-server=http://127.0.0.1:$gatewayProxyPort", '--proxy-bypass-list=<-loopback>', '--disable-quic', '--dns-prefetch-disable', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-extensions', "`"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`"")
        }
        $chromeArguments += 'about:blank'
        $startedChrome = Start-Process -FilePath $chrome -ArgumentList $chromeArguments -PassThru
        $createdChrome = [pscustomobject]@{ ProcessId = $startedChrome.Id; StartedAt = $startedChrome.StartTime.ToUniversalTime() }
        $chromeProcessId = Wait-ForDedicatedChrome -LocalPort $Port -TimeoutSeconds $HealthTimeoutSeconds -ProfilePath $profilePath -ProxyPort $proxyPort
        if ($chromeProcessId -ne $startedChrome.Id) {
            throw 'A different Chrome process claimed the dedicated CDP listener.'
        }
        $chromeProcess = Get-Process -Id $chromeProcessId -ErrorAction Stop
        if ($chromeProcess.StartTime.ToUniversalTime() -ne $createdChrome.StartedAt) {
            throw 'The dedicated Chrome process identity changed during startup.'
        }
    }

    $tunnelPorts = @($Port)
    if ($gateway) { $tunnelPorts += $gatewayStatusPort }
    $tunnel = Start-LoopbackSshTunnel -Target $SshTarget -SshPort $SshPort -IdentityFile $sshIdentityFile -TunnelPorts $tunnelPorts -StartupSeconds $TunnelStartupSeconds -LogDirectory $profilePath
    Test-RemoteLoopbackCdpTunnel -Target $SshTarget -SshPort $SshPort -IdentityFile $sshIdentityFile -TunnelPort $Port -TimeoutSeconds $RemoteProbeTimeoutSeconds -LogDirectory $profilePath
    if ($gateway) {
        $remoteGatewayStatus = Test-RemoteGatewayStatusTunnel -Target $SshTarget -SshPort $SshPort -IdentityFile $sshIdentityFile -StatusPort $gatewayStatusPort -ProxyPort $gatewayProxyPort -PolicyDigest $gateway.PolicyDigest -TimeoutSeconds $RemoteProbeTimeoutSeconds -LogDirectory $profilePath
        if ($remoteGatewayStatus.boot_nonce -ne $gateway.BootNonce) {
            throw 'Remote sealed-gateway status did not identify the local gateway instance.'
        }
    }

    $verifiedChromeProcessId = Assert-DedicatedChromeProcess -LocalPort $Port -ProfilePath $profilePath -ProxyPort $proxyPort
    if ($verifiedChromeProcessId -ne $chromeProcessId) {
        throw 'The dedicated Chrome process changed before ownership publication.'
    }
    $chromeIdentity = Get-Process -Id $chromeProcessId -ErrorAction Stop
    $tunnelIdentity = Get-Process -Id $tunnel.ProcessId -ErrorAction Stop
    if (
        $tunnelIdentity.ProcessName -notmatch '^ssh$' -or
        $tunnelIdentity.StartTime.ToUniversalTime() -ne $tunnel.StartedAt
    ) {
        throw 'The SSH tunnel process changed before ownership publication.'
    }
    if ($gateway) {
        $gatewayIdentity = Assert-SealedGatewayProcess -ProxyPort $gatewayProxyPort -StatusPort $gatewayStatusPort -GatewayProgram $gatewayProgram -PolicyPath $gatewayPolicy
        if (
            $gatewayIdentity.Id -ne $gateway.ProcessId -or
            $gatewayIdentity.StartTime.ToUniversalTime() -ne $gateway.StartedAt
        ) {
            throw 'The sealed gateway process changed before ownership publication.'
        }
    }
    $ownership = [ordered]@{
        schema_version = '2'
        cdp_port = $Port
        profile_path = $profilePath
        bundle = if ($bundle) {
            [ordered]@{
                root = $bundle.Root
                metadata_sha256 = $bundle.Sha256
                release_version = $bundle.ReleaseVersion
                archive_sha256 = $bundle.ArchiveSha256
                manifest_sha256 = $bundle.ManifestSha256
            }
        }
        else {
            [ordered]@{ root = $null; metadata_sha256 = $null; release_version = $null; archive_sha256 = $null; manifest_sha256 = $null }
        }
        chrome = [ordered]@{
            pid = $chromeProcessId
            started_at = $chromeIdentity.StartTime.ToUniversalTime().ToString('o')
        }
        tunnel = [ordered]@{
            pid = $tunnel.ProcessId
            started_at = $tunnel.StartedAt.ToString('o')
            ssh_target = $SshTarget
            ssh_port = $SshPort
            wsl_distribution = if ($WslDistribution) { $WslDistribution } else { $null }
            wsl_user = if ($WslUser) { $WslUser } else { $null }
        }
        gateway = if ($gateway) {
            [ordered]@{
                pid = $gateway.ProcessId
                started_at = $gateway.StartedAt.ToString('o')
                policy_sha256 = $gateway.PolicyDigest
                proxy_port = $gatewayProxyPort
                status_port = $gatewayStatusPort
                program_path = $gatewayProgram
                policy_path = $gatewayPolicy
            }
        }
        else {
            $null
        }
    }
    $ownershipPath = Join-Path $profilePath 'rookery-external-processes.json'
    if (Test-Path -LiteralPath $ownershipPath) {
        $ownershipItem = Get-Item -LiteralPath $ownershipPath -Force
        if ($ownershipItem.PSIsContainer -or ($ownershipItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'The ownership record path is not a regular local file.'
        }
    }
    $ownershipTemporary = $ownershipPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $ownershipJson = $ownership | ConvertTo-Json -Depth 6 -Compress
    [System.IO.File]::WriteAllText(
        $ownershipTemporary,
        $ownershipJson + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $ownershipTemporary -Destination $ownershipPath -Force
    $ownershipTemporary = $null
}
catch {
    $failure = $_
    if ($ownershipTemporary -and (Test-Path -LiteralPath $ownershipTemporary)) {
        try { Remove-Item -LiteralPath $ownershipTemporary -Force } catch { }
    }
    if ($tunnel) {
        try { Stop-NewTunnelProcess -Tunnel $tunnel } catch { }
    }
    if ($createdChrome) {
        try { Stop-NewChromeProcess -Chrome $createdChrome -CdpPort $Port -ProfilePath $profilePath -ProxyPort $proxyPort } catch { }
    }
    if ($gateway -and $gateway.Created) {
        try { Stop-NewGatewayProcess -Gateway $gateway -GatewayProgram $gatewayProgram -PolicyPath $gatewayPolicy -ProxyPort $gatewayProxyPort -StatusPort $gatewayStatusPort } catch { }
    }
    throw $failure
}
[pscustomobject]@{
    cdp_port = $Port
    chrome_pid = $chromeProcessId
    chrome_started_at = $ownership.chrome.started_at
    ssh_pid = $tunnel.ProcessId
    ssh_started_at = $ownership.tunnel.started_at
    ssh_stderr_log = $tunnel.ErrorLog
    gateway_pid = if ($gateway) { $gateway.ProcessId } else { $null }
    gateway_proxy_port = if ($gateway) { $gatewayProxyPort } else { $null }
    gateway_status_port = if ($gateway) { $gatewayStatusPort } else { $null }
    gateway_started_at = if ($gateway) { $ownership.gateway.started_at } else { $null }
    ownership_record = $ownershipPath
} | ConvertTo-Json -Compress | Write-Output
