# DnsWireProtocol.psm1
# ---------------------------------------------------------------------------
# Minimal RFC 1035 wire-format DNS query builder + DoH (RFC 8484) and
# DoT (RFC 7858) transport probes. Used by Test-DNSProviders.ps1 to benchmark
# encrypted DNS endpoints alongside classic Do53.
#
# Only the bare minimum needed for benchmarking is implemented:
#   * Build a single-question A/AAAA/TXT query
#   * POST/GET it over HTTPS to a DoH endpoint
#   * Frame and send it over a TLS-wrapped TCP/853 connection to a DoT endpoint
#   * Time the round trip; do not attempt to parse the answer beyond the header
#
# All probes are synchronous; callers wrap them in jobs/runspaces if needed.
# ---------------------------------------------------------------------------

Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

# Build a wire-format DNS query for a single name/type. Returns byte[].
function New-DnsWireQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('A','AAAA','TXT','MX','CNAME','NS','SOA')]
        [string]$Type = 'A'
    )

    $qtype = switch ($Type) {
        'A'     { 1 }
        'NS'    { 2 }
        'CNAME' { 5 }
        'SOA'   { 6 }
        'MX'    { 15 }
        'TXT'   { 16 }
        'AAAA'  { 28 }
    }

    $bytes = [System.Collections.Generic.List[byte]]::new()

    # Header (12 bytes): random ID, RD=1, QDCOUNT=1
    $id = Get-Random -Minimum 1 -Maximum 65535
    $bytes.Add([byte](($id -shr 8) -band 0xFF))
    $bytes.Add([byte]( $id        -band 0xFF))
    $bytes.AddRange([byte[]](0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00))

    # Question section: labels
    foreach ($label in $Name.Split('.')) {
        if ([string]::IsNullOrEmpty($label)) { continue }
        if ($label.Length -gt 63) { throw "Label '$label' exceeds 63 octets" }
        $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$lb.Length)
        $bytes.AddRange($lb)
    }
    $bytes.Add([byte]0) # root label

    # QTYPE / QCLASS=IN
    $bytes.Add([byte](($qtype -shr 8) -band 0xFF))
    $bytes.Add([byte]( $qtype        -band 0xFF))
    $bytes.AddRange([byte[]](0x00, 0x01))

    return ,$bytes.ToArray()
}

# Inspect the response header. Returns @{ Rcode; AnswerCount; Truncated }.
function Get-DnsResponseHeader {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Count -lt 12) { return @{ Rcode = -1; AnswerCount = 0; Truncated = $false } }
    $flags2 = $Bytes[3]
    $flags1 = $Bytes[2]
    return @{
        Rcode       = [int]($flags2 -band 0x0F)
        AnswerCount = [int](($Bytes[6] -shl 8) -bor $Bytes[7])
        Truncated   = (($flags1 -band 0x02) -ne 0)
    }
}

# DNS-over-HTTPS probe (RFC 8484). Uses GET with base64url-encoded ?dns=
# query, which is the lighter wire and is mandatory-to-support for resolvers.
function Test-DoHQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Domain,
        [string]$RecordType = 'A',
        [int]$TimeoutMs = 4000
    )

    $wire = New-DnsWireQuery -Name $Domain -Type $RecordType
    $b64  = [Convert]::ToBase64String($wire).TrimEnd('=').Replace('+','-').Replace('/','_')

    # HttpClient is preferred but not available everywhere; use HttpWebRequest
    # which works on PS5.1 + PS7.
    try {
        $req = [System.Net.HttpWebRequest]::Create("$Url`?dns=$b64")
        $req.Method            = 'GET'
        $req.Accept            = 'application/dns-message'
        $req.UserAgent         = 'dns-benchmark/1.0'
        $req.Timeout           = $TimeoutMs
        $req.ReadWriteTimeout  = $TimeoutMs
        $req.AllowAutoRedirect = $false

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = $req.GetResponse()
        try {
            if ([int]$resp.StatusCode -ne 200) {
                return @{ Success = $false; Error = "HTTP $([int]$resp.StatusCode)" }
            }
            $stream = $resp.GetResponseStream()
            $ms = [System.IO.MemoryStream]::new()
            $stream.CopyTo($ms)
            $sw.Stop()
            $body = $ms.ToArray()
            $hdr  = Get-DnsResponseHeader -Bytes $body
            return @{
                Success        = ($hdr.Rcode -eq 0 -or $hdr.Rcode -eq 3) # NOERROR or NXDOMAIN both = working resolver
                ResponseTimeMs = $sw.Elapsed.TotalMilliseconds
                Rcode          = $hdr.Rcode
                AnswerCount    = $hdr.AnswerCount
                BytesReceived  = $body.Length
            }
        } finally {
            $resp.Close()
        }
    } catch [System.Net.WebException] {
        return @{ Success = $false; Error = $_.Exception.Message }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# DNS-over-TLS probe (RFC 7858). TCP/853 + TLS handshake + 2-byte length-
# prefixed DNS message. Server certificate is validated against $Hostname.
function Test-DoTQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServerIP,
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][string]$Domain,
        [string]$RecordType = 'A',
        [int]$Port = 853,
        [int]$TimeoutMs = 4000
    )

    $wire   = New-DnsWireQuery -Name $Domain -Type $RecordType
    $framed = [byte[]]::new($wire.Length + 2)
    $framed[0] = [byte](($wire.Length -shr 8) -band 0xFF)
    $framed[1] = [byte]( $wire.Length        -band 0xFF)
    [Array]::Copy($wire, 0, $framed, 2, $wire.Length)

    $tcp = $null
    $ssl = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()

        $connectTask = $tcp.ConnectAsync($ServerIP, $Port)
        if (-not $connectTask.Wait($TimeoutMs)) {
            return @{ Success = $false; Error = 'Timeout (TCP connect)' }
        }

        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false)
        $authTask = $ssl.AuthenticateAsClientAsync($Hostname)
        if (-not $authTask.Wait($TimeoutMs)) {
            return @{ Success = $false; Error = 'Timeout (TLS handshake)' }
        }
        $ssl.ReadTimeout  = $TimeoutMs
        $ssl.WriteTimeout = $TimeoutMs

        $ssl.Write($framed, 0, $framed.Length)
        $ssl.Flush()

        # Read 2-byte length prefix
        $lenBuf = [byte[]]::new(2)
        $read = 0
        while ($read -lt 2) {
            $n = $ssl.Read($lenBuf, $read, 2 - $read)
            if ($n -le 0) { return @{ Success = $false; Error = 'Short response' } }
            $read += $n
        }
        $respLen = ([int]$lenBuf[0] -shl 8) -bor [int]$lenBuf[1]
        if ($respLen -le 0 -or $respLen -gt 65535) {
            return @{ Success = $false; Error = "Invalid response length $respLen" }
        }

        $body = [byte[]]::new($respLen)
        $total = 0
        while ($total -lt $respLen) {
            $n = $ssl.Read($body, $total, $respLen - $total)
            if ($n -le 0) { break }
            $total += $n
        }
        $sw.Stop()

        if ($total -lt $respLen) {
            return @{ Success = $false; Error = "Truncated response ($total/$respLen)" }
        }

        $hdr = Get-DnsResponseHeader -Bytes $body
        return @{
            Success        = ($hdr.Rcode -eq 0 -or $hdr.Rcode -eq 3)
            ResponseTimeMs = $sw.Elapsed.TotalMilliseconds
            Rcode          = $hdr.Rcode
            AnswerCount    = $hdr.AnswerCount
            BytesReceived  = $respLen
        }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch {} }
        if ($tcp) { try { $tcp.Dispose() } catch {} }
    }
}

Export-ModuleMember -Function New-DnsWireQuery, Get-DnsResponseHeader, Test-DoHQuery, Test-DoTQuery
