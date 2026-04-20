# DnsWireProtocol.Tests.ps1
# Pester 5 tests for the DoH/DoT wire-protocol module. Network tests are
# tagged 'Network' so they can be skipped offline (Invoke-Pester -ExcludeTag Network).

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'DnsWireProtocol.psm1'
    Import-Module $ModulePath -Force -DisableNameChecking
}

Describe 'New-DnsWireQuery' {
    It 'produces a 29-byte query for example.com A' {
        $bytes = New-DnsWireQuery -Name 'example.com' -Type A
        $bytes.Length | Should -Be 29
    }

    It 'sets the QDCOUNT field to 1' {
        $bytes = New-DnsWireQuery -Name 'example.com' -Type A
        ([int]$bytes[4] -shl 8) -bor [int]$bytes[5] | Should -Be 1
    }

    It 'sets the recursion-desired flag' {
        $bytes = New-DnsWireQuery -Name 'example.com' -Type A
        ($bytes[2] -band 0x01) | Should -Be 1
    }

    It 'encodes QTYPE=AAAA (28) for AAAA queries' {
        $bytes = New-DnsWireQuery -Name 'example.com' -Type AAAA
        # QTYPE is the last 4 bytes minus QCLASS (last 2). So bytes[-4..-3].
        $qtype = ([int]$bytes[-4] -shl 8) -bor [int]$bytes[-3]
        $qtype | Should -Be 28
    }

    It 'rejects a label longer than 63 octets' {
        $tooLong = ('a' * 64) + '.com'
        { New-DnsWireQuery -Name $tooLong -Type A } | Should -Throw '*63 octets*'
    }
}

Describe 'Get-DnsResponseHeader' {
    It 'returns Rcode=0 and AnswerCount=1 for a NOERROR / 1-answer header' {
        # 12-byte minimal header: ID=0x1234, flags=0x8180, QD=1, AN=1, NS=0, AR=0
        $hdr = [byte[]]@(0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00)
        $r = Get-DnsResponseHeader -Bytes $hdr
        $r.Rcode | Should -Be 0
        $r.AnswerCount | Should -Be 1
        $r.Truncated | Should -BeFalse
    }

    It 'detects the truncation flag' {
        # Same header with TC bit (0x02) set in flags1
        $hdr = [byte[]]@(0x12,0x34, 0x83,0x80, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00)
        (Get-DnsResponseHeader -Bytes $hdr).Truncated | Should -BeTrue
    }

    It 'reports Rcode=3 for NXDOMAIN' {
        $hdr = [byte[]]@(0x00,0x00, 0x81,0x83, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00)
        (Get-DnsResponseHeader -Bytes $hdr).Rcode | Should -Be 3
    }

    It 'returns -1 for a runt response (<12 bytes)' {
        (Get-DnsResponseHeader -Bytes ([byte[]]@(0x00,0x01))).Rcode | Should -Be -1
    }
}

Describe 'Test-DoHQuery' -Tag 'Network' {
    It 'resolves example.com via Cloudflare DoH' {
        $r = Test-DoHQuery -Url 'https://cloudflare-dns.com/dns-query' -Domain 'example.com' -TimeoutMs 6000
        $r.Success | Should -BeTrue
        $r.Rcode | Should -Be 0
        $r.AnswerCount | Should -BeGreaterThan 0
        $r.ResponseTimeMs | Should -BeGreaterThan 0
    }
}

Describe 'Test-DoTQuery' -Tag 'Network' {
    It 'resolves example.com via Cloudflare DoT' {
        $r = Test-DoTQuery -ServerIP '1.1.1.1' -Hostname 'cloudflare-dns.com' -Domain 'example.com' -TimeoutMs 6000
        $r.Success | Should -BeTrue
        $r.Rcode | Should -Be 0
        $r.AnswerCount | Should -BeGreaterThan 0
        $r.ResponseTimeMs | Should -BeGreaterThan 0
    }

    It 'fails fast on an unreachable port' {
        # 192.0.2.0/24 is TEST-NET-1, not routable
        $r = Test-DoTQuery -ServerIP '192.0.2.1' -Hostname 'cloudflare-dns.com' -Domain 'example.com' -TimeoutMs 1500
        $r.Success | Should -BeFalse
    }
}
