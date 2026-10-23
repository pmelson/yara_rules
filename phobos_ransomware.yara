import "pe"

rule Ransomware_Phobos_NetShare_WinHTTP_TokenDup
{
    meta:
        description = "Phobos-style ransomware: enumerates/mounts network shares via WNet* APIs, duplicates process tokens, enumerates processes, and talks to a C2 over WinHTTP"
        author = "Paul Melson (@pmelson)"
        date = "2026-10-21"
        family = "Phobos"
        reference_hashes = "2dcaca208625860f4eb114af4c4158368284eb99c994793d5ac66d3af654bf5f, 5470c14af0710ffde36d775b089496825c38ae33d6ae6dd04140e1d78c4d46d6"

    strings:
        $wnet1 = "WNetEnumResourceW" ascii
        $wnet2 = "WNetUseConnectionW" ascii
        $wnet3 = "WNetOpenEnumW" ascii
        $ip    = "GetIpAddrTable" ascii
        $tok   = "DuplicateTokenEx" ascii
        $priv  = "LookupPrivilegeValueW" ascii
        $proc  = "CreateToolhelp32Snapshot" ascii
        $http  = "WinHttpOpen" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 500KB
        and 6 of ($wnet1, $wnet2, $wnet3, $ip, $tok, $priv, $proc, $http)
}
