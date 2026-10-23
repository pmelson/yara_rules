import "pe"

rule Ransomware_GandCrab_ManualNote_KrabStub
{
    meta:
        description = "GandCrab-style ransomware: drops a '-MANUAL.txt' ransom note (wide/UTF-16LE string) and references a fake krab5.dll import name"
        family = "GandCrab"
        author = "Paul Melson (@pmelson)"
        date = "2026-10-21"
        reference_hashes = "882844bd5e694b96cdebdf63de669605630933f785bb2b2bd16c67319cfede87, c771bc42e06487d49ae3763e0c96d3461d3f990d5426acaaf99da777cb4c7319"

    strings:
        $note1 = "-MANUAL.txt" wide
        $note2 = "%s\\%s-MANUAL.txt" wide
        $dll   = "krab5.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and 2 of ($note1, $note2, $dll)
}
