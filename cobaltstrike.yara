import "pe"
import "math"

rule CobaltStrike_Beacon_DLL
{
    meta:
        description = "Cobalt Strike Beacon DLL (x86/x64) based on PE structure and import profile"
        author = "Paul Melson (pmelson)"
        date = "2026-10-21"
        reference_sample = "0193c6130fc55895ff42dd9d08aa785067ccd56e3aabf6c2e15e26922ba09a8b"

    condition:
        pe.is_dll() and

        // Unique imports: SMB pipe listener, thread hijack, host recon
        pe.imports("kernel32.dll", "ConnectNamedPipe") and
        pe.imports("kernel32.dll", "SetThreadContext") and
        pe.imports("kernel32.dll", "GetComputerNameA") and

        // Process injection
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread") and

        // TCP bind/connect beacon
        pe.imports("ws2_32.dll", "WSAStartup") and
        pe.imports("ws2_32.dll", "connect") and
        pe.imports("ws2_32.dll", "bind") and
        pe.imports("ws2_32.dll", "listen") and

        // No resource section / version info
        pe.number_of_resources == 0 and

        // IMAGE_FILE_BYTES_REVERSED_HI set in FileHeader.Characteristics
        pe.characteristics & pe.BYTES_REVERSED_HI and

        // Code makes up more than half the image (observed 0.545 - 0.599)
        pe.size_of_code * 2 > pe.size_of_image
}
