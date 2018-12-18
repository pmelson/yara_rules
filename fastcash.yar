rule fastcash_aix_injector {
  meta:
    author = "Paul Melson @pmelson"
    description = "HIDDEN COBRA AIX FastCash process injection tool"
    reference = "https://www.us-cert.gov/ncas/alerts/TA18-275A"
    reference = "https://github.com/fboldewin/FastCashMalwareDissected/"
    sample_sha256 = "d465637518024262c063f4a82d799a4e40ff3381014972f24ea18bc23c3b27ee"
  strings:
    $file_eng64 = "/tmp/.ICE-unix/TMPENG%X.dat"
    $file_config = "/tmp/.ICE-unix/config_%d"
    $file_dumpfile = "/tmp/.ICE-unix/DUMP%X.dat"
    $msg0 = "[proc_writememory] ret=%d, err=%d(%s), addr=%p, len=%d, data=%p"
    $msg1 = "[main] Inject Start"
    $msg2 = "[main] SAVE REGISTRY"
    $msg3 = "[main] proc_readmemory fail"
    $msg4 = "[main] Exec func(%llX) OK"
    $msg5 = "[main] Exec func(%llX) fail ret=%X"
    $msg6 = "[main] Inject OK(%llX)"
    $msg7 = "[main] Inject fail ret=%llX"
    $msg8 = "[main] Eject OK"
    $msg9 = "[main] Eject fail ret=%llX"
    $symbol00 = "_GLOBAL__FI_eng64"
    $symbol01 = "_GLOBAL__FD_eng64"
    $symbol02 = "proc_attach"
    $symbol03 = "proc_detach"
    $symbol04 = "proc_continue"
    $symbol05 = "proc_wait"
    $symbol06 = "proc_fault"
    $symbol07 = "proc_getregs"
    $symbol08 = "proc_setregs"
    $symbol09 = "proc_readmemory"
    $symbol10 = "proc_writememory"
    $symbol11 = "inject"
    $symbol12 = "_$STATIC"
    $source0 = "/tmp//cchXKsHV.c"
    $source1 = "/tmp/tmp/eng64.c"
  condition:
    uint16(0) == 0xf701 and (all of ($file*) or all of ($msg*) or all of ($symbol*) or all of ($source*))
}

rule fastcash_aix_iso8583 {
  meta:
    author = "Paul Melson @pmelson"
    description = "HIDDEN COBRA AIX FastCash ISO8583 module (may not be malicious, low attribution confidence)"
    reference = "https://www.us-cert.gov/ncas/alerts/TA18-275A"
    reference = "https://github.com/fboldewin/FastCashMalwareDissected/"
    sample_sha256 = "3a5ba44f140821849de2d82d5a137c3bb5a736130dddb86b296d94e6b421594c"
    sample_sha256 = "ca9ab48d293cc84092e8db8f0ca99cb155b30c61d32a1da7cd3687de454fe86c"
    sample_sha256 = "10ac312c8dd02e417dd24d53c99525c29d74dcbc84730351ad7a4e0a4b1a0eba"
  strings:
    $symbol0 = "msg_to_file"
    $symbol1 = "msg_to_file_recv"
    $symbol2 = "msg_to_file_send"
    $symbol3 = "DetourInitFunc"
    $symbol4 = "DetourAttach"
    $symbol5 = "DetourDetach"
    $symbol6 = "CheckPan"
    $symbol7 = "BlacklistCheck"
    $aschex0 = "DL_ASCHEX_TO_UINT32"
    $aschex1 = "DL_UINT32_TO_ASCHEX"
    $aschex2 = "_pack_iso_ASCHEX"
    $aschex3 = "_unpack_iso_ASCHEX"
    $iso00 = "DL_ISO8583_MSG_Init"
    $iso01 = "DL_ISO8583_MSG_Free"
    $iso02 = "DL_ISO8583_MSG_SetField_Str"
    $iso03 = "DL_ISO8583_MSG_SetField_Bin"
    $iso04 = "DL_ISO8583_MSG_RemoveField"
    $iso05 = "DL_ISO8583_MSG_HaveField"
    $iso06 = "DL_ISO8583_MSG_GetField_Str"
    $iso07 = "DL_ISO8583_MSG_GetField_Bin"
    $iso08 = "DL_ISO8583_MSG_Pack"
    $iso09 = "DL_ISO8583_MSG_Unpack"
    $iso10 = "_DL_ISO8583_MSG_AllocField"
    $iso11 = "DL_ISO8583_COMMON_SetHandler"
    $iso12 = "DL_ISO8583_DEFS_1987_GetHandler"
    $iso13 = "DL_ISO8583_DEFS_1993_GetHandler"
    $iso14 = "_DL_ISO8583_FIELD_Pack"
    $iso15 = "_DL_ISO8583_FIELD_Unpack"
    $iso16 = "DL_ISO8583_MSG_Dump"
    $iso17 = "_iso8583_1987_fields"
    $iso18 = "_iso8583_1993_fields"
  condition:
    uint16(0) == 0xf701 and (all of ($symbol*) or all of ($aschex*) or all of ($iso*))
}

rule fastcash_aix_pvpa {
  meta:
    author = "Paul Melson @pmelson"
    description = "HIDDEN COBRA AIX FastCash pvpa binary (may not be malicious, low attribution confidence)"
    reference = "https://www.us-cert.gov/ncas/alerts/TA18-275A"
    reference = "https://github.com/fboldewin/FastCashMalwareDissected/"
    sample_sha256 = "f3e521996c85c0cdb2bfb3a0fd91eb03e25ba6feef2ba3a1da844f1b17278dd2"
  strings:
    $symbol_static = { 00 5f 24 53 54 41 54 49 43 00 }
    $symbol_pvpa = { 00 00 00 00 70 76 70 61 00 00 00 00 }
    $symbol_get_pvpa = { 00 2e 67 65 74 5f 70 76 70 61 00 }
    $symbol_get_posn = { 00 2e 73 65 74 5f 70 6f 73 6e 00 }
    $symbol_init_pvpa = { 00 2e 69 6e 69 74 5f 70 76 70 61 00 }
    $string0 = "/dev/mem"
    $string1 = "set_posn"
    $string2 = "get_pvpa"
    $string3 = "init_pvpa"
    $string4 = "high_cpuid=%d"
    $string5 = "open kernel mem"
    $string6 = "cpu %d, old value = 0x%02x"
    $string7 = "Usage: pvpa [<new_value> <old_value>]"
    $string8 = "Invalid PVPA read, magic = 0x%08x, len = %d, cpu = %d"
  condition:
    uint16(0) == 0xf701 and (all of ($symbol*) or all of ($string*))
}
