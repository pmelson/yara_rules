rule meterpreter_pe_stager {
  meta:
    description = "Detect shellcode bytes common in Meterpreter PE stagers"
    author = "Paul Melson @pmelson"
    hash = "c626985292bc2017ea7d363af9ce032482194895b3575ec4ec96746832f483d5"
  strings:
    $cld_x86 = { fc e8 (82 | 89 ) 00 00 00 60 89 }
    $cld_x64 = { fc 48 83 e4 f0 e8 }
    $opcode_x86_wininet_HttpOpenRequestA = { 68 eb 55 2e 3b ff d5 }
    $opcode_x86_ws2_32_connect = { 68 99 a5 74 61 ff d5 }
    $opcode_x86_ws2_32_bind = { 68 c2 db 37 67 ff d5 }
    $opcode_x64_wininet_HttpOpenRequestA = { c7 c2 eb 55 2e 3b ff d5 }
    $opcode_x64_ws2_32_connect = { ba 99 a5 74 61 ff d5 }
  condition:
    filesize < 8KB and
    filesize > 4KB and
    uint16be(0) == 0x4d5a and
    ( $cld_x86 and any of ($opcode_x86*) ) or
    ( $cld_x64 and any of ($opcode_x64*) )
}
