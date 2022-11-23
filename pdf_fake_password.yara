rule pdf_fake_password {
  meta:
    date = "2022-11-23"
    description = "Detects PDF obfuscated via /Encrypt and /AuthEvent/DocOpen but opens without password"
    author = "Paul Melson @pmelson"
    hash = "0e182afae5301ac3097ae3955aa8c894ec3a635acbec427d399ccc4aac3be3d6"
  strings:
    $docopen = "<</CF<</StdCF<</AuthEvent/DocOpen/" ascii
    $ownerpass = /\/Filter\/Standard\/Length (40|128|256)\/O\(/
    $userpass = "/StmF/StdCF/StrF/StdCF/U(" ascii
    $perms = { 2f 50 65 72 6d 73 28 5b 07 ec 96 e8 68 ef 35 2e 75 02 16 0f 5c 5c 22 d1 29 }
  condition:
    uint32(0) == 0x46445025 and
    all of them
}
