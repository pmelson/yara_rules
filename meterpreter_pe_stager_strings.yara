rule Meterpreter_PE_stager_strings {
  meta:
    description = "Detect default Meterpeter stager strings"
    author = "Paul Melson @pmelson"
    hash = "c626985292bc2017ea7d363af9ce032482194895b3575ec4ec96746832f483d5"
  strings:
    $apache_bench = "ApacheBench"
    $defaultpdb = "\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb"
    $payload = "PAYLOAD"
  condition:
    uint16be(0) == 0x4d5a and
    ( $apache_bench or $payload or $defaultpdb )
}
