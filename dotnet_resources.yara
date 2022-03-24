import "dotnet"

rule Costura_packer_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resoure names commonly used by Costura packer"
    hash01 = "0d8b85f3de3b266b4dfcd2892f4b0252b808f36cb8cdf594e225d45d0ca84f48"
    hash02 = "a717b5d3af3173ce9958a23f95269e2d8ccd8979445626342c32b398d4f08f8a"
    hash03 = "fc2f5146edf6f28c6cb06e280674dc43b5c1e85f61b7138b766b4607e907ee5b"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "costura.costura.dll.compressed" or
        item.name == "costura.iconlib.dll.compressed" or
        item.name == "costura.packetlib.dll.compressed" or
        item.name == "costura.packetlib.pdb.compressed" )
}

rule AgentTesla_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description  = "Detect .NET resource names commonly used by AgentTesla v1.x"
    hash = "e9f6784128f4f612226ffb8ff4814b88927fa281cf8b1d079b1b92198f5fcd7a"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "IELibrary.resources" or
        item.name == "firefox.resources" )
}

rule AsyncRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by AsyncRAT"
    hash = "06108b37948bfd3c26d775d93a2ff712e2739803c7eee9e7e125501a5f676f64"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Client.Helper.FormChat.resources" )
}

rule BlackWorm_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by BlackWorm"
    hash01 = "51a081ce53b7ebb49dfc7b13027bf76b3c7c71c065d71348e3e4e7c00de15b3a"
    hash02 = "6040539f0f7f57ccb6bf059112c85538868fa834c2eaf4ab2b58c796c87aaa96"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Stub.VanToMRAT.resources" or
        item.name == "Stub.Form3.resources" or
        item.name == "StubX.q.resources" or
        item.name == "StubX.w.resources" )
}

rule NanoCore_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by NanoCore"
    hash = "29591d3e7915a34c0d1c3256450bb5e2addcb3d0277d9b85954fa522909510a5"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "ClientLoaderForm.resources" )
}

rule SeafKoAgent_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by SeafKoAgent"
    hash = "29ec4267f11581ca0fd67ce7df8c360d4803e54f58a2ab299e026ec0df73771f"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "SeafkoAgent.Properties.Resources.resources" )
}

rule SpyGate_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by SpyGate"
    hash = "67ef0a996df2e829afd58bca699342c1b694e51f7f88760d361c0372cfe5311b"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "O.A.resources" or
        item.name == "O.B.resources" or
        item.name == "O.Resources.resources" )
}

rule VoidRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by VoidRAT"
    hash = "02cb13ac4e6ffb8c00669a371263e69ef388e80ee78d4219b4e3cb041fe85c30"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "xClient.Properties.Resources.resources" )
}

rule RevengeRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by Revenge RAT"
    hash01 = "02a30d48471d0e4b6b5e7313f00d5396979186849602ead52a06f1569c458b9c"
    hash02 = "517616106e4a3309f3833f48c08bd042e830bfa2de65fe3538a375cc43782b43"
    
  condition:
    for any item in dotnet.resources:
      ( item.name icontains "reveng" or
        item.name == "Form1.resources" )
}

rule njRat_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by njRat"
    hash01 = "0597ec69b22596a4c3639c9efaa8695ad534776f2f1844225129578874d0b51f"
    hash02 = "34feb3ff474a7b644f497a133a78a220a496a54fd597b097eabce803d2a6c16f"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Stub.Resources.resources" or
        item.name == "Hacking.Explorer1.resources" )
}

rule dotnet_keylogger {
  condition:
    for any item in dotnet.resources:
      (item.name icontains "Keylogger")
}
