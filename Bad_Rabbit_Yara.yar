rule BadRabbit_Gen {
   meta:
      description = "Règles pour BadRabbit"
      author = "@ntaff"
      date = "2020-01-23"
      
      /* dispci.exe */
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
      
      /* infpub.dat */
      hash2 = "579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"
      
      /* flash_player.exe */
      hash3 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
      
   strings:
      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
      $x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
      $x3 = "C:\\Windows\\infpub.dat" fullword wide
      $x4 = "C:\\Windows\\cscc.dat" fullword wide

      $s1 = "\\\\.\\pipe\\%ws" fullword wide
      $s2 = "fsutil usn deletejournal /D %c:" fullword wide
      $s3 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
      $s4 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s5 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
      
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 2 of them )
}