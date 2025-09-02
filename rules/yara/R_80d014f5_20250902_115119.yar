rule R_80d014f5_20250902_115119 {
  meta:
    author = "sec-lab"
    created = "20250902_115119"
    ref = "lab"
  strings:
    $a = { A4 83 2A 4E D6 70 F5 B4 }
  condition:
    all of them
}
