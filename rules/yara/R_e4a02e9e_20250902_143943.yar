rule R_e4a02e9e_20250902_143943 {
  meta:
    author = "sec-lab"
    created = "20250902_143943"
    ref = "lab"
  strings:
    $a = { A5 3B 69 73 E7 11 17 D7 }
  condition:
    all of them
}
