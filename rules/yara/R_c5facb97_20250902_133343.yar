rule R_c5facb97_20250902_133343 {
  meta:
    author = "sec-lab"
    created = "20250902_133343"
    ref = "lab"
  strings:
    $a = { E7 B7 73 7C 0B F9 57 A7 }
  condition:
    all of them
}
