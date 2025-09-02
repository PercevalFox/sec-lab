rule R_c64b7454_20250902_134354 {
  meta:
    author = "sec-lab"
    created = "20250902_134354"
    ref = "lab"
  strings:
    $a = { 93 D7 D4 C2 15 BC 92 E6 }
  condition:
    all of them
}
