rule R_360032b6_20250902_123449 {
  meta:
    author = "sec-lab"
    created = "20250902_123449"
    ref = "lab"
  strings:
    $a = { 86 8D C7 0D 69 A1 A4 26 }
  condition:
    all of them
}
