rule R_760c3dd8_20250922_132010 {
  meta:
    author = "sec-lab"
    created = "20250922_132010"
    ref = "lab"
  strings:
    $a = { 44 A4 BC DE B8 3C 03 D7 }
  condition:
    all of them
}
