rule R_1a06f8a0_20250902_135208 {
  meta:
    author = "sec-lab"
    created = "20250902_135208"
    ref = "lab"
  strings:
    $a = { 65 F2 FC 42 77 10 06 35 }
  condition:
    all of them
}
