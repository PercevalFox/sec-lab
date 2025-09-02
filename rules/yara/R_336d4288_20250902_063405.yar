rule R_336d4288_20250902_063405 {
  meta:
    author = "sec-lab"
    created = "20250902_063405"
    ref = "lab"
  strings:
    $a = { DE 27 B4 B0 85 A4 53 AE }
  condition:
    all of them
}
