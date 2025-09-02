rule R_b4e4b9ad_20250902_063855 {
  meta:
    author = "sec-lab"
    created = "20250902_063855"
    ref = "lab"
  strings:
    $a = { DF 31 30 F2 1D D2 4E D8 }
  condition:
    all of them
}
