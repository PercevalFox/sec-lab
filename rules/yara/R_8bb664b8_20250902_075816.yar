rule R_8bb664b8_20250902_075816 {
  meta:
    author = "sec-lab"
    created = "20250902_075816"
    ref = "lab"
  strings:
    $a = { E3 09 63 1A FE B0 1C 7C }
  condition:
    all of them
}
