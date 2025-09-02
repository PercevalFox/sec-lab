rule R_f492ecc5_20250902_151114 {
  meta:
    author = "sec-lab"
    created = "20250902_151114"
    ref = "lab"
  strings:
    $a = { 6A A5 15 74 DC AE B0 E6 }
  condition:
    all of them
}
