rule R_f56012a5_20250902_133020 {
  meta:
    author = "sec-lab"
    created = "20250902_133020"
    ref = "lab"
  strings:
    $a = { 08 10 81 F1 3B D5 AF B0 }
  condition:
    all of them
}
