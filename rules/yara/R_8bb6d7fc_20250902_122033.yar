rule R_8bb6d7fc_20250902_122033 {
  meta:
    author = "sec-lab"
    created = "20250902_122033"
    ref = "lab"
  strings:
    $a = { 18 E9 ED A5 C4 84 11 BE }
  condition:
    all of them
}
