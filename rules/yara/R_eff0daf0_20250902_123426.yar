rule R_eff0daf0_20250902_123426 {
  meta:
    author = "sec-lab"
    created = "20250902_123426"
    ref = "lab"
  strings:
    $a = { 84 0A DB CE 87 AC 57 75 }
  condition:
    all of them
}
