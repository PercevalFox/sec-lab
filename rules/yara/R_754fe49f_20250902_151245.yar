rule R_754fe49f_20250902_151245 {
  meta:
    author = "sec-lab"
    created = "20250902_151245"
    ref = "lab"
  strings:
    $a = { 17 6F 1D 76 E8 6A E2 42 }
  condition:
    all of them
}
