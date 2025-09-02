rule R_68f44588_20250902_110903 {
  meta:
    author = "sec-lab"
    created = "20250902_110903"
    ref = "lab"
  strings:
    $a = { 32 FC 9F 16 6F 67 E9 84 }
  condition:
    all of them
}
