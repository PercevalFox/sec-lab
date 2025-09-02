rule R_96d312a4_20250902_072550 {
  meta:
    author = "sec-lab"
    created = "20250902_072550"
    ref = "lab"
  strings:
    $a = { C3 D5 00 E0 7B 64 B3 54 }
  condition:
    all of them
}
