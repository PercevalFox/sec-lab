rule R_fe3b90cb_20250905_174213 {
  meta:
    author = "sec-lab"
    created = "20250905_174213"
    ref = "lab"
  strings:
    $a = { D2 E1 2C CA 1F 13 A1 F1 }
  condition:
    all of them
}
