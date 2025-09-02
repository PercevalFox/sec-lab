rule R_411f996e_20250902_144904 {
  meta:
    author = "sec-lab"
    created = "20250902_144904"
    ref = "lab"
  strings:
    $a = { B8 B4 4A 1C 9C ED B0 40 }
  condition:
    all of them
}
