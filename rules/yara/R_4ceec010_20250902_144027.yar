rule R_4ceec010_20250902_144027 {
  meta:
    author = "sec-lab"
    created = "20250902_144027"
    ref = "lab"
  strings:
    $a = { 75 E5 54 ED 7A D1 12 64 }
  condition:
    all of them
}
