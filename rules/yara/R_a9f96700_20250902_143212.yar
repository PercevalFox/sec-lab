rule R_a9f96700_20250902_143212 {
  meta:
    author = "sec-lab"
    created = "20250902_143212"
    ref = "lab"
  strings:
    $a = { 75 AE 4E 52 A0 2A C8 24 }
  condition:
    all of them
}
