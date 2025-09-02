rule R_d1d9cb5e_20250902_150621 {
  meta:
    author = "sec-lab"
    created = "20250902_150621"
    ref = "lab"
  strings:
    $a = { C3 BB 70 42 79 DC DE 4F }
  condition:
    all of them
}
