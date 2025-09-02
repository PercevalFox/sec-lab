rule R_b006149a_20250902_141305 {
  meta:
    author = "sec-lab"
    created = "20250902_141305"
    ref = "lab"
  strings:
    $a = { BF D5 AC CE E0 F2 34 C3 }
  condition:
    all of them
}
