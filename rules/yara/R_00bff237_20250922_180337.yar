rule R_00bff237_20250922_180337 {
  meta:
    author = "sec-lab"
    created = "20250922_180337"
    ref = "lab"
  strings:
    $a = { B1 65 E0 2D B7 C5 19 F0 }
  condition:
    all of them
}
