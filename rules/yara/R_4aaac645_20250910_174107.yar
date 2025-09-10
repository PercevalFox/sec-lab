rule R_4aaac645_20250910_174107 {
  meta:
    author = "sec-lab"
    created = "20250910_174107"
    ref = "lab"
  strings:
    $a = { 49 4C 8F 78 63 61 06 48 }
  condition:
    all of them
}
