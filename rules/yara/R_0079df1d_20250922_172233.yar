rule R_0079df1d_20250922_172233 {
  meta:
    author = "sec-lab"
    created = "20250922_172233"
    ref = "lab"
  strings:
    $a = { 5F 36 26 BC D2 E2 3A F2 }
  condition:
    all of them
}
