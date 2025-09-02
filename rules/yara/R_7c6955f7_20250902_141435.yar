rule R_7c6955f7_20250902_141435 {
  meta:
    author = "sec-lab"
    created = "20250902_141435"
    ref = "lab"
  strings:
    $a = { 05 56 A9 F5 DF 87 6A 34 }
  condition:
    all of them
}
