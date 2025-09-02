rule R_bba74294_20250902_110948 {
  meta:
    author = "sec-lab"
    created = "20250902_110948"
    ref = "lab"
  strings:
    $a = { 09 BB 48 55 16 2A 63 39 }
  condition:
    all of them
}
