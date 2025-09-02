rule R_39294d02_20250902_141050 {
  meta:
    author = "sec-lab"
    created = "20250902_141050"
    ref = "lab"
  strings:
    $a = { A4 BF E9 0E 54 BC 5E 5D }
  condition:
    all of them
}
