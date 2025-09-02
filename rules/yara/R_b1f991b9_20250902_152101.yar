rule R_b1f991b9_20250902_152101 {
  meta:
    author = "sec-lab"
    created = "20250902_152101"
    ref = "lab"
  strings:
    $a = { D1 DD A5 D6 82 50 9F E6 }
  condition:
    all of them
}
