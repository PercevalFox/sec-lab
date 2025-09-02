rule R_22f80899_20250902_131049 {
  meta:
    author = "sec-lab"
    created = "20250902_131049"
    ref = "lab"
  strings:
    $a = { 46 FA 9E 17 99 D7 B1 A7 }
  condition:
    all of them
}
