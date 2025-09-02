rule R_1579bb2d_20250902_103309 {
  meta:
    author = "sec-lab"
    created = "20250902_103309"
    ref = "lab"
  strings:
    $a = { CF 2A 34 AA 76 32 BB D7 }
  condition:
    all of them
}
