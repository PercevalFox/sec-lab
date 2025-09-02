rule R_6baeb04c_20250902_003148 {
  meta:
    author = "sec-lab"
    created = "20250902_003148"
    ref = "lab"
  strings:
    $a = { 74 CB 07 FD 04 CC B3 92 }
  condition:
    all of them
}
