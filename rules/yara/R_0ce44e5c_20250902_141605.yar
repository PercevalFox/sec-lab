rule R_0ce44e5c_20250902_141605 {
  meta:
    author = "sec-lab"
    created = "20250902_141605"
    ref = "lab"
  strings:
    $a = { 92 34 F7 AE 1E 09 38 01 }
  condition:
    all of them
}
