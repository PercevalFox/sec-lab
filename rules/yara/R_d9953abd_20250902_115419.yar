rule R_d9953abd_20250902_115419 {
  meta:
    author = "sec-lab"
    created = "20250902_115419"
    ref = "lab"
  strings:
    $a = { 8F 32 3E 12 5B 5E 1E 58 }
  condition:
    all of them
}
