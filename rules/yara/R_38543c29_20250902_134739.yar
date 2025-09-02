rule R_38543c29_20250902_134739 {
  meta:
    author = "sec-lab"
    created = "20250902_134739"
    ref = "lab"
  strings:
    $a = { B5 9D 36 C6 6F 8E 68 21 }
  condition:
    all of them
}
