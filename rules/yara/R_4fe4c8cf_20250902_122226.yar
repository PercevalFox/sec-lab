rule R_4fe4c8cf_20250902_122226 {
  meta:
    author = "sec-lab"
    created = "20250902_122226"
    ref = "lab"
  strings:
    $a = { A2 F2 68 97 C7 04 F3 B7 }
  condition:
    all of them
}
