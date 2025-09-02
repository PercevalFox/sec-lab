rule R_fec74806_20250902_112553 {
  meta:
    author = "sec-lab"
    created = "20250902_112553"
    ref = "lab"
  strings:
    $a = { 8A E9 F9 2A 45 6F 67 67 }
  condition:
    all of them
}
