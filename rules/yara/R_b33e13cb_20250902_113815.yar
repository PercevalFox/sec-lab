rule R_b33e13cb_20250902_113815 {
  meta:
    author = "sec-lab"
    created = "20250902_113815"
    ref = "lab"
  strings:
    $a = { CE A8 0C F0 3A E0 B5 73 }
  condition:
    all of them
}
