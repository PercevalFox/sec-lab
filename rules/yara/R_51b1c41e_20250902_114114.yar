rule R_51b1c41e_20250902_114114 {
  meta:
    author = "sec-lab"
    created = "20250902_114114"
    ref = "lab"
  strings:
    $a = { 43 17 30 A9 B7 BD A2 11 }
  condition:
    all of them
}
