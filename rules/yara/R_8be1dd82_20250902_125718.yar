rule R_8be1dd82_20250902_125718 {
  meta:
    author = "sec-lab"
    created = "20250902_125718"
    ref = "lab"
  strings:
    $a = { 07 B8 0E A2 F1 E9 9B E8 }
  condition:
    all of them
}
