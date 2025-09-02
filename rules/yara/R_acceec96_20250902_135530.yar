rule R_acceec96_20250902_135530 {
  meta:
    author = "sec-lab"
    created = "20250902_135530"
    ref = "lab"
  strings:
    $a = { FF B0 C4 E9 8A 2C 07 05 }
  condition:
    all of them
}
