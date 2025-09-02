rule R_c9572da9_20250902_111418 {
  meta:
    author = "sec-lab"
    created = "20250902_111418"
    ref = "lab"
  strings:
    $a = { 71 D2 F5 6F 29 8D 53 B1 }
  condition:
    all of them
}
