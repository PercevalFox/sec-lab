rule R_4b46b947_20250902_130812 {
  meta:
    author = "sec-lab"
    created = "20250902_130812"
    ref = "lab"
  strings:
    $a = { 2B 42 21 1C 5E DA F5 F5 }
  condition:
    all of them
}
