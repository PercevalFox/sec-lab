rule R_2a3aaba6_20250902_051900 {
  meta:
    author = "sec-lab"
    created = "20250902_051900"
    ref = "lab"
  strings:
    $a = { 48 F3 01 3C 4B 9E 0E 88 }
  condition:
    all of them
}
