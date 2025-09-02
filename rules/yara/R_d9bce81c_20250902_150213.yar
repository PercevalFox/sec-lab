rule R_d9bce81c_20250902_150213 {
  meta:
    author = "sec-lab"
    created = "20250902_150213"
    ref = "lab"
  strings:
    $a = { C8 A4 E8 E8 54 48 96 1B }
  condition:
    all of them
}
