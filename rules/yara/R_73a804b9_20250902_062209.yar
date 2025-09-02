rule R_73a804b9_20250902_062209 {
  meta:
    author = "sec-lab"
    created = "20250902_062209"
    ref = "lab"
  strings:
    $a = { C3 02 D5 1A 26 3A 1D 72 }
  condition:
    all of them
}
