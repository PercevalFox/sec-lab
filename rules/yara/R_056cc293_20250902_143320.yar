rule R_056cc293_20250902_143320 {
  meta:
    author = "sec-lab"
    created = "20250902_143320"
    ref = "lab"
  strings:
    $a = { FF 7C B9 DA AD CA EC 38 }
  condition:
    all of them
}
