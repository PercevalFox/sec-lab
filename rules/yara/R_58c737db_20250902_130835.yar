rule R_58c737db_20250902_130835 {
  meta:
    author = "sec-lab"
    created = "20250902_130835"
    ref = "lab"
  strings:
    $a = { D9 F6 47 28 70 4C 4E C8 }
  condition:
    all of them
}
