rule R_c3a3f95f_20250902_105833 {
  meta:
    author = "sec-lab"
    created = "20250902_105833"
    ref = "lab"
  strings:
    $a = { D7 88 E0 ED 53 5E 3E 9A }
  condition:
    all of them
}
