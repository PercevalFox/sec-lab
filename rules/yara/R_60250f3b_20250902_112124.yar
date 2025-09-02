rule R_60250f3b_20250902_112124 {
  meta:
    author = "sec-lab"
    created = "20250902_112124"
    ref = "lab"
  strings:
    $a = { D0 DB 0E 7B AA 41 75 DA }
  condition:
    all of them
}
