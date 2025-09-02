rule R_cb100685_20250902_111248 {
  meta:
    author = "sec-lab"
    created = "20250902_111248"
    ref = "lab"
  strings:
    $a = { D0 D7 22 65 D7 6F 54 72 }
  condition:
    all of them
}
