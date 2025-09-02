rule R_8c0141db_20250902_071355 {
  meta:
    author = "sec-lab"
    created = "20250902_071355"
    ref = "lab"
  strings:
    $a = { 37 F3 D9 A8 C7 0A E1 A3 }
  condition:
    all of them
}
