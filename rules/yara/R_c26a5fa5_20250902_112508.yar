rule R_c26a5fa5_20250902_112508 {
  meta:
    author = "sec-lab"
    created = "20250902_112508"
    ref = "lab"
  strings:
    $a = { D2 24 43 25 F3 D1 08 A9 }
  condition:
    all of them
}
