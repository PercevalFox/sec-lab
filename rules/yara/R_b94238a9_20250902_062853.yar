rule R_b94238a9_20250902_062853 {
  meta:
    author = "sec-lab"
    created = "20250902_062853"
    ref = "lab"
  strings:
    $a = { F6 B3 6B FA 49 29 D1 87 }
  condition:
    all of them
}
