rule R_c8f2604d_20250902_053349 {
  meta:
    author = "sec-lab"
    created = "20250902_053349"
    ref = "lab"
  strings:
    $a = { D7 22 7F 16 99 DB 1F C4 }
  condition:
    all of them
}
