rule R_ed3a8d1c_20250905_033239 {
  meta:
    author = "sec-lab"
    created = "20250905_033239"
    ref = "lab"
  strings:
    $a = { A8 45 9E D9 C3 B6 87 68 }
  condition:
    all of them
}
