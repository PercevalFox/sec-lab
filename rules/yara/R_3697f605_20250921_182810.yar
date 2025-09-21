rule R_3697f605_20250921_182810 {
  meta:
    author = "sec-lab"
    created = "20250921_182810"
    ref = "lab"
  strings:
    $a = { 0F 71 3B 32 C2 78 21 A8 }
  condition:
    all of them
}
