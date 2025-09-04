rule R_6563f55d_20250904_154903 {
  meta:
    author = "sec-lab"
    created = "20250904_154903"
    ref = "lab"
  strings:
    $a = { 06 92 3A 24 D6 48 74 3A }
  condition:
    all of them
}
