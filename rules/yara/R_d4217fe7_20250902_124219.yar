rule R_d4217fe7_20250902_124219 {
  meta:
    author = "sec-lab"
    created = "20250902_124219"
    ref = "lab"
  strings:
    $a = { 9A 11 FB 0F 26 2B 3B 2D }
  condition:
    all of them
}
