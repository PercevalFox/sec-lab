rule R_c5bc9fc0_20250902_152232 {
  meta:
    author = "sec-lab"
    created = "20250902_152232"
    ref = "lab"
  strings:
    $a = { 80 25 C3 3A A3 8C 78 E4 }
  condition:
    all of them
}
