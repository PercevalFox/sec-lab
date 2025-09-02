rule R_f50c9036_20250902_112830 {
  meta:
    author = "sec-lab"
    created = "20250902_112830"
    ref = "lab"
  strings:
    $a = { 20 D7 20 98 D5 86 B3 F0 }
  condition:
    all of them
}
