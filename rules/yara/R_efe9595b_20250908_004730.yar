rule R_efe9595b_20250908_004730 {
  meta:
    author = "sec-lab"
    created = "20250908_004730"
    ref = "lab"
  strings:
    $a = { 2D 8E DD 90 88 53 2D 42 }
  condition:
    all of them
}
