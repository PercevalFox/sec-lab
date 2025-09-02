rule R_242f15c1_20250902_134654 {
  meta:
    author = "sec-lab"
    created = "20250902_134654"
    ref = "lab"
  strings:
    $a = { 9D 32 AC 12 15 B9 8A D6 }
  condition:
    all of them
}
