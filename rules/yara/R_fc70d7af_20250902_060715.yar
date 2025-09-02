rule R_fc70d7af_20250902_060715 {
  meta:
    author = "sec-lab"
    created = "20250902_060715"
    ref = "lab"
  strings:
    $a = { 84 BD BA 95 4B 1A E2 BB }
  condition:
    all of them
}
