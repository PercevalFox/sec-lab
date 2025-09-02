rule R_c3e95491_20250902_060354 {
  meta:
    author = "sec-lab"
    created = "20250902_060354"
    ref = "lab"
  strings:
    $a = { 9C B1 1D 50 C9 85 55 5E }
  condition:
    all of them
}
