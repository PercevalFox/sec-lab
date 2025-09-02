rule R_14739c60_20250902_110134 {
  meta:
    author = "sec-lab"
    created = "20250902_110134"
    ref = "lab"
  strings:
    $a = { 1C CD EB 37 15 73 4E 8D }
  condition:
    all of them
}
