rule R_4b7500d4_20250902_002342 {
  meta:
    author = "sec-lab"
    created = "20250902_002342"
    ref = "lab"
  strings:
    $a = { 50 CD 5B 45 7D E4 9F CD }
  condition:
    all of them
}
