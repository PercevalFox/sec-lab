rule R_606f3534_20250902_072059 {
  meta:
    author = "sec-lab"
    created = "20250902_072059"
    ref = "lab"
  strings:
    $a = { 83 53 9E 02 B3 A3 E8 90 }
  condition:
    all of them
}
