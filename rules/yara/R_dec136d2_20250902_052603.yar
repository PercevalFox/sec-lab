rule R_dec136d2_20250902_052603 {
  meta:
    author = "sec-lab"
    created = "20250902_052603"
    ref = "lab"
  strings:
    $a = { DD 17 58 5B 4D 79 1B 47 }
  condition:
    all of them
}
