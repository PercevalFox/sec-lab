rule R_b6db8cd9_20250902_052754 {
  meta:
    author = "sec-lab"
    created = "20250902_052754"
    ref = "lab"
  strings:
    $a = { F6 9C 1F 6D 08 3E DC 77 }
  condition:
    all of them
}
