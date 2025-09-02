rule R_16857770_20250902_110519 {
  meta:
    author = "sec-lab"
    created = "20250902_110519"
    ref = "lab"
  strings:
    $a = { F0 9F 5A 2A DF 9D E8 33 }
  condition:
    all of them
}
