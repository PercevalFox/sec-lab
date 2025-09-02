rule R_1b23248b_20250902_063343 {
  meta:
    author = "sec-lab"
    created = "20250902_063343"
    ref = "lab"
  strings:
    $a = { 5D 6B CD 2C F1 34 20 3C }
  condition:
    all of them
}
