rule R_ed4fd0a9_20250902_072804 {
  meta:
    author = "sec-lab"
    created = "20250902_072804"
    ref = "lab"
  strings:
    $a = { CB 01 DD 9D 63 93 9B 5C }
  condition:
    all of them
}
