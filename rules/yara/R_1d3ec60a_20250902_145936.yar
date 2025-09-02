rule R_1d3ec60a_20250902_145936 {
  meta:
    author = "sec-lab"
    created = "20250902_145936"
    ref = "lab"
  strings:
    $a = { F2 F8 C7 48 D8 5C 8F F2 }
  condition:
    all of them
}
