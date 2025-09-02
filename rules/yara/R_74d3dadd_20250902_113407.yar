rule R_74d3dadd_20250902_113407 {
  meta:
    author = "sec-lab"
    created = "20250902_113407"
    ref = "lab"
  strings:
    $a = { C1 88 23 F6 2C C4 48 9D }
  condition:
    all of them
}
