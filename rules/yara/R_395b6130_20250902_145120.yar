rule R_395b6130_20250902_145120 {
  meta:
    author = "sec-lab"
    created = "20250902_145120"
    ref = "lab"
  strings:
    $a = { 75 47 D7 75 22 2D 1B A4 }
  condition:
    all of them
}
