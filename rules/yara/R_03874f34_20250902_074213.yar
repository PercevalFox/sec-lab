rule R_03874f34_20250902_074213 {
  meta:
    author = "sec-lab"
    created = "20250902_074213"
    ref = "lab"
  strings:
    $a = { 99 0E 44 AC 94 E7 7B D0 }
  condition:
    all of them
}
