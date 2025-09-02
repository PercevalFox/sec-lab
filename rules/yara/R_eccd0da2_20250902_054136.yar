rule R_eccd0da2_20250902_054136 {
  meta:
    author = "sec-lab"
    created = "20250902_054136"
    ref = "lab"
  strings:
    $a = { 35 74 4D A8 B5 68 8D F9 }
  condition:
    all of them
}
