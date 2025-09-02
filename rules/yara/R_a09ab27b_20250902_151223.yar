rule R_a09ab27b_20250902_151223 {
  meta:
    author = "sec-lab"
    created = "20250902_151223"
    ref = "lab"
  strings:
    $a = { 9C 54 8C E4 22 FA 47 6A }
  condition:
    all of them
}
