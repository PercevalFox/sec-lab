rule R_519151a1_20250902_074321 {
  meta:
    author = "sec-lab"
    created = "20250902_074321"
    ref = "lab"
  strings:
    $a = { 71 6E FD 46 1A 82 67 7D }
  condition:
    all of them
}
