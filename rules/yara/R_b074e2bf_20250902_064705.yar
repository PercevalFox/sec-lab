rule R_b074e2bf_20250902_064705 {
  meta:
    author = "sec-lab"
    created = "20250902_064705"
    ref = "lab"
  strings:
    $a = { 6F 1D 2D 40 E6 53 3E A6 }
  condition:
    all of them
}
