rule R_f834241d_20250902_120919 {
  meta:
    author = "sec-lab"
    created = "20250902_120919"
    ref = "lab"
  strings:
    $a = { 71 92 FA 03 B2 2B 55 87 }
  condition:
    all of them
}
