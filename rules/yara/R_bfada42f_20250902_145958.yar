rule R_bfada42f_20250902_145958 {
  meta:
    author = "sec-lab"
    created = "20250902_145958"
    ref = "lab"
  strings:
    $a = { 56 B4 3C D0 FE 3E A6 D0 }
  condition:
    all of them
}
