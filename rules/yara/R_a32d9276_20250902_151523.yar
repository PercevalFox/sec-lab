rule R_a32d9276_20250902_151523 {
  meta:
    author = "sec-lab"
    created = "20250902_151523"
    ref = "lab"
  strings:
    $a = { 65 3F EF 92 B9 4E 25 05 }
  condition:
    all of them
}
