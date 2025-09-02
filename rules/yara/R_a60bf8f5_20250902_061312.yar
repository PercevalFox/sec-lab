rule R_a60bf8f5_20250902_061312 {
  meta:
    author = "sec-lab"
    created = "20250902_061312"
    ref = "lab"
  strings:
    $a = { 6C 99 0A C0 CD DD 4C A0 }
  condition:
    all of them
}
