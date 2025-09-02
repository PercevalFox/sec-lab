rule R_bbd72cbf_20250902_114950 {
  meta:
    author = "sec-lab"
    created = "20250902_114950"
    ref = "lab"
  strings:
    $a = { 1A 38 F7 93 D9 99 AD 3A }
  condition:
    all of them
}
