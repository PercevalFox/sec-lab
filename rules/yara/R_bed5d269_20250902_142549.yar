rule R_bed5d269_20250902_142549 {
  meta:
    author = "sec-lab"
    created = "20250902_142549"
    ref = "lab"
  strings:
    $a = { 7A 34 9E 47 EB 90 98 D5 }
  condition:
    all of them
}
