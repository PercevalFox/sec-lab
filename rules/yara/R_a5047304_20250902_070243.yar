rule R_a5047304_20250902_070243 {
  meta:
    author = "sec-lab"
    created = "20250902_070243"
    ref = "lab"
  strings:
    $a = { 15 8F 9B BB 51 01 DD 07 }
  condition:
    all of them
}
