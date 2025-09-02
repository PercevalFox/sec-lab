rule R_3f476950_20250902_115333 {
  meta:
    author = "sec-lab"
    created = "20250902_115333"
    ref = "lab"
  strings:
    $a = { BC 13 08 01 1B B6 69 C4 }
  condition:
    all of them
}
