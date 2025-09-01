rule R_31c5d9dd_20250901_234613 {
  meta:
    author = "sec-lab"
    created = "20250901_234613"
    ref = "lab"
  strings:
    $a = { 38 48 46 08 94 C1 82 25 }
  condition:
    all of them
}
