rule R_3a6c3257_20250902_073806 {
  meta:
    author = "sec-lab"
    created = "20250902_073806"
    ref = "lab"
  strings:
    $a = { 7D 57 4D CC 59 6C 7A E3 }
  condition:
    all of them
}
