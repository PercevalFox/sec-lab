rule R_14f94e3b_20250903_084640 {
  meta:
    author = "sec-lab"
    created = "20250903_084640"
    ref = "lab"
  strings:
    $a = { 3C A4 91 2F D8 9D DE 3C }
  condition:
    all of them
}
