rule R_76c3b5f8_20250902_113645 {
  meta:
    author = "sec-lab"
    created = "20250902_113645"
    ref = "lab"
  strings:
    $a = { 6F DD 74 76 B1 FB 5B DF }
  condition:
    all of them
}
