rule R_e4e75322_20250909_113926 {
  meta:
    author = "sec-lab"
    created = "20250909_113926"
    ref = "lab"
  strings:
    $a = { 88 C6 27 35 72 E3 5E 9C }
  condition:
    all of them
}
