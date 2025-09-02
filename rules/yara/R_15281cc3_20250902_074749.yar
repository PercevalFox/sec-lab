rule R_15281cc3_20250902_074749 {
  meta:
    author = "sec-lab"
    created = "20250902_074749"
    ref = "lab"
  strings:
    $a = { DC B6 C2 65 BB 86 39 9F }
  condition:
    all of them
}
