rule R_7b96bff2_20250902_132034 {
  meta:
    author = "sec-lab"
    created = "20250902_132034"
    ref = "lab"
  strings:
    $a = { CF A3 1C 2A 18 54 F1 CE }
  condition:
    all of them
}
