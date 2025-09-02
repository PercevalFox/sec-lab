rule R_51496fc5_20250902_055542 {
  meta:
    author = "sec-lab"
    created = "20250902_055542"
    ref = "lab"
  strings:
    $a = { 24 8F F8 86 78 1F E8 EF }
  condition:
    all of them
}
