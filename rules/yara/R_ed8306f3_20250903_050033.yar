rule R_ed8306f3_20250903_050033 {
  meta:
    author = "sec-lab"
    created = "20250903_050033"
    ref = "lab"
  strings:
    $a = { 13 60 32 86 B8 CB B1 74 }
  condition:
    all of them
}
