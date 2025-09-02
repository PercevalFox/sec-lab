rule R_a4327f48_20250902_111740 {
  meta:
    author = "sec-lab"
    created = "20250902_111740"
    ref = "lab"
  strings:
    $a = { 14 F3 05 D6 42 41 CE 98 }
  condition:
    all of them
}
