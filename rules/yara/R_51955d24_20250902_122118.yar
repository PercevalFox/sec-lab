rule R_51955d24_20250902_122118 {
  meta:
    author = "sec-lab"
    created = "20250902_122118"
    ref = "lab"
  strings:
    $a = { 3A 1F 67 80 84 05 1B 4A }
  condition:
    all of them
}
