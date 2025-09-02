rule R_a4ccbce6_20250902_065753 {
  meta:
    author = "sec-lab"
    created = "20250902_065753"
    ref = "lab"
  strings:
    $a = { EF AB B8 1B AF DF 46 CA }
  condition:
    all of them
}
