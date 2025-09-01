rule R_083a82a0_20250901_234907 {
  meta:
    author = "sec-lab"
    created = "20250901_234907"
    ref = "lab"
  strings:
    $a = { 93 B8 4E 08 74 D1 75 C2 }
  condition:
    all of them
}
