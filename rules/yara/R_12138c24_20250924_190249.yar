rule R_12138c24_20250924_190249 {
  meta:
    author = "sec-lab"
    created = "20250924_190249"
    ref = "lab"
  strings:
    $a = { 93 5C 15 DA D5 F9 C4 95 }
  condition:
    all of them
}
