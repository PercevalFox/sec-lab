rule R_4745e0f8_20250906_033039 {
  meta:
    author = "sec-lab"
    created = "20250906_033039"
    ref = "lab"
  strings:
    $a = { 07 5C 96 55 1F 79 B5 60 }
  condition:
    all of them
}
