rule R_e1116ea3_20250911_164148 {
  meta:
    author = "sec-lab"
    created = "20250911_164148"
    ref = "lab"
  strings:
    $a = { 0B A7 DC ED 3F 0A 2F 00 }
  condition:
    all of them
}
