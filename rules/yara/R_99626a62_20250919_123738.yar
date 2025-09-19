rule R_99626a62_20250919_123738 {
  meta:
    author = "sec-lab"
    created = "20250919_123738"
    ref = "lab"
  strings:
    $a = { 27 37 30 CF 4C AF 5E 8E }
  condition:
    all of them
}
