rule R_963bf843_20250902_061955 {
  meta:
    author = "sec-lab"
    created = "20250902_061955"
    ref = "lab"
  strings:
    $a = { 65 1F C0 E4 5E 19 6C EA }
  condition:
    all of them
}
