rule R_f19ab6cc_20250902_133429 {
  meta:
    author = "sec-lab"
    created = "20250902_133429"
    ref = "lab"
  strings:
    $a = { 03 96 6C 38 62 CB ED 52 }
  condition:
    all of them
}
