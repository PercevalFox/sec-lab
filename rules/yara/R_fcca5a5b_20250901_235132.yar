rule R_fcca5a5b_20250901_235132 {
  meta:
    author = "sec-lab"
    created = "20250901_235132"
    ref = "lab"
  strings:
    $a = { 44 D5 4B 73 57 85 E4 21 }
  condition:
    all of them
}
