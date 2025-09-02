rule R_dba8179b_20250902_073829 {
  meta:
    author = "sec-lab"
    created = "20250902_073829"
    ref = "lab"
  strings:
    $a = { 00 2F 7B ED 95 5F 08 39 }
  condition:
    all of them
}
