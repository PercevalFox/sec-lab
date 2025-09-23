rule R_7e07f3cf_20250923_174006 {
  meta:
    author = "sec-lab"
    created = "20250923_174006"
    ref = "lab"
  strings:
    $a = { D0 DF 56 87 87 29 51 3D }
  condition:
    all of them
}
