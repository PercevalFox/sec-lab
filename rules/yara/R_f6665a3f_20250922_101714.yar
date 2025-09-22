rule R_f6665a3f_20250922_101714 {
  meta:
    author = "sec-lab"
    created = "20250922_101714"
    ref = "lab"
  strings:
    $a = { 65 37 8B 28 DF 7F B8 CC }
  condition:
    all of them
}
