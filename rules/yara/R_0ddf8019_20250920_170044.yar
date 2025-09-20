rule R_0ddf8019_20250920_170044 {
  meta:
    author = "sec-lab"
    created = "20250920_170044"
    ref = "lab"
  strings:
    $a = { EA 0F 23 E8 65 E1 55 FD }
  condition:
    all of them
}
