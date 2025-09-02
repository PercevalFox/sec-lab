rule R_e5739b79_20250902_060248 {
  meta:
    author = "sec-lab"
    created = "20250902_060248"
    ref = "lab"
  strings:
    $a = { 94 BD 22 E3 49 B6 36 6C }
  condition:
    all of them
}
