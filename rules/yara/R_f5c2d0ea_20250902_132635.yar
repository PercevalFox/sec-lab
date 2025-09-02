rule R_f5c2d0ea_20250902_132635 {
  meta:
    author = "sec-lab"
    created = "20250902_132635"
    ref = "lab"
  strings:
    $a = { 52 32 47 ED 13 B6 19 25 }
  condition:
    all of them
}
