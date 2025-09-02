rule R_4cf5bfa9_20250902_104314 {
  meta:
    author = "sec-lab"
    created = "20250902_104314"
    ref = "lab"
  strings:
    $a = { 53 9A 78 2D 7A CE B0 8E }
  condition:
    all of them
}
