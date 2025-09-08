rule R_a8eccb1c_20250908_161237 {
  meta:
    author = "sec-lab"
    created = "20250908_161237"
    ref = "lab"
  strings:
    $a = { EE B5 22 49 E9 CA 02 00 }
  condition:
    all of them
}
