rule R_009af41e_20250924_183646 {
  meta:
    author = "sec-lab"
    created = "20250924_183646"
    ref = "lab"
  strings:
    $a = { 6A A2 33 B3 7D F5 34 6D }
  condition:
    all of them
}
