rule R_bd9c9add_20250902_145658 {
  meta:
    author = "sec-lab"
    created = "20250902_145658"
    ref = "lab"
  strings:
    $a = { 24 CB 54 B1 B1 0C A7 0B }
  condition:
    all of them
}
