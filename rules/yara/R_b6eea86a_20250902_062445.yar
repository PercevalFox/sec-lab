rule R_b6eea86a_20250902_062445 {
  meta:
    author = "sec-lab"
    created = "20250902_062445"
    ref = "lab"
  strings:
    $a = { 92 29 DB A7 0C 42 97 A2 }
  condition:
    all of them
}
