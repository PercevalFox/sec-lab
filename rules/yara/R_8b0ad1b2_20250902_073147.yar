rule R_8b0ad1b2_20250902_073147 {
  meta:
    author = "sec-lab"
    created = "20250902_073147"
    ref = "lab"
  strings:
    $a = { 74 87 93 A0 A0 D4 28 C5 }
  condition:
    all of them
}
