rule R_7e474e09_20250902_070052 {
  meta:
    author = "sec-lab"
    created = "20250902_070052"
    ref = "lab"
  strings:
    $a = { 32 FF 9D 73 C9 99 E4 34 }
  condition:
    all of them
}
