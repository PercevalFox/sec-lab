rule R_fd049385_20250902_074258 {
  meta:
    author = "sec-lab"
    created = "20250902_074258"
    ref = "lab"
  strings:
    $a = { E7 26 4C 51 D5 19 CB 73 }
  condition:
    all of them
}
