rule R_5a4e0636_20250902_112701 {
  meta:
    author = "sec-lab"
    created = "20250902_112701"
    ref = "lab"
  strings:
    $a = { 8F DA 67 1C 95 5C EB 33 }
  condition:
    all of them
}
