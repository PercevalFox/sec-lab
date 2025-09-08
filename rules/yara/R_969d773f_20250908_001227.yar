rule R_969d773f_20250908_001227 {
  meta:
    author = "sec-lab"
    created = "20250908_001227"
    ref = "lab"
  strings:
    $a = { 54 75 C7 0C 7E C4 D8 B9 }
  condition:
    all of them
}
