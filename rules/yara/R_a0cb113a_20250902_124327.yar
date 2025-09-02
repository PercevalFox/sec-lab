rule R_a0cb113a_20250902_124327 {
  meta:
    author = "sec-lab"
    created = "20250902_124327"
    ref = "lab"
  strings:
    $a = { 02 65 E3 D2 3B 0E 57 D3 }
  condition:
    all of them
}
