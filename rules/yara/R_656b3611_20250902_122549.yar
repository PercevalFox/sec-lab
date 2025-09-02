rule R_656b3611_20250902_122549 {
  meta:
    author = "sec-lab"
    created = "20250902_122549"
    ref = "lab"
  strings:
    $a = { 1F BC 39 B3 9D 8B F9 68 }
  condition:
    all of them
}
