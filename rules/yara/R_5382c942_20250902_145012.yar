rule R_5382c942_20250902_145012 {
  meta:
    author = "sec-lab"
    created = "20250902_145012"
    ref = "lab"
  strings:
    $a = { 64 9D 6C 9B E9 9B F0 64 }
  condition:
    all of them
}
