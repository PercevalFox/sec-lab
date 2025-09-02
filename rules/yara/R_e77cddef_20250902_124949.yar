rule R_e77cddef_20250902_124949 {
  meta:
    author = "sec-lab"
    created = "20250902_124949"
    ref = "lab"
  strings:
    $a = { 33 61 3A 53 96 0F 77 1A }
  condition:
    all of them
}
