rule R_9c7e8cd9_20250902_121241 {
  meta:
    author = "sec-lab"
    created = "20250902_121241"
    ref = "lab"
  strings:
    $a = { 77 54 F2 3C 02 09 DD 66 }
  condition:
    all of them
}
