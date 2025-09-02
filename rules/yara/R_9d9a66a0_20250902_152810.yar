rule R_9d9a66a0_20250902_152810 {
  meta:
    author = "sec-lab"
    created = "20250902_152810"
    ref = "lab"
  strings:
    $a = { CE 03 D8 B6 6F AD 91 3F }
  condition:
    all of them
}
