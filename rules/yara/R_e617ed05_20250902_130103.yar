rule R_e617ed05_20250902_130103 {
  meta:
    author = "sec-lab"
    created = "20250902_130103"
    ref = "lab"
  strings:
    $a = { 8A 45 4A 2A 5D 68 59 7F }
  condition:
    all of them
}
