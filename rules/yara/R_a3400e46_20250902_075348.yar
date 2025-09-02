rule R_a3400e46_20250902_075348 {
  meta:
    author = "sec-lab"
    created = "20250902_075348"
    ref = "lab"
  strings:
    $a = { E0 1E 1F 51 FC 62 C6 37 }
  condition:
    all of them
}
