rule R_810735c0_20250902_153811 {
  meta:
    author = "sec-lab"
    created = "20250902_153811"
    ref = "lab"
  strings:
    $a = { B2 AA 7D BE F6 2E 1B 83 }
  condition:
    all of them
}
