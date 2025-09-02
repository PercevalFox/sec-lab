rule R_a06636fe_20250902_150644 {
  meta:
    author = "sec-lab"
    created = "20250902_150644"
    ref = "lab"
  strings:
    $a = { 71 66 9B D8 F1 1B D1 96 }
  condition:
    all of them
}
