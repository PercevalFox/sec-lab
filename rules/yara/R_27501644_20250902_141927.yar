rule R_27501644_20250902_141927 {
  meta:
    author = "sec-lab"
    created = "20250902_141927"
    ref = "lab"
  strings:
    $a = { 02 EC 1D 44 35 F9 19 4E }
  condition:
    all of them
}
