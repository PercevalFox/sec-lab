rule R_46307199_20250902_111203 {
  meta:
    author = "sec-lab"
    created = "20250902_111203"
    ref = "lab"
  strings:
    $a = { 71 ED CF 4E F2 FF 1C 69 }
  condition:
    all of them
}
