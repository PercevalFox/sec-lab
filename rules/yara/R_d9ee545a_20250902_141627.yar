rule R_d9ee545a_20250902_141627 {
  meta:
    author = "sec-lab"
    created = "20250902_141627"
    ref = "lab"
  strings:
    $a = { 97 74 66 CC 34 F7 03 E2 }
  condition:
    all of them
}
