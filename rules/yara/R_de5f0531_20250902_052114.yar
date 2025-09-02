rule R_de5f0531_20250902_052114 {
  meta:
    author = "sec-lab"
    created = "20250902_052114"
    ref = "lab"
  strings:
    $a = { 98 7F E6 85 1A 6A 27 03 }
  condition:
    all of them
}
