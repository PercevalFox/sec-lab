rule R_3af18bb2_20250902_123835 {
  meta:
    author = "sec-lab"
    created = "20250902_123835"
    ref = "lab"
  strings:
    $a = { B1 71 45 DA F3 4A 59 9F }
  condition:
    all of them
}
