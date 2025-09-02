rule R_9867150a_20250902_104230 {
  meta:
    author = "sec-lab"
    created = "20250902_104230"
    ref = "lab"
  strings:
    $a = { A3 D4 FA 34 F6 F2 A8 5E }
  condition:
    all of them
}
