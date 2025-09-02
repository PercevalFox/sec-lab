rule R_954ba6cb_20250902_071716 {
  meta:
    author = "sec-lab"
    created = "20250902_071716"
    ref = "lab"
  strings:
    $a = { 84 EE 62 2D B8 F2 B8 B7 }
  condition:
    all of them
}
