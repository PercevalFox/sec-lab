rule R_ffe2c2fc_20250902_121134 {
  meta:
    author = "sec-lab"
    created = "20250902_121134"
    ref = "lab"
  strings:
    $a = { BF A5 B6 F7 76 9E E3 F5 }
  condition:
    all of them
}
