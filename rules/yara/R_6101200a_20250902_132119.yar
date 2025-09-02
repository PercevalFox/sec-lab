rule R_6101200a_20250902_132119 {
  meta:
    author = "sec-lab"
    created = "20250902_132119"
    ref = "lab"
  strings:
    $a = { A9 51 9A 9A E0 FB 42 2B }
  condition:
    all of them
}
