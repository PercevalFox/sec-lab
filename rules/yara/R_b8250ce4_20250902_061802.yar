rule R_b8250ce4_20250902_061802 {
  meta:
    author = "sec-lab"
    created = "20250902_061802"
    ref = "lab"
  strings:
    $a = { 2F 90 4A E4 44 56 C6 BE }
  condition:
    all of them
}
