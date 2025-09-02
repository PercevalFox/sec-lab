rule R_dbd15739_20250902_152855 {
  meta:
    author = "sec-lab"
    created = "20250902_152855"
    ref = "lab"
  strings:
    $a = { DA 2C 6C 66 F4 4B B3 D3 }
  condition:
    all of them
}
