rule R_bc7682b5_20250902_124903 {
  meta:
    author = "sec-lab"
    created = "20250902_124903"
    ref = "lab"
  strings:
    $a = { DA 0F FE 23 E2 B5 D7 70 }
  condition:
    all of them
}
