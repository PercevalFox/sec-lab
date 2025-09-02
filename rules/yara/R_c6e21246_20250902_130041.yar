rule R_c6e21246_20250902_130041 {
  meta:
    author = "sec-lab"
    created = "20250902_130041"
    ref = "lab"
  strings:
    $a = { F6 59 40 4B 51 E8 A5 DF }
  condition:
    all of them
}
