rule R_249ce9ac_20250902_120749 {
  meta:
    author = "sec-lab"
    created = "20250902_120749"
    ref = "lab"
  strings:
    $a = { E0 0E 5B A5 C0 F0 56 BD }
  condition:
    all of them
}
