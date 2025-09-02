rule R_fc5fa61d_20250902_150043 {
  meta:
    author = "sec-lab"
    created = "20250902_150043"
    ref = "lab"
  strings:
    $a = { 71 81 26 BD 05 41 48 0B }
  condition:
    all of them
}
