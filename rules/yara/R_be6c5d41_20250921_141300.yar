rule R_be6c5d41_20250921_141300 {
  meta:
    author = "sec-lab"
    created = "20250921_141300"
    ref = "lab"
  strings:
    $a = { 78 1E C1 E4 C5 37 64 ED }
  condition:
    all of them
}
