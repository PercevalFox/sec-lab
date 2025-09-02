rule R_4562901c_20250902_051944 {
  meta:
    author = "sec-lab"
    created = "20250902_051944"
    ref = "lab"
  strings:
    $a = { 43 57 21 C8 1D 9E B4 0B }
  condition:
    all of them
}
