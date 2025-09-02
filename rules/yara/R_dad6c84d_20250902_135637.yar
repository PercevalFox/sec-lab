rule R_dad6c84d_20250902_135637 {
  meta:
    author = "sec-lab"
    created = "20250902_135637"
    ref = "lab"
  strings:
    $a = { 5B F0 14 A1 70 2F 03 2B }
  condition:
    all of them
}
