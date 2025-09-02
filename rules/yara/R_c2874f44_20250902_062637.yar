rule R_c2874f44_20250902_062637 {
  meta:
    author = "sec-lab"
    created = "20250902_062637"
    ref = "lab"
  strings:
    $a = { B3 82 63 62 AB 5D 0B F7 }
  condition:
    all of them
}
