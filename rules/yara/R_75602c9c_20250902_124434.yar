rule R_75602c9c_20250902_124434 {
  meta:
    author = "sec-lab"
    created = "20250902_124434"
    ref = "lab"
  strings:
    $a = { BD 4E 5D E1 20 50 13 35 }
  condition:
    all of them
}
