rule R_8ede95e5_20250907_153812 {
  meta:
    author = "sec-lab"
    created = "20250907_153812"
    ref = "lab"
  strings:
    $a = { BA 36 B6 6E 6F 86 B3 86 }
  condition:
    all of them
}
