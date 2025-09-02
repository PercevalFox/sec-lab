rule R_29cdfd6e_20250902_144349 {
  meta:
    author = "sec-lab"
    created = "20250902_144349"
    ref = "lab"
  strings:
    $a = { 95 25 44 00 B0 CE FE CD }
  condition:
    all of them
}
