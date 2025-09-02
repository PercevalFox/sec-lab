rule R_ce588cb2_20250902_062744 {
  meta:
    author = "sec-lab"
    created = "20250902_062744"
    ref = "lab"
  strings:
    $a = { EE F0 7D 76 28 10 27 17 }
  condition:
    all of them
}
