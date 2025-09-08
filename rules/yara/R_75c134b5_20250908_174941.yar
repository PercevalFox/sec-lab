rule R_75c134b5_20250908_174941 {
  meta:
    author = "sec-lab"
    created = "20250908_174941"
    ref = "lab"
  strings:
    $a = { FC 40 7F 7F A8 49 36 DA }
  condition:
    all of them
}
