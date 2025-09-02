rule R_c3db0412_20250902_121541 {
  meta:
    author = "sec-lab"
    created = "20250902_121541"
    ref = "lab"
  strings:
    $a = { 09 CA A1 B8 A6 22 9F 5E }
  condition:
    all of them
}
