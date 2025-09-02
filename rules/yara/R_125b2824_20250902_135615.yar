rule R_125b2824_20250902_135615 {
  meta:
    author = "sec-lab"
    created = "20250902_135615"
    ref = "lab"
  strings:
    $a = { 0E AE 7E F8 C2 0F DE F4 }
  condition:
    all of them
}
