rule R_e916308f_20250902_111847 {
  meta:
    author = "sec-lab"
    created = "20250902_111847"
    ref = "lab"
  strings:
    $a = { 90 60 A0 26 E9 45 99 BC }
  condition:
    all of them
}
