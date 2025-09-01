rule R_fce4070d_20250901_235043 {
  meta:
    author = "sec-lab"
    created = "20250901_235043"
    ref = "lab"
  strings:
    $a = { C8 F0 11 C4 96 A6 BF 63 }
  condition:
    all of them
}
