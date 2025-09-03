rule R_560697ac_20250903_170431 {
  meta:
    author = "sec-lab"
    created = "20250903_170431"
    ref = "lab"
  strings:
    $a = { 04 58 18 BD D0 0B DB 2D }
  condition:
    all of them
}
