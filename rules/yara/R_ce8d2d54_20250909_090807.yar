rule R_ce8d2d54_20250909_090807 {
  meta:
    author = "sec-lab"
    created = "20250909_090807"
    ref = "lab"
  strings:
    $a = { 61 13 D1 F4 88 77 CB 4D }
  condition:
    all of them
}
