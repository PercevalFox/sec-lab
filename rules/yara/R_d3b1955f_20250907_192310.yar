rule R_d3b1955f_20250907_192310 {
  meta:
    author = "sec-lab"
    created = "20250907_192310"
    ref = "lab"
  strings:
    $a = { 60 F9 D1 43 01 36 7C 2B }
  condition:
    all of them
}
