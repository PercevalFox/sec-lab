rule R_678148b2_20250902_133946 {
  meta:
    author = "sec-lab"
    created = "20250902_133946"
    ref = "lab"
  strings:
    $a = { 92 F3 A2 20 68 D8 71 BD }
  condition:
    all of them
}
