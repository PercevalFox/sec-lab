rule R_085fda31_20250902_133235 {
  meta:
    author = "sec-lab"
    created = "20250902_133235"
    ref = "lab"
  strings:
    $a = { 5C 1E E9 21 C8 C7 46 3F }
  condition:
    all of them
}
