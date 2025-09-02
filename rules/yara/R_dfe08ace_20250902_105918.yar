rule R_dfe08ace_20250902_105918 {
  meta:
    author = "sec-lab"
    created = "20250902_105918"
    ref = "lab"
  strings:
    $a = { 72 6C 02 B9 A0 FC F0 D2 }
  condition:
    all of them
}
