rule R_58ddd042_20250902_123127 {
  meta:
    author = "sec-lab"
    created = "20250902_123127"
    ref = "lab"
  strings:
    $a = { 57 FC 75 74 BF 0E 07 5E }
  condition:
    all of them
}
