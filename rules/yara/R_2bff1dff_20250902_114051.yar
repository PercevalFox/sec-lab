rule R_2bff1dff_20250902_114051 {
  meta:
    author = "sec-lab"
    created = "20250902_114051"
    ref = "lab"
  strings:
    $a = { 7C DA 56 AE 42 4A 9F 46 }
  condition:
    all of them
}
