rule R_fcdab413_20250902_065133 {
  meta:
    author = "sec-lab"
    created = "20250902_065133"
    ref = "lab"
  strings:
    $a = { 4F 27 E8 24 2B 62 BB A9 }
  condition:
    all of them
}
