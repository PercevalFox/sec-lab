rule R_99512f94_20250902_064002 {
  meta:
    author = "sec-lab"
    created = "20250902_064002"
    ref = "lab"
  strings:
    $a = { 3D 80 5E B8 50 E2 D2 A5 }
  condition:
    all of them
}
