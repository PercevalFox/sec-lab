rule R_bc2f1750_20250902_075242 {
  meta:
    author = "sec-lab"
    created = "20250902_075242"
    ref = "lab"
  strings:
    $a = { 66 3D A6 3D C7 0A 31 50 }
  condition:
    all of them
}
