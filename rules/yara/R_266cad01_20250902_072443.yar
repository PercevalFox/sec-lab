rule R_266cad01_20250902_072443 {
  meta:
    author = "sec-lab"
    created = "20250902_072443"
    ref = "lab"
  strings:
    $a = { 8F F8 E6 FB 1D CE 24 AB }
  condition:
    all of them
}
