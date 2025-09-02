rule R_216ecc3c_20250902_064153 {
  meta:
    author = "sec-lab"
    created = "20250902_064153"
    ref = "lab"
  strings:
    $a = { 62 E3 7E 8D B2 1B BA 18 }
  condition:
    all of them
}
