rule R_ea2bd463_20250902_151737 {
  meta:
    author = "sec-lab"
    created = "20250902_151737"
    ref = "lab"
  strings:
    $a = { EF F6 AE 9C CD 9D BA 26 }
  condition:
    all of them
}
