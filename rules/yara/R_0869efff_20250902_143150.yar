rule R_0869efff_20250902_143150 {
  meta:
    author = "sec-lab"
    created = "20250902_143150"
    ref = "lab"
  strings:
    $a = { CF 20 E5 D1 95 31 4D 1C }
  condition:
    all of them
}
