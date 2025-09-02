rule R_c224315e_20250902_063512 {
  meta:
    author = "sec-lab"
    created = "20250902_063512"
    ref = "lab"
  strings:
    $a = { EC 91 DA 0D 15 1F 45 66 }
  condition:
    all of them
}
