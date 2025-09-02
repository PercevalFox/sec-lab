rule R_f609fab6_20250902_073722 {
  meta:
    author = "sec-lab"
    created = "20250902_073722"
    ref = "lab"
  strings:
    $a = { 7A D8 8D 7F FE 66 FE A7 }
  condition:
    all of them
}
