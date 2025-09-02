rule R_ae63bf08_20250902_051433 {
  meta:
    author = "sec-lab"
    created = "20250902_051433"
    ref = "lab"
  strings:
    $a = { 4F 60 7D 9B 99 9C 17 42 }
  condition:
    all of them
}
