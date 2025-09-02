rule R_30868d6c_20250902_052242 {
  meta:
    author = "sec-lab"
    created = "20250902_052242"
    ref = "lab"
  strings:
    $a = { B0 49 C9 42 F5 FF BF 47 }
  condition:
    all of them
}
