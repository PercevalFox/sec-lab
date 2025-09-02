rule R_0e341942_20250902_130533 {
  meta:
    author = "sec-lab"
    created = "20250902_130533"
    ref = "lab"
  strings:
    $a = { 5C 27 D1 19 B0 CF DA 74 }
  condition:
    all of them
}
