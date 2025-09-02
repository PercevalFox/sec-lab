rule R_a95e738b_20250902_061441 {
  meta:
    author = "sec-lab"
    created = "20250902_061441"
    ref = "lab"
  strings:
    $a = { C9 90 DE 35 A2 5B 3D D9 }
  condition:
    all of them
}
