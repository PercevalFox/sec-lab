rule R_b19ee891_20250902_124627 {
  meta:
    author = "sec-lab"
    created = "20250902_124627"
    ref = "lab"
  strings:
    $a = { 9C 28 F4 31 7B 2F B6 01 }
  condition:
    all of them
}
