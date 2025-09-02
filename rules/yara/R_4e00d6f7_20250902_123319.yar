rule R_4e00d6f7_20250902_123319 {
  meta:
    author = "sec-lab"
    created = "20250902_123319"
    ref = "lab"
  strings:
    $a = { 7D 12 67 F6 4F B0 BF EC }
  condition:
    all of them
}
