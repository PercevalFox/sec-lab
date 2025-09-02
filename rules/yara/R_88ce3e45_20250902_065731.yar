rule R_88ce3e45_20250902_065731 {
  meta:
    author = "sec-lab"
    created = "20250902_065731"
    ref = "lab"
  strings:
    $a = { 62 EF 10 A9 62 B1 F3 6F }
  condition:
    all of them
}
