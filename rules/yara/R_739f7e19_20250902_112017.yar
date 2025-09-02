rule R_739f7e19_20250902_112017 {
  meta:
    author = "sec-lab"
    created = "20250902_112017"
    ref = "lab"
  strings:
    $a = { 2C C0 B1 74 27 09 2B CF }
  condition:
    all of them
}
