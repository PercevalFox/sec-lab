rule R_32cec6dd_20250902_051349 {
  meta:
    author = "sec-lab"
    created = "20250902_051349"
    ref = "lab"
  strings:
    $a = { F9 89 97 04 E9 B1 EB 18 }
  condition:
    all of them
}
