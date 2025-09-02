rule R_583c2014_20250902_114158 {
  meta:
    author = "sec-lab"
    created = "20250902_114158"
    ref = "lab"
  strings:
    $a = { 97 BE DD 1C 85 7D ED F5 }
  condition:
    all of them
}
