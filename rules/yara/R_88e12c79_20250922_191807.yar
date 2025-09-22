rule R_88e12c79_20250922_191807 {
  meta:
    author = "sec-lab"
    created = "20250922_191807"
    ref = "lab"
  strings:
    $a = { 8A 5E A4 95 E2 29 4D EC }
  condition:
    all of them
}
