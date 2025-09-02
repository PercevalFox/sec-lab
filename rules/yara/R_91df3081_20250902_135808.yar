rule R_91df3081_20250902_135808 {
  meta:
    author = "sec-lab"
    created = "20250902_135808"
    ref = "lab"
  strings:
    $a = { 01 E9 5C 90 A1 9D 65 CE }
  condition:
    all of them
}
