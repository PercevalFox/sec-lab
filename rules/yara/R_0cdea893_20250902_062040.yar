rule R_0cdea893_20250902_062040 {
  meta:
    author = "sec-lab"
    created = "20250902_062040"
    ref = "lab"
  strings:
    $a = { FB D6 29 17 CF CC 63 67 }
  condition:
    all of them
}
