rule R_ac692503_20250902_064643 {
  meta:
    author = "sec-lab"
    created = "20250902_064643"
    ref = "lab"
  strings:
    $a = { EC AF 4C CD 68 8E 06 99 }
  condition:
    all of them
}
