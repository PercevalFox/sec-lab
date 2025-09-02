rule R_e1f857de_20250902_060056 {
  meta:
    author = "sec-lab"
    created = "20250902_060056"
    ref = "lab"
  strings:
    $a = { FB 36 3A 3B 25 43 0A 68 }
  condition:
    all of them
}
