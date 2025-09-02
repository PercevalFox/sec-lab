rule R_9107bd7b_20250902_113429 {
  meta:
    author = "sec-lab"
    created = "20250902_113429"
    ref = "lab"
  strings:
    $a = { CE 0D 41 82 F7 98 1E 1C }
  condition:
    all of them
}
