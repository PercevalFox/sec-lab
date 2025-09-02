rule R_fbc17682_20250902_134501 {
  meta:
    author = "sec-lab"
    created = "20250902_134501"
    ref = "lab"
  strings:
    $a = { A6 AF 88 3F 83 5D 91 6B }
  condition:
    all of them
}
