rule R_7569e78e_20250902_072122 {
  meta:
    author = "sec-lab"
    created = "20250902_072122"
    ref = "lab"
  strings:
    $a = { 38 3D 0F 4F AF 45 5B EF }
  condition:
    all of them
}
