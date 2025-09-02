rule R_cb6085fc_20250902_120404 {
  meta:
    author = "sec-lab"
    created = "20250902_120404"
    ref = "lab"
  strings:
    $a = { 5D 1E 03 0A 2D 89 FD 27 }
  condition:
    all of them
}
