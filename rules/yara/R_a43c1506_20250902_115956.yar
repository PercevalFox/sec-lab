rule R_a43c1506_20250902_115956 {
  meta:
    author = "sec-lab"
    created = "20250902_115956"
    ref = "lab"
  strings:
    $a = { 43 68 79 B0 BC B8 FD 7E }
  condition:
    all of them
}
