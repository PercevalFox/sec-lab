rule R_8ba6cc7d_20250902_132249 {
  meta:
    author = "sec-lab"
    created = "20250902_132249"
    ref = "lab"
  strings:
    $a = { 84 5B 92 01 E4 1B F0 3D }
  condition:
    all of them
}
