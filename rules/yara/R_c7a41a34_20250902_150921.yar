rule R_c7a41a34_20250902_150921 {
  meta:
    author = "sec-lab"
    created = "20250902_150921"
    ref = "lab"
  strings:
    $a = { AA F8 2D 1A 16 2D 6E DE }
  condition:
    all of them
}
