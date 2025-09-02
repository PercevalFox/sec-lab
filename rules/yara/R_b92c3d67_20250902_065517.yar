rule R_b92c3d67_20250902_065517 {
  meta:
    author = "sec-lab"
    created = "20250902_065517"
    ref = "lab"
  strings:
    $a = { 9F B7 FB 1E 9B 64 E6 19 }
  condition:
    all of them
}
