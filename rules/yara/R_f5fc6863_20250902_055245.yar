rule R_f5fc6863_20250902_055245 {
  meta:
    author = "sec-lab"
    created = "20250902_055245"
    ref = "lab"
  strings:
    $a = { 64 40 E5 AB 93 FB 8E 4F }
  condition:
    all of them
}
