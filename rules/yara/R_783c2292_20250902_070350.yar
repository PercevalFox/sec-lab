rule R_783c2292_20250902_070350 {
  meta:
    author = "sec-lab"
    created = "20250902_070350"
    ref = "lab"
  strings:
    $a = { AB 17 53 D6 4E 6A 03 A5 }
  condition:
    all of them
}
