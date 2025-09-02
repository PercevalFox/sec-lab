rule R_93fb2771_20250902_105426 {
  meta:
    author = "sec-lab"
    created = "20250902_105426"
    ref = "lab"
  strings:
    $a = { AA 6F B6 C8 65 AC 55 A8 }
  condition:
    all of them
}
