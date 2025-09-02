rule R_7dfbf6dc_20250902_140814 {
  meta:
    author = "sec-lab"
    created = "20250902_140814"
    ref = "lab"
  strings:
    $a = { 86 37 60 66 28 F4 C0 49 }
  condition:
    all of them
}
