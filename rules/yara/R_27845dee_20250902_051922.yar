rule R_27845dee_20250902_051922 {
  meta:
    author = "sec-lab"
    created = "20250902_051922"
    ref = "lab"
  strings:
    $a = { C5 EE 36 F4 A9 6D D0 92 }
  condition:
    all of them
}
