rule R_3b207223_20250902_105319 {
  meta:
    author = "sec-lab"
    created = "20250902_105319"
    ref = "lab"
  strings:
    $a = { 10 FF 0F 24 11 9F BE 9B }
  condition:
    all of them
}
