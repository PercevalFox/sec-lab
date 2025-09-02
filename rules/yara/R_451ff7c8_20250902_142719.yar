rule R_451ff7c8_20250902_142719 {
  meta:
    author = "sec-lab"
    created = "20250902_142719"
    ref = "lab"
  strings:
    $a = { 4F 5D DB 0B 58 DB 00 D5 }
  condition:
    all of them
}
