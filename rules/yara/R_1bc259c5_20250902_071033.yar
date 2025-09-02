rule R_1bc259c5_20250902_071033 {
  meta:
    author = "sec-lab"
    created = "20250902_071033"
    ref = "lab"
  strings:
    $a = { 51 2B 6D 5F 47 30 91 49 }
  condition:
    all of them
}
