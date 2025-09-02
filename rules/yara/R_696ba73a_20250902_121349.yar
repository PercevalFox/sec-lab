rule R_696ba73a_20250902_121349 {
  meta:
    author = "sec-lab"
    created = "20250902_121349"
    ref = "lab"
  strings:
    $a = { 8C D9 3A FA F6 31 6A 04 }
  condition:
    all of them
}
