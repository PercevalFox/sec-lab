rule R_03de4a57_20250902_105020 {
  meta:
    author = "sec-lab"
    created = "20250902_105020"
    ref = "lab"
  strings:
    $a = { B7 19 76 60 80 97 B6 EB }
  condition:
    all of them
}
