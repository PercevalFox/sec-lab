rule R_60d90efe_20250902_124604 {
  meta:
    author = "sec-lab"
    created = "20250902_124604"
    ref = "lab"
  strings:
    $a = { 0A 48 6D 96 42 53 0E A9 }
  condition:
    all of them
}
