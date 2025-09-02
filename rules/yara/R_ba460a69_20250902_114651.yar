rule R_ba460a69_20250902_114651 {
  meta:
    author = "sec-lab"
    created = "20250902_114651"
    ref = "lab"
  strings:
    $a = { DB FB A5 56 82 8A 4E A6 }
  condition:
    all of them
}
