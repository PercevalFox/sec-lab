rule R_867dec31_20250902_051220 {
  meta:
    author = "sec-lab"
    created = "20250902_051220"
    ref = "lab"
  strings:
    $a = { 61 86 87 91 2A 4D 5F FA }
  condition:
    all of them
}
