rule R_abdad687_20250902_151801 {
  meta:
    author = "sec-lab"
    created = "20250902_151801"
    ref = "lab"
  strings:
    $a = { 04 BF DF 7D BC B6 20 2A }
  condition:
    all of them
}
