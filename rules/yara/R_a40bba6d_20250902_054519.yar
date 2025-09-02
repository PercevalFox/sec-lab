rule R_a40bba6d_20250902_054519 {
  meta:
    author = "sec-lab"
    created = "20250902_054519"
    ref = "lab"
  strings:
    $a = { 59 5C E1 54 26 9B BF BF }
  condition:
    all of them
}
