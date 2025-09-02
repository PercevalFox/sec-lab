rule R_aef8ef0a_20250902_073615 {
  meta:
    author = "sec-lab"
    created = "20250902_073615"
    ref = "lab"
  strings:
    $a = { 03 64 C1 CF 7A 6D 87 0E }
  condition:
    all of them
}
