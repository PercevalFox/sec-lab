rule R_6bd95901_20250902_051157 {
  meta:
    author = "sec-lab"
    created = "20250902_051157"
    ref = "lab"
  strings:
    $a = { 04 03 AA CF EE C7 AA 4C }
  condition:
    all of them
}
