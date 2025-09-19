rule R_0ec511ee_20250919_225923 {
  meta:
    author = "sec-lab"
    created = "20250919_225923"
    ref = "lab"
  strings:
    $a = { 42 6A F6 EF 8E DB BD 79 }
  condition:
    all of them
}
