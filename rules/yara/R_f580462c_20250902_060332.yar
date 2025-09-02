rule R_f580462c_20250902_060332 {
  meta:
    author = "sec-lab"
    created = "20250902_060332"
    ref = "lab"
  strings:
    $a = { 62 A3 25 F5 6F 8F EA 9D }
  condition:
    all of them
}
