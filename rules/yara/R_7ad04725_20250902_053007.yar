rule R_7ad04725_20250902_053007 {
  meta:
    author = "sec-lab"
    created = "20250902_053007"
    ref = "lab"
  strings:
    $a = { 40 23 A4 84 2C DB 53 E1 }
  condition:
    all of them
}
