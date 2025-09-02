rule R_6c284139_20250902_112723 {
  meta:
    author = "sec-lab"
    created = "20250902_112723"
    ref = "lab"
  strings:
    $a = { 90 AC B6 8D 3E A6 D0 83 }
  condition:
    all of them
}
