rule R_cb91ca2c_20250910_112919 {
  meta:
    author = "sec-lab"
    created = "20250910_112919"
    ref = "lab"
  strings:
    $a = { A3 7E BD 16 59 E5 24 06 }
  condition:
    all of them
}
