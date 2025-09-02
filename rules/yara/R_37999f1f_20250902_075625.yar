rule R_37999f1f_20250902_075625 {
  meta:
    author = "sec-lab"
    created = "20250902_075625"
    ref = "lab"
  strings:
    $a = { 7E E4 E5 91 40 CD DB 65 }
  condition:
    all of them
}
