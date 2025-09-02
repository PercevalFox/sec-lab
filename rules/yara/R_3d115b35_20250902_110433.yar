rule R_3d115b35_20250902_110433 {
  meta:
    author = "sec-lab"
    created = "20250902_110433"
    ref = "lab"
  strings:
    $a = { 15 3A 7A 0B 56 7E E4 DE }
  condition:
    all of them
}
