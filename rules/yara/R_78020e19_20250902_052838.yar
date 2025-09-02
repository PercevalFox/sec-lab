rule R_78020e19_20250902_052838 {
  meta:
    author = "sec-lab"
    created = "20250902_052838"
    ref = "lab"
  strings:
    $a = { 68 D3 D6 2D F1 AB B3 96 }
  condition:
    all of them
}
