rule R_2382062d_20250901_234919 {
  meta:
    author = "sec-lab"
    created = "20250901_234919"
    ref = "lab"
  strings:
    $a = { 45 CD 6D 1A 67 A7 40 C1 }
  condition:
    all of them
}
