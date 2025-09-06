rule R_314a9627_20250906_184842 {
  meta:
    author = "sec-lab"
    created = "20250906_184842"
    ref = "lab"
  strings:
    $a = { E5 5F EB 18 70 19 1F 19 }
  condition:
    all of them
}
