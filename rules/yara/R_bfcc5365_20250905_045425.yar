rule R_bfcc5365_20250905_045425 {
  meta:
    author = "sec-lab"
    created = "20250905_045425"
    ref = "lab"
  strings:
    $a = { 5C C1 A5 65 5C B4 14 00 }
  condition:
    all of them
}
