rule xor_pe {
  meta:
    author = "Paul Melson @pmelson"
    date = "2022-10-01"
    description = "Example of a better rule to find PE header artifacts that have been XOR encoded"
    sha256 = "d8d10a877c3e8833c59ccb4e36bb9d59b905425a19ce444bab59b1b2bd44a073"
    reference = "https://yara.readthedocs.io/en/v4.1.0/writingrules.html?highlight=xor#xor-strings"
  strings:
    $this_program1 = "This program can" xor(0x01-0x1f)
    $this_program2 = "This program can" xor(0x21-0xff)
  condition:
    any of them
}
