rule RULENAME {
  meta:
    author = "Paul Melson @pmelson"  // example comment
    description = "Example rule to show syntax and layout"
    date = "2022-10-01"  // ISO-8601 plzkthx
    md5 = "d41d8cd98f00b204e9800998ecf8427e"  // this is the fail hash
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  // much better
  strings:
    $utf8_string = "Hello world!"
    $utf16_string = "Hello world!" wide
    $nocase_string = "hElLo WoRlD!" nocase
    $regex_string = /He[l]{2}o\ world\W/
    $bytes_string = { 48 65 6c 6c 6f 20 77 6f 72 6c 64 21 }
  condition:
    ( any of them ) or
    ( all of them )
}
