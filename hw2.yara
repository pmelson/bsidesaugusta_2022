rule helloworld2 {
  meta:
    author = "Paul Melson @pmelson"
    description = "Example rule to show conditional logic"
    date = "2022-10-01"
    sha256 = "0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8"
  strings:
    $hello = "Hello"
    $world = "world"
  condition:
    (filesize<13 and
      (($hello at 0) and ($world in (4..filesize))) or
      ($hello and $world) or
      (all of ($hel*) and any of ($wor*)))
}
