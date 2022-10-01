rule njrat_base64strings {
  meta:
    author = "Paul Melson @pmelson"
    date = "2022-10-01"
    description = "Use Yara base64/base64wide strings to find njRat 0.7d variants."
    sha256 = "5eb405dc81fc6ae21b0a8c87483af1c6b5c0b64c55a498dfd839f19ca5b1b1a4"
    sha256_1 = "15fdc53e9ce899c26869ba5710d0f79e864506ce953819940cf16cc79c442b17"
    sha256_2 = "54e8e80ccea30e0e8e884cf4b73d2451f83ce74512f9e41eacbd12ff1097df34"
    sha256_3 = "6f5259996f22a8a2056fa7ac382fd8dc90a7a80e7e190fea59065e50c7d46e76"
    sha256_4 = "2e6dee3c2b2759256774bab701ebbf8aa02f473e11d55d19fd22cf65b4c2ded2"
    family = "njrat"
    tags = "rat,njrat,nyancat"
  strings:
    $njrat_nyancat = "NYANxCAT" base64wide
    $njrat_legendrat = "LeGendRat" base64wide
    $njrat_bhat = "B HAT" base64wide
    $njrat_cryp = "Cryp" base64wide
    $njrat_pastpin = "pastpin" base64wide
  condition:
    uint16(0) == 0x5A4D and
    any of ($njrat*)
}
