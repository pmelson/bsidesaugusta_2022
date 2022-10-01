import "pe"

rule isdll {
  meta:
    author = "Paul Melson @pmelson"
    description = "Example rule, uses Yara PE module to identify DLL files"
    reference = "https://yara.readthedocs.io/en/v4.1.0/modules/pe.html"
  condition:
    pe.is_dll()
}

rule oldschool_isdll
{
  meta:
    author = "Paul Melson @pmelson"
    description = "Example rule, verifies PE magic number, PE section header, and PE characteristics to identify DLL files" 
    reference = "https://yara.readthedocs.io/en/v4.1.0/writingrules.html?highlight=uint32#accessing-data-at-a-given-position"
    reference = "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"
  condition:
    uint16(0) == 0x5A4D and  // MZ at 0x00
    uint32(uint32(0x3C)) == 0x00004550 and  // PE at 0x3C
    (uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000  // IMAGE_FILE_DLL set at 0x52
}
