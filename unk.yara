import "dotnet"
import "pe"

rule YippHB {
  meta:
    author = "BSides Augusta 2022"
    description = "Detect pjoao1578's new YippHB dropper"
    date = "2022-10-01"
    hash = "0f9c100d68ff5c4e09038acb7046b57f4607f9ef14ff76b2caa57c4ddab74772"
  strings:
    $buildmeta_module = "YippHB.dll" ascii wide  // module name
    $buildmeta_module_2023 = "bPRwWN.dll" ascii wide // module name 2023-02-01
    $buildmeta_res = "YippHB.Resources.resources" ascii wide  // resource name
    $buildmeta_res_2023 = "bPRwWN.Resources.resources" ascii wide // resource name 2023-02-01
    $buildmeta_method1 = "JsKJLo" ascii  // method name
    $buildmeta_method_2023 = "YYhPKa" ascii // method name 2023-02-01
    $buildmeta_customattrib = "PPsxtqiU" wide  // used for assembly custom attribute values: Title, Name, Company, Product
    $function_getprocessbyid = "GetProcessById" ascii
    $function_kill = "Kill" ascii
    $function_unmap = "UnmapViewOfSection" ascii
    $function_createproc = "CreateProcess" ascii
    $function_writeprocmem = "WriteProcessMemory" ascii
    $function_readprocmem = "ReadProcessMemory" ascii
    $function_virtualalloc = "VirtualAllocEx" ascii
    $function_setthreadctx = "SetThreadContext" ascii
    $function_getthreadctx = "GetThreadContext" ascii
  condition:
    pe.is_dll() and
    dotnet.version == "v4.0.30319" and
    dotnet.typelib == "4516E0E1-5C0E-4B4E-9A32-9E37E23E7426" and
    ( all of ($function*) or any of ($buildmeta*) )
}
