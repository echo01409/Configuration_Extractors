rule ASync_RAT {
    meta:
        author      = "Echo01409 (Ben Hopkins)"
        description = "detects AsyncRAT using host based indicators of compromise"
        date = "08/03/2025"
        hash = "DA8814D41003A320BB8BC59E7E899CC80553D91BB87F30EA4E32BE8FDAA2E020"
    strings:

        $async_header_1 = { 04 00 00 00 ?? ?? ?? ?? 00 00 00 00 }
        $async_header_2 = { 02 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

        $str_anti_1 = "VIRTUAL" wide
        $str_anti_2 = "vmware" wide
        $str_anti_3 = "VirtualBox" wide
        $str_anti_4 = "SbieDll.dll" wide

        $str_key = "ejFjc0p0QWtudENHVTdsakhjTExYbm1KM1RqbTVUMlA="

        $str_reg_key_run    = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
    
        $str_schtask = "schtasks /create /f /sc onlogon /rl highest /tn"

        $str_config_1 = "Ports" wide
        $str_config_2 = "Hosts" wide
        $str_config_3 = "Version" wide
        $str_config_4 = "Install" wide
        $str_config_5 = "MTX" wide
        $str_config_6 = "Anti" wide
        $str_config_7 = "Pastebin" wide
        $str_config_8 = "BDOS" wide
        $str_config_9 = "Group" wide

    condition:
        all of ($str_anti_*)  and 
        4 of ($str_config_*) and (
            ($str_schtask) or
            ($str_reg_key_run) or 
            ($async_header_1) or 
            ($async_header_2) or
            ($str_key)
        )
} 
