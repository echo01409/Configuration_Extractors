rule Xworm_RAT {
    meta:
        author = "Echo01409 (Ben Hopkins)"
        description = "Detects the Xworm RAT based on constant hex-byte arrays and string values"
        date = "23/11/2024"
        hash = "b3e217c467cfe1e8079e82b88f2f99950a9459330a8843070ebb34bf3e2bcf38"
    strings:
        $str_hex1 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $str_hex2 = {50 00 6C 00 75 00 67 00 69 00 6E 00 73 00 20 00 52 00 65 00 6D 00 6F 00 76 00 65 00 64 00 21}
        $str_hex3 = {73 00 65 00 6E 00 64 00 50 00 6C 00 75 00 67 00 69 00 6E}
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
    condition:
        uint16(0) == 0x5A4D and (1 of ($str_hex*) or all of ($str_x*))

