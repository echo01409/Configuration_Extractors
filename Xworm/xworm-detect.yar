rule Xworm_RAT {
    meta:
        author = "Echo01409 (Ben Hopkins)"
        description = "Detects the Xworm RAT based on constant hex-byte arrays"
        date = "23/11/2024"
        hash = "b3e217c467cfe1e8079e82b88f2f99950a9459330a8843070ebb34bf3e2bcf38"
    strings:
        $s1 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $s2 = {50 00 6C 00 75 00 67 00 69 00 6E 00 73 00 20 00 52 00 65 00 6D 00 6F 00 76 00 65 00 64 00 21}
        $s3 = {73 00 65 00 6E 00 64 00 50 00 6C 00 75 00 67 00 69 00 6E}
    condition:
        uint16(0) == 0x5A4D and all of them

