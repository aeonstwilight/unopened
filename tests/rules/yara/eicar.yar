// Test-only rule: the EICAR anti-virus test string, the one "detected" content allowed.
rule EICAR_Test_File : test
{
    meta:
        description = "EICAR anti-virus test file"
        author = "unopened tests"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
