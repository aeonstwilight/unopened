// Deliberately invalid, for the compile-error test. Lives outside tests/rules/yara/.
rule Broken {
    strings: $a = "x"
    condition: $a and
}
