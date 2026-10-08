// Test-only rule in a sub-directory, to check namespaces and URL defanging in output.
rule Fixture_Payload_URL
{
    meta:
        description = "Planted fixture URL"
        score = 50
    strings:
        $url = "http://malicious.example.com/payload.bin"
        $wide = "utf16.example.net" wide
    condition:
        any of them
}
