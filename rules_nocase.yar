rule PEDosStubNocase
{
    strings:
        $dos = "this program cannot be run in dos mode" nocase ascii
    condition:
        $dos
}
