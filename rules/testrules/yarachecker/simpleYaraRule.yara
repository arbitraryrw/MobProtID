rule yaraCheckerBasic : yaraCheckerRegression
{
    meta:
        description = "Simple Yara rule to verify yaraChecker parent rule matching"
        author = "Nikola Cucakovic"

    strings:
        $a = "It's MobProtID here!"

    condition:
        $a
}