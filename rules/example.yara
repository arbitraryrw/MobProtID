rule first_example : examples
{
    meta:
        description = "This is just an example"
        author = "blah"

    strings:
        $a = "secret"
        $b = "Secret"

    condition:
        $a or $b
}