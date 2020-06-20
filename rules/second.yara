rule second_example : examples
{
    meta:
        description = "This is just an example"
        author = "blah"

    strings:
        $a = "calloc"
        $b = "memset"

    condition:
        $a or $b
}

rule third_example : examples
{
    meta:
        description = "This is just an example"
        author = "blah"

    strings:
        $a = "calloc"
        $b = "memset"

    condition:
        $a or $b
}