rule first_example : examples
{
    meta:
        description = "This is just an example"
        author = "blah"

    strings:
        $a = "It's MobProtID here!"

    condition:
        $a
}