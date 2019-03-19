#!/usr/bin/tclsh
#
# reFundamentals
# Copyright (c) 2019 Adam Podlosky
#
# Generate stack string.
#

set str "cmd.exe /c \"echo This file has been infected! & echo. & pause\""
set var "cmd"

set charList [split $str ""]
lappend charList "\\0"

puts "DWORD $var\[\];"
foreach {a b c d} $charList {
    puts [format "  %s\[%d\] = '%s%s%s%s';" $var [incr index] $d $c $b $a]
}
