tcl::tm::path add [file dirname [info script]]
puts [package require fbase64] 
puts [time {fbase64::encode [string repeat "ab" 100000]} 1000]
set a [fbase64::encode "adsdasssssssssssssssssssasfkas;fkjklagjkljafkldsfj lajfadklsjf jalfkjdsfkl jdsaklfj asdklfj alsdfjkljdsaf ladjsfl adjsfkljsdfkljds"]
puts $a

puts [fbase64::decode $a]
catch {fbase64::decode adslljk\u0123} result
puts $result
