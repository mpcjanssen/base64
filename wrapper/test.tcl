load fbase64-1.0.dylib fbase64
puts [time {fbase64::encode "adsdasssssssssssssssssssasfkas;fkjklagjkljafkldsfj lajfadklsjf jalfkjdsfkl jdsaklfj asdklfj alsdfjkljdsaf ladjsfl adjsfkljsdfkljds"} 10000]
set a [fbase64::encode "adsdasssssssssssssssssssasfkas;fkjklagjkljafkldsfj lajfadklsjf jalfkjdsfkl jdsaklfj asdklfj alsdfjkljdsaf ladjsfl adjsfkljsdfkljds"]
puts $a

puts [fbase64::decode $a]
catch {fbase64::decode adslljk\u0123} result
puts $result
