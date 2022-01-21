compare = "ZRIU]HdANdJAGDIAxIAvDDsAyDDq_"
first_compute = ""

for i in compare:
    first_compute += chr(ord(i) - 0x02)

second_compute = first_compute.encode('rot13')
flag = ""

for i in second_compute:
    if (ord(i) < 0x41 or (ord(i) > 0x5a and ord(i) < 0x61) or ord(i) > 0x7a):
        flag += chr(ord(i) + 0x20)
    else:
        flag += i

print(flag)
