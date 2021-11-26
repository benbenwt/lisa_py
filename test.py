import lief

binary=lief.ELF.parse(r'C:\Users\guo\Desktop\malicious\arm.server')
header=binary.header
entrypoint=header.entrypoint
print(header)

for section in binary.sections:
    print(section.name)
text=binary.get