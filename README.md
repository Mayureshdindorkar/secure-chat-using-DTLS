# secure-chat-using-DTLS


**TASK-2: Secure chat app** 
---
A secure peer-to-peer chat application using openssl in C which uses DTLS V1.2 for encrypting the chat messages.


**Step 1:** To copy file from VM to Container:  
```console
$ lxc file push secure_chat_app.c alice1/root/  
$ lxc file push secure_chat_app.c bob1/root/
```

**Step 2:** Command to login to a container:  
```console
$ lxc exec alice1 bash  
$ lxc exec bob1 bash  
```

**Step 3:** Compile the client (alice1) and server (bob1) codes using the commands:
```console
$ gcc -o secure_chat_app secure_chat_app.c -lssl -lcrypto -Wno-deprecated-declarations
```  

**Step 4:** (Skip this step to run code without packet loss)   
Commands to inject loss and show loss.  

```console
$ sudo tc qdisc add dev eth0 root netem loss 55% 
$ sudo tc qdisc show dev eth0
```

**Step 5:** Commands for running the client and server codes  
Run the files in the below order  
 ```console
For Server:  $ ./secure_chat_app -s  
For Client:  $ ./secure_chat_app -c bob1
```  

**Step 6:** To close the chat from either cient or server side send this message  
```console
chat_close
```  

**Step 7:** (Do this step only if had injected the loss at step 4)  
Commands to delete and then show the loss  
```console
$ sudo tc qdisc del dev eth0 root netem  
$ sudo tc qdisc show dev eth0
```  

---


