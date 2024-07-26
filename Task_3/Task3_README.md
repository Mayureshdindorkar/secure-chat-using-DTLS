**TASK-3:  START SSL downgrade attack for eavesdropping** 
---
Downgrade attack by Trudy by intercepting the chat_START_SSL control message from Alice
(Bob) to Bob (Alice).


**Step 1:** To copy file from VM to Container:  
```console
$ lxc file push secure_chat_app.c alice1/root/  
$ lxc file push secure_chat_app.c bob1/root/  
$ lxc file push secure_chat_interceptor.c trudy1/root/ 
```

**Step 2:** Command to login to a container:  
```console
$ lxc exec alice1 bash  
$ lxc exec bob1 bash  
$ lxc exec trudy1 bash
```

**Step 3:** Compile the client (alice1) and server (bob1) codes using the commands:
```console
$ gcc -o secure_chat_interceptor secure_chat_interceptor.c -lssl -lcrypto -Wno-deprecated-declarations
$ gcc -o secure_chat_app secure_chat_app.c -lssl -lcrypto -Wno-deprecated-declarations
```  

**Step 4:** Commands for running the trudy and server codes  
Run the files in below order only
 ```console
For Trudy:   $ ./secure_chat_interceptor -d alice1 bob1
For Server:  $ ./secure_chat_app -s  
```

**Step 5:** Command to poison the /etc/host files  
```console
$ bash ~/poison-dns-alice1-bob1.sh
```

**Step 6:** Command to run the client code
 ```console
For Client:  $ ./secure_chat_app -c bob1
```   

**Step 7:** To close the chat from either cient or server side send this message  
```console
chat_close
```  

**Step 8:** Command to unpoison the /etc/host files  
```console
$ bash ~/unpoison-dns-alice1-bob1.sh
```



