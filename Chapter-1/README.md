# Practical Malware Analysis Labs 
## Lab 01-01 : 
1.  There is 54 from 70 engines marked lab01-01.exe as malicious, and there is 45 from 70 engines marked lab01-01.dll as malicious.

2. lab01-01.exe compilation time is 2010/12/19 16:16:19 UTC, and lab01-01.dll compilation time is 2010/12/19 16:16:38 UTC.

3. There are no indications that any file is packed or obfuscated.

4. Interesting lab01-01.dll imports as CreateProcess, Sleep and WS2_32.dll, and lab01-01.exe Imports KERNEL32.DLL and MSVCRT.DLL .

5. There is a file path C:\windows\system32\kerne132.dll , File named Lab01-01.DLL ,and some operations on files, kerne132.dll is a good host-based indicator in mentioned file Lab01-01.DLL .

6. There is a local IP address 127.26.152.13 .

7. The malware has 2 stages first stage Lab01-01.exe run or download Lab01-01.dll which is a backdoor.

### Lab 01-01.DLL :-

At first we need to get file hash using [SHA265sum.exe](https://www.bing.com/ck/a?!&&p=060cb04947cda4c3JmltdHM9MTY5NDIxNzYwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTE5Nw&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=sha256sum+download&u=a1aHR0cHM6Ly9zb3VyY2Vmb3JnZS5uZXQvZGlyZWN0b3J5Lz9xPXNoYTI1NnN1bQ&ntb=1)

file Hash : 
> f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba

![Alt text](<0101dll hash.png>)

then search by hash on [virustotal](https://www.virustotal.com/gui/home/upload)

![Alt text](<0101dll virustotal.png>)
we find that 43 security vendors detected this file as malicious  


TO GET the time date  stamp we will use [CFF Explorer](https://www.bing.com/ck/a?!&&p=f4ae81195a7ce4caJmltdHM9MTY5NDMwNDAwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTIzMA&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=download+cff+explorer&u=a1aHR0cHM6Ly9kb3dubG9hZC5jbmV0LmNvbS9DRkYtRXhwbG9yZXIvMzAwMC0yMzgzXzQtMTA0MzExNTYuaHRtbA&ntb=1)

![Alt text](<0101dll CFF Explorer.png>)
so, the file created on Wednesday 05 July 2023, 16.20.25

To know the file is packed or not we will use [PEiD](https://www.bing.com/ck/a?!&&p=7cc615de9d7a0eb8JmltdHM9MTY5NDIxNzYwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTIwMA&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=peid&u=a1aHR0cHM6Ly93d3cuYWxkZWlkLmNvbS93aWtpL1BFaUQ&ntb=1)
![Alt text](<0101dll PEiD.png>)
so, the file is not packed with any packer

If we looked about Imports we will find some hints tell us the malware function like :
![Alt text](<0101dll indicators.png>)
- 23 (socket)
- 115 (WSAStartup)
- 11 (inet_addr)
- 4 (connect)
- 19 (send)
- 22 (shutdown)
- 16 (recv)
- 3 (closesocket)
- 116 (WSACleanup)
- 9 (htons)
- Sleep
- CreateProcessA

If we looked in strings by using [floss.exe](https://www.bing.com/ck/a?!&&p=58425d7859940a46JmltdHM9MTY5NDMwNDAwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTUxMQ&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=download+floss&u=a1aHR0cHM6Ly93d3cubWFuZGlhbnQuY29tL3Jlc291cmNlcy9ibG9nL2Zsb3NzLXZlcnNpb24tMg&ntb=1) we will find some Host-based indicator :
![Alt text](<0101dll str1.png>)
this malware create mutex and open mutex (The mutexes can be used to prevent infection by the same malware in different instances), KERNEL32.DLL allow malware to open and manipulate processes and files such as ReadFile, CreateFile, and WriteFile.

Network-based indicator is :
![Alt text](<0101dll str2.png>)
There is an important network-based indicator : IP 127.26.152.13 which malware connect to .

### Lab 01-01.EXE :-
Get the file Hash by using [PEStudio](https://www.bing.com/ck/a?!&&p=0608350778fe023bJmltdHM9MTY5NDIxNzYwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTIxOQ&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=pestudio+download&u=a1aHR0cHM6Ly9wZXN0dWRpby5lbi5sbzRkLmNvbS93aW5kb3dz&ntb=1)


SHA-256 :
> 58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47


When we upload Lab01-01.exe on virus total we find that 54 AV from 71 AV detected this malware 
![Alt text](<0101 Virus total.png>)

Get the time date stamp by using [PEStudio](https://www.bing.com/ck/a?!&&p=0608350778fe023bJmltdHM9MTY5NDIxNzYwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTIxOQ&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=pestudio+download&u=a1aHR0cHM6Ly9wZXN0dWRpby5lbi5sbzRkLmNvbS93aW5kb3dz&ntb=1)
![Alt text](<0101 time date stamp.png>)
we find that time of compilation is Sun Dec 19 18:16:19 2010

there is no indicators show that file is packed and we confirm this by using [PEiD](https://www.bing.com/ck/a?!&&p=7cc615de9d7a0eb8JmltdHM9MTY5NDIxNzYwMCZpZ3VpZD0xZmQxODVlMC05ZmQ5LTZhZjItMWEyNi05Nzk1OWVhNjZiZGYmaW5zaWQ9NTIwMA&ptn=3&hsh=3&fclid=1fd185e0-9fd9-6af2-1a26-97959ea66bdf&psq=peid&u=a1aHR0cHM6Ly93d3cuYWxkZWlkLmNvbS93aWtpL1BFaUQ&ntb=1)
![Alt text](<0101 PEiD.png>)
 when we check strings we found out alot and the size in the hard disk equal the size in the memory  so, the file is not packed.

If we looked about Imports we will find some hints tell us the malware function like :
![Alt text](<0101 imports.png>)
- UnmapViewOfFile
- MapViewOfFile
- FindNextFileA
- FindFirstFileA


If we looked in strings we will find some Host-based indicators like :
![Alt text](<0101 Host-based indicators.png>)
- C:\windows\system32\kerne132.dll
- CreateFileMapping
- except_handler3
- FindFirstFile
- FindNextFile
- KERNEL32.dll
- Lab01-01.dll
- CloseHandle
- CreateFile
- CopyFile


Finally we found that the malware has 2 stages first stage is a trojan called Lab01-01.exe run or download Lab01-01.dll which is a backdoor located in the path we found.