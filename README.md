# nthelp
## 初始化busybox
```bash
source .src
# 或者执行以下
chmod +x ./busybox
```
## 检测dpkg感染
+ 用于验证已经安装在系统中的软件包的完整性，是否涉及篡改
+ 当软件包中的可执行文件被恶意修改了内容，dpkg -V可以检测到文件内容的 MD5 哈希值与原始安装记录不一致，从而提醒用户系统可能存在安全风险。
```bash
dpkg -V
```
## 检查PATH
```bash
busybox env | busybox grep PATH
```
## 检查并清除泄露文件
```bash
# robots.txt
busybox cat /var/www/html/robots.txt
busybox rm /var/www/html/robots.txt
# 备份文件
busybox rm /var/www/html/www.zip
.Ds_store
.git
# 其他等等
busybox find /var/www/html -name *.txt
busybox find /var/www/html -name *.zip
```
## 检查可以用哪些工具先跑起来
```bash
# 备份一些文件，这个也写在.src中
busybox cp ~/.bash_history $NTHOME/lib/tempinfo/bash_history.txt
待完善：apache的log日志文件
# 检查gcc、g++、python、python2、python3
(busybox which perl || true ) && (busybox which g++ || true ) && (busybox which gcc || true) && (busybox which python | busybox xargs ls -al || true) && (busybox which python2 | busybox xargs ls -al || true) && (busybox which python3 | busybox xargs ls -al || true) &&  (python -V || ture) && ( python2 -V || ture) && (python3 -V || true) && echo "IF gcc/g++, try [chkrootkit] or [rkhunter --check --sk]" && echo "IF python, try [python GScan.py --sug]" && echo "IF perl, try [logwatch.pl]"
```
## 分辨识别操作系统
```bash
lsb_release -a
busybox cat /etc/redhat_release
busybox cat /proc/version
busybox cat /etc/issue
```
## 检查alias
```bash
busybox grep 'alias' ~/.bash*
alias -p # 命令检查
```
## 检查export
```bash
busybox grep 'export' ~/.bash*
unset xxx # 用于修复
```
## 检查~/.bashrc相关
```bash
busybox cat ~/.bashrc
busybox cat ~/.bash_profile
busybox cat ~/.bash_login
# 注意观察1. alias  2. export相关
```
## 检查/etc/passwd /etc/shadow
```bash
busybox cat /etc/passwd
busybox cat /etc/shadow
userdel -r -f hacker # 强制删除用户
busybox awk -F: '$3 >= 1000 && $3 != 65534' /etc/passwd
busybox awk -F: '$3==0{print $1}' /etc/passwd
busybox cat  /etc/sudoers | busybox grep -v "^#\|^$" | busybox grep "ALL=(ALL)"
```
## 检查ps
```bash
# 通过busybox查看系统进程
busybox ps  > busybox_ps.txt && busybox cat busybox_ps.txt | busybox grep -v busybox | busybox grep -v grep | busybox awk '{print $1}' | busybox sort -n > busybox_pid.txt && busybox cat busybox_ps.txt 
# 通过系统命令查看进程并比对
ps -ef  > system_ps.txt && busybox cat system_ps.txt | busybox grep -v "ps -ef" | busybox grep -v grep | busybox awk '{print $2}' | busybox sort -n > system_pid.txt && busybox diff busybox_pid.txt system_pid.txt
# 通过查看/proc目录比对进程id
busybox ls /proc | busybox grep -E '^[0-9]+$' | busybox sort -n > proc_pid.txt && busybox diff proc_pid.txt system_pid.txt
# 发现可疑进程，一般直接杀
busybox find /etc | xargs strings -f | busybox grep bad_filename
busybox find ~ | xargs strings -f | busybox grep bad_filename
#查看运行目录
pwdx PID
```
## 检查netstat
```bash
# 通过busybox查看网络连接
busybox netstat -antp > busybox_netstat_antp.txt && busybox cat busybox_netstat_antp.txt | busybox egrep "LISTEN|ESTABLISB" | busybox awk '{print $3,$4,$6}' | busybox sort > busybox_netstat.txt && busybox cat busybox_netstat_antp.txt
# 通过系统命令查看网络连接并比对
netstat -antp > system_netstat_antp.txt && busybox cat system_netstat_antp.txt | busybox egrep "LISTEN|ESTABLISB" | busybox awk '{print $3,$4,$6}' | busybox sort > system_netstat.txt && busybox diff busybox_netstat.txt system_netstat.txt
# 发现可疑端口，一般直接杀
busybox find /etc | xargs strings -f | busybox grep bad_port
busybox find ~ | xargs strings -f | busybox grep bad_port
```
## 检查crontab
```bash
crontab -l
busybox cat /var/spool/cron/*
busybox cat /var/spool/cron/crontabs/*
busybox cat /etc/crontab
busybox cat /etc/cron.d/*
busybox find /etc -type f | busybox grep etc/cron | xargs busybox cat
# 如果实在太多，用下面的过滤命令
busybox egrep "^([0-9*]+)"
# 还遇到一个变态考点
虽然没有有害定时任务，但考点就是删除定时任务相关文件
```
## 检查系统启动项rc.d rc.local等
```bash
chkconfig --list # 异常适用chkconfig 服务名 off  #进行关闭
busybox cat /etc/rc.local
busybox cat /etc/inittab
busybox cat /etc/profile
busybox find /etc/rc.d/ -type f | busybox xargs busybox ls -al
busybox find /etc/profile.d/ -type f | busybox xargs busybox ls -al
# 发现文件进行查看
busybox cat filename
```
## 检查可能存在的脆弱进程
```bash
busybox cat busybox_ps.txt | busybox egrep "ftp|redis|rsync|apache|mysql|python"
```
## 命令异常/替换检查
```bash
# 7天内
find / -type f -mtime -7 -executable
# 一般命令替换会提供一个.bak的备份文件供恢复，主要是从这个点进行检查
busybox echo $PATH | busybox tr ':' '\n' | busybox xargs -I {} busybox find {} -iname "*bak*"
```
编写了一个shell脚本用来检查最近x天(默认设置为30天)有变化的命令(根据$PATH环境变量分析)
```bash
#!/bin/bash

# 判断是否传入了参数，如果没有传入参数，默认设置为30天
if [ $# -eq 0 ]; then
    num_days=30
else
    num_days=$1
fi

# 根据传入的天数参数，计算对应的时间戳（以秒为单位）
ago_timestamp=$(date +%s --date="${num_days} day ago")

# 先获取$PATH环境变量中以冒号分隔的各个路径，并换行输出
busybox echo $PATH | busybox tr ':' '\n' | while read path; do
    # 判断路径是否存在，如果不存在则跳过本次循环
    if [! -d "$path" ]; then
        continue
    fi
    # 遍历该路径下的所有文件
    for file in "$path"/*; do
        # 判断是否是普通文件，如果是则进行后续检查
        if [ -f "$file" ] ; then
            # 获取文件的修改时间戳（以秒为单位）
            file_modify_timestamp=$(busybox stat -c %Z "$file")
            # 判断文件修改时间戳是否大于指定时间戳，如果大于则表示在相应天数内有修改，进行输出
            if [ "$file_modify_timestamp" -gt "$ago_timestamp" ]; then
                busybox echo -n "$file " && busybox stat $file | busybox grep Change
            fi
        fi
    done
done
```
## 检查具有suid执行权限的恶意程序
```bash
busybox find / -user root -perm -4000 -print 2>/dev/null
busybox find / -user root -perm -4000 -exec ls -ldb {} \; 
busybox find / -perm -u=s -type f 2>/dev/null
busybox find / -perm /4000 -type f
sudo -l # 查看是否存在命令可以免密执行sudo
sudo -l | grep NOPASSWD
```
## 检查是否存在公钥文件
```bash
# 遍历所有用户的家目录，如果 .ssh/authorized_keys 文件存在，就会输出警告信息并打印该文件的内容。
busybox cat /etc/passwd | busybox cut -d: -f6 | busybox xargs -I {} sh -c 'if [ -f "{}/.ssh/authorized_keys" ]; then busybox echo "[!!!] 在用户 {} 下发现登录公钥：" && busybox cat "{}/.ssh/authorized_keys"; fi'
busybox ls -al ~/.ssh/
busybox ls -al /etc/ssh
```
#####TO BE CONTINUE##############
# 暂时没有实现自动化的说明
## 检查敏感文件、敏感目录
```bash
busybox find / *.jsp -perm 777
find / -type f -mtime -1 | grep /var/www/html/  # 检查最近一天修改的文件
grep -rni "xmrig"* # xmrig是挖矿相关文件
检查/var/www/html目录，所有目录除管理员外均应设置为只读权限
```
## 检查LD_PRELOAD
```bash
busybox env | busybox grep LD
unset LD_PRELOAD
# 记得先分析恶意文件，再参考以下进行删除，或者备份到本地
busybox lsattr /etc/ld.so.preload    #检查文件属性，一般该文件会有隐藏属性，会导致无法清楚
busybox chattr -ia /etc/ld.so.preload     #去除文件的隐藏属性，然后再检查属性
#一般需要先随便写一个库文件到/etc/ld.so.preload，然后才可以删除
echo "/lib/test.so" > /etc/ld.so.preload
rm /etc/ld.so.preload
```
## 恶意文件检查
```bash
# 检查是否存在调用特殊的库文件
strace -f -e trace=file /bin/ls 
# 或者是
ldd /bin/ls
# readelf类似ldd，但是没有ldd全面
readelf -a /bin/ls | grep interpreter

busybox lsattr /etc/ld.so.preload    #检查文件属性，一般该文件会有隐藏属性，会导致无法清楚
busybox chattr -ia /etc/ld.so.preload     #去除文件的隐藏属性，然后再检查属性
#一般需要先随便写一个库文件到/etc/ld.so.preload，然后才可以删除
echo "/lib/test.so" > /etc/ld.so.preload
rm /etc/ld.so.preload

# find 常用语法
#find / -mtime -n +n     //-n是n天内  +n指n天前修改文件 
#find / -name "*.xls"                //查找指定文件
#find . -type f |grep -i \.*filename    //在当前目录及其子目录中查找包含指定文件名（不区分大小写）的文件
# 查找7天内具有执行权限的普通文件，并输出文件名和修改日期
  find / -type f -mtime -7 -executable
# 指定目录下2天内新增的文件
 find /tmp -ctime -2  
# 指定目录下1天内修改的文件
 find /home/ -type f -mtime -1    //指定目录下1天内修改的文件
# 指定日期修改的文件
 find /home/ -type f -newermt 2022-03-22 
# 查找指定日期内存在变动的文件
  ind / -type f -newermt "2024-12-03" ! -newermt "2024-12-07" 2>/dev/nul | grep -E "\.(py|sh|per|pl|php|asp|jsp|txt)$"
# 寻找当前目录下文件内容中是否存在base64加密     
  find . -type f -exec grep -l "base64 -d|bash" {} \;
  find . -type f -exec grep -l "base64_decode" {} \;
# 当漏扫工具被截留到服务器上时候，还定位不到攻击者遗留的工具时，例如ips上出现横向攻击10.16.5.134 时，可以执行如下命令。 他会查找全系统文件内容中的可能存在漏洞结果的文件位置。
  find / -type f -exec grep -l "10.16.5.134" {} \;
```
## 检查木马文件含内存马
```bash
busybox find /var/www/html/ -type f -name *.php | busybox xargs grep -i eval
# 常规别忘记用D盾扫描分析
D盾
# 删不掉的内存马，通过创建目录的方式解决
rm -rf /var/www/html/.pass.php && mkdir /var/www/html/.pass.php
```
## 通过提升启动优先级发现更隐蔽的问题
具体如何分辨识别操作系统，见最初介绍
### Ubuntu16测试成功过
在/etc/init.d/目录下新建test.sh，内容如下，然后 chmod +x test.sh
+ 添加自启动脚本。在这里90表明一个优先级，越高表示执行的越晚
sudo update-rc.d test.sh defaults 90
+ 从开机自启动项里删除自启动项
sudo update-rc.d -f test.sh remove
```bash
#! /bin/sh
### BEGIN INIT INFO
# Provides: rc.hisign
# Required-Start: 
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop:
# Short-Description: Run /etc/rc.hisign if it exist
### END INIT INFO
# 为了提升执行优先级，需要将require后面的内容全部删除，彻底提升优先级
# 查看启动项
cp /etc/rc.local /tmp/xxx
# 查看所有的系统中运行的suid可执行文件
find / -user root -perm -4000 -print >> /tmp/xxx
# 关于启动项的总结
ps -ef > /tmp/ps.txt
cp /etc/rc.local /tmp/rclocal.txt
ls -alt /etc/init.d > /tmp/initd.txt
ls -alt /var/spool/cron > /tmp/varcron.txt
grep -r "\* \*" /etc > /tmp/etccron.txt
cp /root/.bashrc /tmp/rootbashrc.txt
cp /root/.bash_profile /tmp/rootbashprofile.txt
exit 0
```
### Linux建立自启动脚本的方法（U22测试均失败）
+ 方法一：
1. 先查询当前用户运行级别，命令runleve，可得到一个数字对应用户等级
2. 根据对应数字，cd /etc/rcX.d/目录下，ln -vsf /etc/init.d/start.sh S99start，这里99表示运行顺序，不放心可疑多设置几个S90或者更小的
3. 在/etc/init.d/目录下创建start.sh脚本以便执行相关命令，具体参考前面
+ 方法二：修改rmnologin.sh文件
1. 修改/etc/init.d/rmnologin.sh文件，如果没有这个文件，选其他文件（看命）
2. 在: exit 0这一行上面添加一行内容:  /etc/init.d/start.sh
3. 将start.sh文件放入/etc/init.d/目录下
+ 方法三：在/etc/systemd/system/目录下创建my_startup_service.service，内容如下。然后systemctl enable my_startup_service.service
```bash
[Unit]
Description=My Startup Service
After=network.target

[Service]
Type=simple
ExecStart=/etc/init.d/start.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## ssh登录有关的日志分析
```bash

# 查看哪些IP破解你SSH密码以及次数
  cat /var/log/secure | awk '/Failed/{print $(NF-3)}' | sort | uniq -c | awk '{print $2" = "$1;}'
# 登录失败的记录
  grep -o "Failed password" /var/log/secure|uniq -c
# 登录成功的记录
  grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
#查看可疑IP登陆
  last -f /var/log/wtmp 
# 登录日志中检测是否遭受暴力破解攻击
  grep -i 'failed' /var/log/auth*.log* | grep -E 'password|authentication failure' | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | while read count ip; do if [ "$count" -ge 5 ]; then echo "[!!!] IP $ip 可能正在进行暴力破解攻击，共有 $count 次失败尝试。"; fi; done
```
# 2 命令合集
## 2.1 Linux
### 2.1.1 apache服务重启
1. apachctl -k restart
### 2.1.2 查看与某文件同一天修改的其他文件
find /var/www/html -type f -exec grep -q -s -F -H -e "" --null {} + | xargs -0 ls -l
### 2.1.3 Linux账户密码安全策略
1. 密码过期时间设置vim /etc/login.def `PASS_MAX_DAYS 90`
2. 连续输入错误三次，锁定5分钟
```bash
vim /etc/pam.d/sshd
auth required pam_tally.so deny=3 onerr=fail unlock_time=300 #最后一行添加配置文件
auth required pam_faillock.so pre
auth audit silent deny=3 unlock_time=300
auth required pam_faillock.so authfail audit deny=3 unlock_time=300
```
或者修改 /etc/pam.d/common-auth
## 2.2 Windows
### 合集
```bash
netstat -ano 检查端口连接情况，是否有远程连接、可疑连接
tasklist | findstr "PID"根据pid定位进程
msconfig看一下启动项是否有可以的启动
%UserProfile%\Recent   最近访问的文件夹
netstat -ano   //网络连接
tasklist |findstr PID  //通过PID查看进程
msconfig   //服务项
tasklist /svc    //进程
resmon cpu  //使用情况
compmgmt.msc      //计算机-管理 计划任务，日志查询
eventvwr.msc   事件查看器
lusrmgr.msc  //用户与组
services.msc  //服务
net user  //获取用户列表
net session  //查看当前会话
net use   //远程连接
net share   //查看当前用户的共享目录
net start   //查看当前运行的服务
net localgroup administrators  //本机管理员
certutil -hashfile 文件名 MD5     //获取md5值命令
ncpa.cpl  //打开网络连接
wmic process where Name=”cmd.exe” get ParentProcessId  //查看对应父进程
wmic process get caption,commandline /value >> tmp.txt   //分析进程参数
wmic process where caption="svchost.exe" get caption,commandline /value   //分析指定进程命令行参数 
#windows 自启动目录
C:\Users\用户名\AppData\Roaming\Microsoft\Windows\start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```
### 2.2.1 用户检查1：net user
### 2.2.2 用户检查2：wmic useraccount get name,SID
![[Pasted image 20240624172438.png]]
### 2.2.3 用户检查3： reg query HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names
有些时候在 SAM 下面没有内容， 这是因为没有权限进行查看， 这时需要定位到  
HKEY_LOCAL_MACHINE\SAM\SAM  
右键权限 完全控制
![[Pasted image 20240624173011.png]]
### 2.2.4 用户检查4： D盾
工具 - 克隆账号检测
![[Pasted image 20240624173314.png]]
### 2.2.5 用户检查5：lusrmgr.msc
### 2.2.6 netstat -anb | findstr xx
### 2.2.7 日常查看：eventvmr.msc  - 事件查看器
事件 ID 说明  
4624 账号成功登录  
4625 账号登录失败  
4720 已创建用户帐户  
4722 用户帐户已启用  
4723 尝试更改帐户的密码  
4724 尝试重置帐户密码  
4725 用户帐户已被禁用  
4726 用户帐户已删除
![[Pasted image 20240624173517.png]]

导出 Windows 日志--安全， 利用 Log Parser 进行分析。  
LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated as  
LoginTime,EXTRACT_TOKEN(Strings,5,'|') as username,EXTRACT_TOKEN(Strings, 8, '|') as  
LogonType,EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName,EXTRACT_TOKEN(Strings, 18,  
'|') AS SourceIP FROM 日志位置'C:\Users\Administrator\Desktop\win10.evtx' where  
EventID=4624"  
下载安装包 LogParser.msi
![[Pasted image 20240624173625.png]]
### 2.2.8 tasklist   以及  tasklist /svc 可以查看进程对应的服务





