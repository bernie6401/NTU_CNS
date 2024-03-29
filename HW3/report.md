# Cryptography and Network Security – Homework 3
###### tags: `NTUCNS`

[TOC]


## 1. DDoS
### 1)
* Hint: You can use I/O Graphs to find the time that the flow starts to burst. Then you can find the first packet near there.

* Ans: Using I/O graph in `Statistic/I/O Graphs` in wireshark, then you can figure out the whole trend of this network flow.
  
    ![](https://hackmd.io/_uploads/rJk-LueL3.jpg)
    
    Also, you can set the different scale of the graph and figure out the attack time precisely. I set the `Interval=100ms` and find the increasing time at `24.8s` which is `No.55862` packet shown as below.
    
    ![](https://hackmd.io/_uploads/ryG7POxL2.png)
    
    Thus, the attack time should be at <font color="FF0000">`24.945277`</font> and the victim is <font color="FF0000">`192.168.232.95`</font>
    
    ![](https://hackmd.io/_uploads/Syurtue8h.png)
    
    
    
    Note: You can observe that how many packets of each address received or transmitted in `Statistic/Endpoints`. You can note that the address `192.168.232.95` has received tons of packets.
    
    ![](https://hackmd.io/_uploads/BJ6r9dgI3.png)
    

### 2)
* Hint: How to find attack packets if you know the victim?
* Ans: The protocol that the attack exploit is <font color="FF0000">`UDP`</font>. Maybe this is a `UDP` flood attack. And the size of an attack packet should be <font color="FF0000">$482$</font> bytes.
* Note: You can set the filter `ip.dst==192.168.232.95 && udp` and observe the flow and packets.
  
    ![](https://hackmd.io/_uploads/HJ4hkte8n.png)
    
### 3)
* Ans: (Skip)

### 4)
* Background: this DDoS attack using NTP protocol to amplify the packets to achieve the attack.
    > NTP 放大 DoS 攻擊利用響應遠程 monlist 請求的網絡時間協議（NTP）服務器。 monlist 函數返回與服務器交互的所有設備的列表，在某些情況下最多達 600 個列表。 攻擊者可以偽造來自目標 IP 地址的請求，並且漏洞服務器將為每個發送的請求返回非常大的響應 - by [Kali Linux網絡掃描秘籍第六章拒絕服務(二)](https://cloud.tencent.com/developer/article/2182801)
    
    ![](https://hackmd.io/_uploads/BkX8K9eL2.png)
    
* Hint: You can find some useful statistics in `IPv4 Statistics`.
* Ans: In `IPv4 Statistics`, we can note the several victims receive most of the packets. $\to$ <font color="FF0000">`192.168.232.80`, `192.168.232.10`, `192.168.232.95`</font>
  
    ![](https://hackmd.io/_uploads/B1W9QcgIn.png)
    
    ![](https://hackmd.io/_uploads/SyBgw5xLh.png)
    
    * `192.168.232.80`: 28320 packets received
    * `192.168.232.10`: 26870 packets received
    * `192.168.232.95`: 23327 packets received
    * 3 major amplifiers: <font color="FF0000">`34.93.220.190`, `128.111.19.188`, `129.236.255.8`</font>

### 5)
* Background:
    > NTP 放大 DoS 攻擊利用響應遠程 monlist 請求的網絡時間協議（NTP）服務器。 monlist 函數返回與服務器交互的所有設備的列表，在某些情況下最多達 600 個列表。 攻擊者可以偽造來自目標 IP 地址的請求，並且漏洞服務器將為每個發送的請求返回非常大的響應 - by [Kali Linux網絡掃描秘籍第六章拒絕服務(二)](https://cloud.tencent.com/developer/article/2182801)
    > 
    > NTP放大攻擊：網路時間協定(Network Time Protocol, NTP)是一種允許主機之間透過封包交換進行系統時間同步之網路協定。但在NTP協定中，有一個monlist指令，當NTP伺服器收到monlist請求後，會回傳多筆近期與之通訊的列表，該列表最高限制為600筆。而攻擊者便可利用此機制，以偽裝之IP位址寄送monlist請求給NTP伺服器，則NTP伺服器便會將至多600筆之數據傳送給遭攻擊者偽冒的IP位址，導致遭偽冒之受害主機因一次大量的數據傳輸，造成其網路頻寬無法負荷，致使受害伺服器無法正常提供服務。此種攻擊之放大係數為556.9，為所有DDoS放大攻擊中放大倍率次高者。 - by [分散式阻斷服務攻擊(DDoS)趨勢與防護](https://www.twcert.org.tw/tw/cp-157-6408-e0c62-1.html)
* Hint: You can use `nmap` or `ntpdc` to send a monlist query.
* Ans:
    1. Determine if the remote server is running NTP service
        I tried 9 IP(3 IP from previous question + 6 IPs provided from TAs)
        Note: `-sU` option can be used to specify <font color="FF0000">UDP</font>, then the `-p` option can be used to specify the port
        
        ```bash
        $ sudo nmap -sU 128.111.19.188 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 22:01 CST
        Nmap scan report for cms28.physics.ucsb.edu (128.111.19.188)
        Host is up (0.15s latency).
        
        PORT    STATE  SERVICE
        123/udp closed ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds
        $ sudo nmap -sU 34.93.220.190 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:32 CST
        Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
        Nmap done: 1 IP address (0 hosts up) scanned in 3.21 seconds
        $ sudo nmap -sU 129.236.255.89 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:32 CST
        Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
        Nmap done: 1 IP address (0 hosts up) scanned in 3.16 seconds
        $ sudo nmap -sU 142.44.162.188 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:34 CST
        Nmap scan report for 188.ip-142-44-162.net (142.44.162.188)
        Host is up (0.19s latency).
        
        PORT    STATE SERVICE
        123/udp open  ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 1.06 seconds
        sudo nmap -sU 91.121.132.146 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:35 CST
        Nmap scan report for ns3002114.ip-91-121-132.eu (91.121.132.146)
        Host is up (0.28s latency).
        
        PORT    STATE SERVICE
        123/udp open  ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
        $ sudo nmap -sU 82.65.72.200 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:35 CST
        Nmap scan report for 82-65-72-200.subs.proxad.net (82.65.72.200)
        Host is up (0.26s latency).
        
        PORT    STATE SERVICE
        123/udp open  ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 1.40 seconds
        $ sudo nmap -sU 81.23.0.110 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:35 CST
        Nmap scan report for clients-0.23.81.110.misp.ru (81.23.0.110)
        Host is up (0.29s latency).
        
        PORT    STATE         SERVICE
        123/udp open|filtered ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 5.57 seconds
        $ sudo nmap -sU 72.76.155.29 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:36 CST
        Nmap scan report for static-72-76-155-29.nwrknj.fios.verizon.net (72.76.155.29)
        Host is up (0.21s latency).
        
        PORT    STATE SERVICE
        123/udp open  ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 1.17 seconds
        $ sudo nmap -sU 61.216.81.26 -p 123
        Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-28 23:37 CST
        Nmap scan report for 61-216-81-26.hinet-ip.hinet.net (61.216.81.26)
        Host is up (0.017s latency).
        
        PORT    STATE         SERVICE
        123/udp open|filtered ntp
        
        Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds
        ```
        
        Final Result:
        34.93.220.190 $\to$ down
        128.111.19.188 $\to$ closed
        129.236.255.89 $\to$ down
        142.44.162.188 $\to$ open
        91.121.132.146 $\to$ open
        82.65.72.200 $\to$ open
        81.23.0.110 $\to$ open|filtered
        72.76.155.29 $\to$ open
        61.216.81.26 $\to$ open|filtered

    2. Determine if NTP service can be used for amplification attacks
       
        ```bash
        $ ntpdc -n -c monlist 34.93.220.190
        34.93.220.190: timed out, nothing received
        ***Request timed out
        $ ntpdc -n -c monlist 128.111.19.188
        ntpdc: read: Connection refused
        $ ntpdc -n -c monlist 129.236.255.89
        129.236.255.89: timed out, nothing received
        ***Request timed out
        $ ntpdc -n -c monlist 142.44.162.188
        remote address          port local address      count m ver rstr avgint  lstint
        ===============================================================================
        213.251.128.249          123 142.44.162.188         1 4 4      0    373     373
        54.39.23.64              123 142.44.162.188         1 4 4      0    429     429
        105.187.151.14         59585 142.44.162.188         1 3 2      0    784     784
        ...
        $ ntpdc -n -c monlist 91.121.132.146
        91.121.132.146: timed out with incomplete data
        ***Response from server was incomplete
        $ ntpdc -n -c monlist 82.65.72.200
        82.65.72.200: timed out with incomplete data
        ***Response from server was incomplete
        $ ntpdc -n -c monlist 81.23.0.110
        81.23.0.110: timed out with incomplete data
        ***Response from server was incomplete
        $ ntpdc -n -c monlist 72.76.155.29
        72.76.155.29: timed out with incomplete data
        ***Response from server was incomplete
        $ ntpdc -n -c monlist 61.216.81.26
        61.216.81.26: timed out, nothing received
        ***Request timed out
        ```
        
        In this moment the final result:
        34.93.220.190 $\to$ timed out
        128.111.19.188 $\to$ Connection refused
        129.236.255.89 $\to$ timed out
        142.44.162.188 $\to$ <font color="FF0000">Success</font>
        91.121.132.146 $\to$ incomplete
        82.65.72.200 $\to$ incomplete
        81.23.0.110 $\to$ incomplete
        72.76.155.29 $\to$ incomplete
        61.216.81.26 $\to$ timed out
    3. Record the network flow and compute the amplification factor
       In my network situation and remote server circumstances, I received 100 packets with $482\ bytes*100\ packets=48200\ bytes$ from NTP server so the amplification factor is just <font color="FF0000">$48200/234 \cong 206$</font> directly (234 is transmit packet size).
       
        ![](https://hackmd.io/_uploads/SyUpW5-8h.png)
       

### 6)
* Ans 1: 
    * Implement rate limiting to restrict the number of UDP packets from a single source IP.
    * Use traffic filtering mechanisms like ACLs or firewalls to block malicious UDP traffic.
    * Deploy IPS/IDS systems to automatically block or mitigate the attack.
    * Enable flow monitoring to detect abnormal traffic patterns.
* Ans 2:
    * Deploy firewalls and routers with robust security features.
    * Use IDS/IPS systems to detect and block malicious UDP traffic.
    * Implement traffic shaping and QoS to prioritize legitimate traffic.
    * Consider using specialized DDoS mitigation services.
    * Monitor network traffic for signs of UDP flood attacks.
    * Keep network infrastructure and security measures up to date.

## 2. Smart Contract
(SKIP...)

## 3. Web Authentication

### a)
Username: `CNS-user`
Password: `CNS-password`
1. Basic Authentication
    How to deploy your service? You can refer to [this video](https://www.youtube.com/watch?v=G1EVWLjwvrE&ab_channel=TechieBlogging) and remember to set the extra command `pip install flask-httpauth` to install other library.
    ![](https://hackmd.io/_uploads/Sko6ZheD2.png)

    <font color="FF0000">TA can refer to `code3-a-basic.py`</font>

    Flag: `CNS{H77P_4U7h_r0CK2}`

2. Cookie-Based Authentication
   
    > In this subtask, you will implement cookie-based authentication.
    First, I will perform 'POST /', which contains two fields: 'username' and 'password', in application/x-www-form-urlencoded format.
    Then I will execute 'GET /', which will contain the cookies returned in the previous POST request.
    
    <font color="FF0000">TA can refer to `code3-a-cookie.py`</font>
    Flag: `CNS{CooK135_4R3_d3L1c1ou2}`
3. JWT-Based
   
    > In this subtask, you will implement JWT-based authentication.
    First, I will execute 'POST /', which contains two fields: 'username' and 'password', in application/x-www-form-urlencoded format.
    Your service should output the token directly in the HTTP response body.
    Then I will execute 'GET /' with the token.
    
    <font color="FF0000">Not complete!</font>
### b)
* Basic HTTP Authentication:
    * Pros:
        Simple to implement and widely supported by browsers and servers.
        No additional server-side storage required, as the credentials are sent with each request.
    * Cons:
        The credentials are sent with every request, which can increase the risk if the connection is not secured with HTTPS.
        The password is base64-encoded, which is not a secure encryption method. It can be easily decoded if intercepted.
    * Basic HTTP Authentication is a simple and widely supported method, but it has security limitations. Sending credentials with each request can be risky, especially if the connection is not secured. Additionally, base64 encoding doesn't provide encryption, making it vulnerable to interception.
* Cookie-based Authentication:
    * Pros:
        Stateless on the server side. The server doesn't need to store user sessions as the session ID is included with each request.
        Session ID is stored on the client-side, making it less vulnerable to interception.
    * Cons:
        Requires server-side storage or a session management system to handle session IDs securely.
        Vulnerable to session hijacking if proper security measures like session expiration and secure cookie flags are not implemented.
    * Cookie-based Authentication is more secure than Basic Authentication as the session ID is stored on the client-side. However, it requires server-side storage or session management systems. If proper security measures are not implemented, session hijacking attacks can occur.
* JWT-based Authentication:
    * Pros:
        Stateless on the server side. The server doesn't need to store session data as all required information is encoded in the JWT.
        Enables easy scalability and interoperability, as JWTs can be used across multiple services or distributed systems.
        Allows for fine-grained control by including user-related data (claims) within the token.
    * Cons:
        The server needs to maintain the secret key securely to prevent unauthorized JWT issuance or tampering.
        If a JWT is compromised, it remains valid until its expiration time, as tokens are self-contained and don't require round-trips to the server for validation.
    * JWT-based Authentication is a stateless and scalable method, making it suitable for distributed systems. It allows for fine-grained control and doesn't require server-side storage. However, the server needs to securely manage the secret key. If a JWT is compromised, it remains valid until expiration.
### c)
#### Recon
Alice implemented a great web service that uses the `JWT` stored in the cookie to authenticate users. So, we can access the token as below:
* Header: `{"alg":"RS256","typ":"JWT"}`
* Payload: `{"username":"guest","flag1":"CNS{JW7_15_N07_a_900d_PLACE_70_H1DE_5ecrE75}","exp":1686041128}`

* Flag 1: Just hide in cookie and use `base64` online decoder, you'll obtain `CNS{JW7_15_N07_a_900d_PLACE_70_H1DE_5ecrE75}`
#### Exp for another flag
The description said another flag is hidden in the account with the username `admin`. Thus, we can tamper the token that used different algorithm to sign the payload.

* Problem 1:
If we have to used another algorithm like `HS256`, we need RSA public key to sing the payload. What is public key(n, e) in this token?
* Problem 2:
How to generate `.pem` file?
* Problem 3:
How to implement `JWT` signature to sign the payload?

---
1. Find the `N` and `e` of RSA public key
    We note that every time your refresh the web page, the tokens are quite different because of different expired time.
    So, how can we used these plaintext and signature pair to construct original `N`
$$
  \downarrow\\
   m_1^e \equiv c_1\ (mod\ N)\\
   m_2^e \equiv c_2\ (mod\ N)\\
   m_3^e \equiv c_3\ (mod\ N)\\
   \downarrow\\
   m_1^e - c_1\ = \alpha N\\
   m_2^e - c_2\ = \beta N\\
   m_3^e - c_3\ = \gamma N
$$

   * Thus, we can find $N$ using $gcd(αN, βN, γN)=N$. Note that the large number calculation can use <font color="FF0000">`gmpy2`</font> library.
   * Remember the work flow of signature in RSA: You can refer [this page](https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html)
   * The work flow is `b'hello'`$\to$do hash by `sha256`$\to$do padding by `pkcs#1v1.5`$\to$ then sign$\to$ciphertext
   * Note 2 From TA: PKCS v1.5 padding 在encryption與signature的操作不太一樣喔，有 random bytes的是encryption，詳細可以參考[spec](https://www.rfc-editor.org/rfc/rfc3447#section-9.2)

   * <font color="FF0000">TA can refer to the first part of `code3-c.py`</font>

2. Generate `public-key.pem` file
   Now, we know what `N` is, so we can generate a `.pem` file with properly format. According to [this page](https://stackoverflow.com/questions/76458680/how-can-i-generate-rsa-public-key-with-specified-n-and-e-parameter-by-using-open), <font color="FF0000">TA can refer to the second part of `code3-c.py`</font>

3. Implement `JWT` to sign the payload by using public key
   <font color="FF0000">Note that you must make sure that the public key has a new line symbol at the end of the file</font>. 

   <font color="FF0000">TA can refer to the third part of `code3-c.py`</font>

4. Then replace the web page original token and you'll get the flag
    Note that the expire time in payload should be careful.

* Flag 2: `CNS{4L9_15_un7Ru573d_u53r_1nPU7}`
### d)
* Just follow the [library code](https://github.com/pyauth/pyotp/tree/develop), <font color="FF0000">TA can refer to `code3-d.py`</font>
  
    Flag: `CNS{2FA_15_9R347_y0U_5H0Uld_h4v3_0N3}`
### e)
* Hint 1: There are strings in the cookie that look like hashes, what could they be? 
* Hint 2: If you failed to figure out what hint 1 means, here’s another method. It’s the era of Machine Learning. Even babies know what Convolutional Neural Network is. 
* Hint 3: What are some common ways to get the user’s IP when the web service is behind a reverse proxy? Are these common practices secure?
#### Recon and Hint
* From the hint and description, we know that our goal is to brute force this login authentication with <font color="FF0000">captcha challenge</font> and <font color="FF0000">rate limitations(3 attempts)</font>.
* As the [reference here](https://xxgblog.com/2018/10/12/x-forwarded-for-header-trick/), we can bypass the rate limitation.
* As the hint above, we have 2 types attack, `CNN recognition`, `replay attack`, and I choose `replay attack`, btw.
The replay attack is just fit the same cookie and captcha parameter at each attack, then we can bypass this captcha.

#### How to exploit?
1. Access `http://cns.csie.org:17505` in Burp Suite
    Intercept the packet and send to <font color="FF0000">Intruder</font>

2. Generate variety IP

    <font color="FF0000">TA can refer to `code3-e-gen_IP.py`</font>

    ```python
    f = open("./Gen_IP.txt", "w")
    
    for i in range(256):
        for j in range(256):
            f.write("140.112."+str(i)+"."+str(j)+"\n")
    
    f.close()
    ```

3. wget password payload
    ```bash
    $ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-10000.txt
    ```

4. Set Payload & Start Attack
    * Use <font color="FF0000">`Pitchfork`</font> as your attack type
      
        ![](https://hackmd.io/_uploads/rkQvwz1v2.png)
        ![](https://hackmd.io/_uploads/BknuPG1wh.png)
        ![](https://hackmd.io/_uploads/SkKtPG1P2.png)

Password: `everett`
Flag: `CNS{8Ru73_f0Rc3_Pr3v3n710N_C4n_83_C0mPl1c473d}`
### f)
One modern authentication method is the FIDO2 security key. This is a physical device that can be used to sign in to web-based applications and Windows 10 devices with your Azure AD account without entering a username or password. It is based on the open standards of FIDO2, which include the WebAuthn protocol and the Client to Authentication Protocol (CTAP).

The FIDO2 security key works by generating a public-private key pair for each account that you register with it. The private key is stored securely on the device, and the public key is sent to the service provider (such as Azure AD) along with a randomly generated attestation certificate that proves the authenticity of the device. When you sign in with the FIDO2 security key, the service provider sends a nonce (a random number) to the device, which signs it with the private key and sends it back. The service provider then verifies the signature using the public key and grants access.

The FIDO2 security key method is better than traditional methods such as passwords or tokens for several reasons:

It is more secure, as it prevents phishing, replay, and man-in-the-middle attacks. The private key never leaves the device, and the attestation certificate prevents spoofing or cloning of the device.
It is more convenient, as it does not require remembering or typing passwords or codes. The user only needs to insert the device and provide a second factor such as a fingerprint or a PIN.
It is more scalable, as it can work across thousands of accounts and services that support FIDO2 without sharing any secrets.

## 4. Accumulator
### a)
* Just following the TODO hint and complete the each sub-function, <font color="FF0000">TA can refer to `code4-a.py`</font>

    
### b) Really thx for R11944034 許智翔 for inspiration
* Goal: We have to construct a fake member $m' \notin S$
* We know: 
    $$
    p=g^{\prod \limits_{s \in S/\{m'\}}S}=g^{\prod \limits_{s \in S}S}=d
    $$
* :+1:If we used normal $p$ and normal $m \in S$: 
    $$
    p^m=g^{\prod \limits_{s \in S/\{m\}}S*m}=g^{\prod \limits_{s \in S}S}=d
    $$
* :-1:If we used normal $p$ and new message $m'$: 
    $$
    p^{m'}=g^{\prod \limits_{s \in S}S \cdot m'}=d^{m'} \neq d
    $$
* :+1:If we used fake proof $p'$ and new message $m'$: 
    $$
    {p'}^{m'}=d^{{\{m'\}}^{-1} *m'}=d
    $$
* We can control proof $p'$ and new message $m'$, so we need to construct fake proof $p'$
    $$
    p' \equiv d^{\{m'\}^{-1}}\ (mod\ N) \equiv p^{\{m'\}^{-1}\ (mod\ \varphi(N))}\ (mod\ N)\ -\ Euler\ Theorem
    $$

    To achieve this attack, one condition must be met: We have to compute $\varphi (n)$, so we need the private key of RSA
    
    Then we can use any member that's not in member set but still can pass the verification.

​	<font color="FF0000">TA can refer to `code4-b.py`</font>

​	Flag: `cns{ph4k3_m3m83r5H1p!}`

### c)
Like the previous question mentioned, we'd like to give a fake proof that can pass the verification process even the member is not in member set.
* We know that if $gcd(m,\ delta)=1$, then we can find coefficient $a$ and $b$ so that $a\cdot m+b\cdot delta=1$: 
    $$
    delta={\prod \limits_{s \in S}s}
    $$
* :+1:If we used normal $p$ and normal $m \in S$: 
    $$
    (g^a)^m\cdot d^b=g^{a\cdot m}\cdot g^{b\cdot ({\prod \limits_{s \in S}s})}=g^{a\cdot m+b\cdot ({\prod \limits_{s \in S}s})}=g
    $$
* :-1:If we used normal $proof=(g^a, b)$ and new message $m'$: 
You can not find $a$ and $b$ to fit $a\cdot m+b\cdot delta=1$
* :+1:If we used fake proof $proof'=(g^{a'}, b')$ and new message $m'$:
If $a'=m^{-1}, b=0$
  $$
    (g^{a'})^m\cdot d^b=g^{m^{-1}\cdot m}\cdot g^{b\cdot ({\prod \limits_{s \in S}s})}=g^{1+0}=g
  $$


​	<font color="FF0000">TA can refer to `code4-c.py`</font>
​	Flag: `cns{N0N_n0n_m3M83RSh1p!}`

### d)
(Skip)

## Reference
### 1. DDoS
* [使用Wireshark分析並發現DDoS攻擊](https://security.tencent.com/index.php/blog/msg/3)
* [Kali Linux網絡掃描秘籍第六章拒絕服務(二)](https://cloud.tencent.com/developer/article/2182801)
* [NTP放大DDoS攻擊](https://www.cloudflare.com/zh-tw/learning/ddos/ntp-amplification-ddos-attack/)
* [分散式阻斷服務攻擊(DDoS)趨勢與防護](https://www.twcert.org.tw/tw/cp-157-6408-e0c62-1.html)
### 3. Web Authentication
#### Basic Authentication
* [How To Create Flask Web App In Digital Ocean Using App Deployment](https://www.youtube.com/watch?v=G1EVWLjwvrE&ab_channel=TechieBlogging)
* [Python Flask – Read Form Data from Request](https://pythonexamples.org/python-flask-read-form-data-from-request/)
#### Cookie-Based Authentication
* [Get and set cookies with Flask](https://pythonbasics.org/flask-cookies/)
* [Python Flask – Read Form Data from Request](https://pythonexamples.org/python-flask-read-form-data-from-request/)
#### JWT-Based
* [[筆記] 透過 JWT 實作驗證機制](https://medium.com/麥克的半路出家筆記/筆記-透過-jwt-實作驗證機制-2e64d72594f8)
* [JWT(JSON Web Token) — 原理介紹](https://medium.com/企鵝也懂程式設計/jwt-json-web-token-原理介紹-74abfafad7ba)
* [JSON Web Tokens Encoder/Decoder](https://jwt.io/)
#### 3.C
* [在Python中使用GMP（gmpy2）](https://kexue.fm/archives/3026)
* [binascii.Error: Incorrect padding](https://blog.csdn.net/qq_38463737/article/details/117637783)
* [problem in run code gives Error: Non-base32 digit found](https://stackoverflow.com/questions/70762719/problem-in-run-code-gives-error-non-base32-digit-found)
* [pyauth/pyotp](https://github.com/pyauth/pyotp/tree/develop)
* [Week12 - 要在不同Server間驗證JWT好麻煩嗎？RS256提供你一種簡單的選擇 - JWT篇 [Server的終局之戰系列]](https://ithelp.ithome.com.tw/articles/10231212)
* ['bytes' object has no attribute 'oid'](https://stackoverflow.com/questions/75461879/bytes-object-has-no-attribute-oid)
* [EMSA-PKCS1-v1_5 Specification](https://www.rfc-editor.org/rfc/rfc3447#section-9.2)
* [EMSA_PKCS1_V1_5_ENCODE Implementation](https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_v1_5.py)
* [Generate PEM file with specified RSA parameter](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html#Crypto.PublicKey.RSA.construct)
* [How can I generate rsa public key with specified n and e parameter by using openssl?](https://stackoverflow.com/questions/76458680/how-can-i-generate-rsa-public-key-with-specified-n-and-e-parameter-by-using-open)
* [How can I generate JWT token using HMAC? How is the signature created?](https://stackoverflow.com/questions/74063656/how-can-i-generate-jwt-token-using-hmac-how-is-the-signature-created)
* [JWT encoding using HMAC with asymmetric key as secret](https://security.stackexchange.com/questions/187265/jwt-encoding-using-hmac-with-asymmetric-key-as-secret)
#### 3.E
* [X-Forwarded-For](https://xxgblog.com/2018/10/12/x-forwarded-for-header-trick/)
* [Intruder帳密暴力破解與列舉FUZZING找漏洞的好幫手](https://ithelp.ithome.com.tw/articles/10245914)
* [Intruder Attack type & Payloads - 擁有千種姿態的攻擊模式](https://ithelp.ithome.com.tw/articles/10246457)
### 4. Accumulator
* [淺談 RSA Accumulator](https://antonassocareer.medium.com/淺談-rsa-accumulator-與stateless-client-a75f00ad388e)
* [歐拉定理的介紹](https://youtu.be/fm8L6k1lu8E)
* [歐拉函數的觀察](https://youtu.be/CNQeixKoclU)
* [歐拉函數的計算法](https://youtu.be/DzzBZwjjSrY)
* [歐拉定理的論證](https://youtu.be/P8VjTGAQQUo)