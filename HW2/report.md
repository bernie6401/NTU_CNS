# Cryptography and Network Security – Homework 2
###### tags: `NTUCNS`
Student ID: `R11921A16`
Name: 何秉學

## Handwriting
### 1. SYN Cookies
1. Ans:
This strategy involves the creation of a cookie by the server. In order to avoid the risk of dropping connections when the backlog has been filled, the server responds to each connection request with a SYN-ACK packet but then drops the SYN request from the backlog, removing the request from memory and leaving the port open and ready to make a new connection. If the connection is a legitimate request, and a final ACK packet is sent from the client machine back to the server, the server will then reconstruct (with some limitations) the SYN backlog queue entry. While this mitigation effort does lose some information about the TCP connection, it is better than allowing denial-of-service to occur to legitimate users as a result of an attack.

2. Ans:
The timestamp is used to ensure that the cookie is valid and has not expired. When a server generates a SYN-ACK packet with a cookie, it includes a timestamp that indicates the time when the packet was sent. The client must respond with an ACK packet that includes the same timestamp value. If the timestamp is too old, the server will reject the connection request.

    The client's IP address is also included in the cookie as a way to prevent attackers from using previously generated cookies to establish connections. Since the client's IP address is included in the cookie, it is specific to that particular client and cannot be used by other clients. If an attacker tries to use a previously generated cookie, the server will reject the connection request since the client's IP address in the cookie will not match the IP address of the attacker.

3. Ans:
   A MAC provides both message integrity and authenticity, whereas a hash function only provides message integrity. This means that a MAC can not only detect if a message has been tampered with, but also confirm that the message was sent by the expected sender.

    In the context of SYN cookies, using a MAC to generate a unique code ensures that the cookie is not only secure from tampering or modification but also that it is authentic and generated by the expected server. This provides an extra layer of security against attackers who may attempt to spoof the server's identity and generate fake cookies.

    Another advantage of using a MAC is that it is more resistant to key recovery attacks compared to hash functions. Key recovery attacks involve attempting to recover the secret key used by the hash function or MAC, which can allow an attacker to generate valid cookies. MACs are typically more secure than hash functions because they use a more complex process to generate the code, making it more difficult for an attacker to recover the key.
### 2. BGP
1. Ans:
In this case, `AS 999` should announce the longer IP prefix than the target(`AS 1000`), e.g. `10.10.220.0/23` so that BGP will choose the longer one as the packets route path

2. We can review the example in class that talked about China Telecom intercepted 15% of IP prefixes using prefix hijacking:
    <center><img src="https://dl.acm.org/cms/attachment/1cca5d53-98d3-49ad-8545-6f58e7aeaf1c/goldberg2.png)"></center>

    > **Decision 1: AT&T (`AS 7018`) chooses to route to China Telecom.** In Figure 2, AT&T (`AS 7018`) has two available paths to the prefix. However, since the path advertised by China Telecom (`AS 4134`) is shorter, AT&T (`AS 7018`) chooses to route to China Telecom.
    >
    >**Decision 2: Level 3 (AS 3356) chooses not to route to China Telecom.** In order for traffic to leave China Telecom’s network and flow on to the intended destination, China Telecom requires a neighbor that does not choose the path it advertises. In the example above, this occurs when Level 3 (AS 3356) chooses to route through its customer Verizon (`AS 6167`) instead of through its peer China Telecom (`AS 4134`). Thus, China Telecom can send traffic towards Level 3 and have it arrive at the intended destination.

    a)Ans:
    In this case, `AS 999` first announced the shorter AS-path so that all of the packets would choose `AS 999` as their next station. Second, in order to leave `AS 999` network and flow on to the intended destination, it requires a neighbor that does not choose the path it advertises. In this example, this occurs when `AS 2` chooses to route through its customer `AS 1` instead of through its peer `AS 999`. Thus, `AS 999` can send traffic towards `AS 2` and have it arrive at the intended destination
    The update message is like {`10.10.220.0/22`, [`AS 999`, `AS 998`, `AS 998`]}

    b)Ans:
    * Path prepending can be used to influence traffic to take a longer, less desirable path. An attacker can add extra instances of their own AS number to their advertised routes, making them appear less attractive to other ASs. This can cause traffic to flow through other paths that the attacker controls, allowing them to monitor or manipulate the traffic.

    * Loop prevention can be exploited by attackers to create routing loops intentionally. By manipulating BGP announcements, an attacker can create a situation where routing loops occur, causing network congestion or even network outages.

3. Ans:
    * One of the advantage is enhances security:
    The maximum prefix limit can reduce the threat of BGP hijacking and routing errors to network security by preventing unnecessary routing information from entering the network.
    * But it still exist some disadvantage, such as it may block legitimate routing information:
    In some cases, legitimate routing information may be misidentified as illegitimate routing information and blocked. For example, some networks may have a large number of BGP prefixes that exceed the maximum prefix limit, and these prefix information may be misidentified as illegitimate and blocked.


### 3. Knowing What I Am, Not Knowing Who I Am
The whole workflow is as below:
<center><img src="https://i.imgur.com/iV3NuDm.png"></center>

where $c_m=E_{pkm}(w;r_m)\ \forall\ i\ \in {1,...,l}$ and $w'=D_{ski}(c_i)$
1. Ans:
$$
\begin{aligned}
Pr[Exp_{\pi ,A, l}^{anon}(n)=1]&=Pr[j=i|cheat_s=0] \\
&=Pr[j=i|c_m=E_{pkm}(w;r_m)\ \forall\ m\ \in\ \{1,...,l\}]\\
&=Pr[j=i|c_m\oplus E_{pkm}(w;r_m)=0\ \forall\ m\ \in\ \{1,...,l\}]\\
&=Pr[j\oplus i=0|c_m\oplus E_{pkm}(w;r_m)=0\ \forall\ m\ \in\ \{1,...,l\}]\\
\end{aligned}
$$
If the adversarial server $S$ used the same random number $w$ to encrypt each ciphertext, then the given condition in this probability will not affect the result, that is the given condition is not associate to guessing result $j$. So, the probability of the statement will be equal to $Pr[j\oplus i=0]\le {1\over l}$

2. Ans: In my perspective, we can refer to `k-anonymity` to split $k$ users that has the same attributes as a group. In addition, they can share the same public/private key to decrypt the ciphertext or verified the adversarial server is cheating or not. Then the complexity of the verified process can be more efficiency, i.e. $O(l\over k)$ where there're $l$ users and each group has $k$ users that has similar attributes.

3. Ans: 這一題的假設是讓user自己生產自己的public key然後上傳到server供其他人下載嗎?想不出來


## CTF
### 4. TLS
#### Recon
What if the two prime factors p and q of an RSA modulus n are too close to each other?
Note that Ncat does not support TLS, so you may need to use other tools like OpenSSL to establish a connection to the server.
`$ openssl s_client -connect cns.csie.org:12345`

1. Try to factorize public key by using [online tool](https://www.alpertron.com/ECM.HTM)

2. Construct private key
    ```python
    >>> from Crypto.Util.number import inverse
    >>> p=27171899387582994630080241635149110083271663600309412521746050077768885906315627389853968666978344583062190025422406556299962462577371938126502805594063354420813465504379781719813559864324424860667828794143342554880661764085821586961603756682754593972938581924631795195026434529901154406060011099096550054692948775946026202445725528280139742483813426388247330680581603463449714704030064353339761917890699417992071180183947964103967284932770956957844989073082639407508192226568377226601600813327551969255729045779934469524197423719313463774332606735758556445171050839176603767275802969849771354230198787362147064261141
    >>> q = 27171899387582994630080241635149110083271663600309412521746050077768885906315627389853968666978344583062190025422406556299962462577371938126502805594063354420813465504379781719813559864324424860667828794143342554880661764085821586961603756682754593972938581924631795195026434529901154406060011099096550054692948775946026202445725528280139742483813426388247330680581603463449714704030064353339761917890699417992071180183947964103967284932770956957844989073082639407508192226568377226601600813327551969255729045779934469524197423719313463774332606735758556445171050839176603767275802969849771354230298787362147064261753
    >>> phi_n = (p-1)*(q-1)
    >>> inverse(65537, phi_n)
    471182755778531633837595254982392912025203887450675396173052859951517226327308287900569077573364523920057914854393577740186889850202056700205386190405605462108974792901403115381842095468788204747698304697390945163288343872000620563081945267258671474601542919120102730194721238439211991571325691228395891189282500624319258308667980205186674536584717833266977397744127443006730525078605511941645755885134412912779841630021416603114887877542810924836148144149072482784493014142576398535481803211441860774359442834382450586896485662461769369027933268431598257015049427650623765345072281579244866783437350396619862565737627763575514488335944795541995433605729652918306987153468955004556117838020882436357536473693421452686248238163534518808971680955943532476013599759458268294381520872799953359615598298222319020925397677745581907581310692655121309300095562888539980842742239635926584038343456014891878918451322001100154737187176145201686105552229473727339669113582294232621679208173518946872148410645516312281953157344683484963494463304752322686067736852981814079919012126538862044280554201637714290133745624435881055700349008833523600149235721690153645535830972099526514511047334339269312883123405652148571373677266783312996648420101473
    ```

3. Construct Pem File - Refer to [this page](https://crypto.stackexchange.com/questions/46653/how-would-i-encode-rsa-private-key-given-that-i-know-the-decimal-representation)
    ```python
    >>> from Crypto.PublicKey import RSA
    >>> n = 0xb4f98200f1309e8a486824051051ac80790f8e66dac4744e2ce5134fb432121f41c5471e3459d01e56e64befd2034c65eb300ebf0045342221bff206b6cdda7f3349c17b08563a576731f95a64e2f00af70b5cbb2f4f388d49ce82da76ca609a6ec1529f29b0fa0bedc5764b86472e2c5ac5198cedb6f5e1e8e0ca950ea11bc4cf5e5a0497db3ad96f5a745cf902d56be394a259068fe198bc9de8fe8d034a71013f46c2ac72451211eb1127286c19467eaf3a10049942d46b0f49f3c51c01c06a2f8c94416cc1aadaeb191de959f0241ce8f32575c848bd2f4f8f84dab46e2aa7ad45de1c6060fbbee9668f8e9cb6d366b8cd6ce99f78bbef145f2b7b7e5222f762ccb95f17b1538260c2ea45571061b0d873fbe60d61dd87aa4833ac71b802f2b91d30f38e30ae9da39fbd1c53e80496f511521285b3bb1da3dc79931463d278d1fe28a77880a9f2368029c4cefffebbbd6904f85291b3606d0b5ed3efd8c1ee14538dc051274665f4b0f55d6c6e12d2cb728ac15f7a6572b71a5bd6fa01bddb0af211091bff4c8ec7e93efae4654b2abae09e35be29afbfc3f4df8e4348c525b9d8662a1ac344dadb15b953905f639b48fec7cfcfdf27cc0ad82b936d5efe7c0d891bf9752d3fb0857d38337df033e4b681d19ec8603535504d05a421036c077694482eee919a44b3296e2a4c272cbf7bbf14b6d62eb194e4ee83ba227fed
    >>> e = 0x10001
    >>> d = 0x737efcd1df1b7942a53d1927c62769a0c022066e6bd58ea8498c948b7c63ac1f18996f6ebe584732e5a0a9fbce9ade49f913bd857605b464c80738cdc22293fc33de314574a79b2a26a8c50b447174627b115c47f5c46841fb45794b351ea91245f6c8e4dcf59e4eb89b1988cf9463ca58cf8b23de9db2444f9c0e8d9c3d837c521f53f1b47c6c0d523c7720d2a655503a78a4378eb18a773080d2ae898dfd172b8597822c0ded38c008b5f4b89e6c6f09f0886caa92a90ce99a6346d897ac2281620124a8b060d4ca4bd9c6b622f8d8033f43d5b75a6fd994f50091f805c87d1e6fbdb42785f6bf1332df8a64a86d21736023720b9303b964b62a9a9480a4a7ab5fac794f583109d5663998ccc893590ebe26ae076e17c2b93c2238106612094fd4c6a56ec84ca5fa6ee3608ba3422f931828772e6732c337fcd6d4e6cb4a907d2e978227423d783c112f7a7d3e6d7c91ac7c540f0095d39842a6be534321a67d7a3fcb1c62c0f9e8a6d6e10281e10ff957449770d19f939153692c73f940450eab03f58ef55d2adf98c3f8479d05bb02997667381d3583c8f0eba6ea91bce512b001a27788309a4aa15952c73572a329b2f3acd6a11f43e3ae00532ccfbe9f157702162b534d26ca1e668d4cdbfd0116b7cb724603ea99e8aa08c90410534dd681b59350542c59523cb1259428e05e1fe0aab479c4b5af2a44d18ef713cd61
    >>> p = 0xd73e2ef8f2e4f1de44ee80070beef39943d4fa89a7a7ab4b0061e851aca7deb4f717f2baf4a0c018f3dcdab92148596bc50800fd6eb2f2e7757e0343534aea2241f0a2d34795a08f8e5ccc7959184b9cf8e3007a8ad63acd7d4b350dbf2d4caf04f4bc98d74a3b01d3b1aced745133186fd8460a2dff536a74ee4d041c988d5743cc9355144f48fe5f52db0449a46ba7c15c04001a5cb141796b5b42d9d72c36cca6d6bb8f177aee1699a47ba5d87c7ee886467af18403dbd84e102a952ebee03cc70bcf072c26b1b1f0f5094be08470c6c1769b417feffd5c89a0c373f75a350d177309618bfeb16316c660c6b2a341a984c8845081ede7c42e22cc9272aa15
    >>> q = 0xd73e2ef8f2e4f1de44ee80070beef39943d4fa89a7a7ab4b0061e851aca7deb4f717f2baf4a0c018f3dcdab92148596bc50800fd6eb2f2e7757e0343534aea2241f0a2d34795a08f8e5ccc7959184b9cf8e3007a8ad63acd7d4b350dbf2d4caf04f4bc98d74a3b01d3b1aced745133186fd8460a2dff536a74ee4d041c988d5743cc9355144f48fe5f52db0449a46ba7c15c04001a5cb141796b5b42d9d72c36cca6d6bb8f177aee1699a47ba5d87c7ee886467af18403dbd84e102a952ebee03cc70bcf072c26b1b1f0f5094be08470c6c1769b417feffd5c89a0c373f75a350d177309618bfeb16316c660c6b2a341a984c8845081eded2ff580f9f582ac79
    >>> key_params = (n, e, d, p, q)
    >>> key = RSA.construct(key_params)
    >>> f = open('./rsaprivatekey.pem', 'w')
    >>> f.write(key.exportKey().decode())
    >>> f.close()
    ```
4. Decrypt SSL Package - Refer to [this page](https://gohalo.me/post/decrypt-tls-ssl-with-wireshark.html)
   Setting in `/Edit/Preferences/TSL/RSA keys list` as below and click `OK`:
   ![](https://i.imgur.com/Q7BhZhe.png)
   Then we can observe that some packages can decrypt `TLS` message:
   Set the wireshark's filter to `data`
    ![](https://i.imgur.com/uRqJ70b.png)
   
    Then we can browse each packages that be decrypted and we can fetch the username and password
    Username: `Alice413`
    Password: `dogsarecute`
    Command: `Flag...plzzzzz...`
5. Cannot connect to server directly...
   
    ```bash
    $ openssl s_client -connect cns.csie.org:12345
    CONNECTED(00000003)
    depth=1 C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
    verify error:num=19:self signed certificate in certificate chain
    verify return:1
    depth=1 C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
    verify return:1
    depth=0 C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = TA, CN = CNS, emailAddress = cns@csie.ntu.edu.tw
    verify return:1
    ---
    Certificate chain
     0 s:C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = TA, CN = CNS, emailAddress = cns@csie.ntu.edu.tw
       i:C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
     1 s:C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
       i:C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
    ---
    Server certificate
    -----BEGIN CERTIFICATE-----
    MIIFgTCCA2kCCQCQOH8t8/tG3TANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC
    VFcxDzANBgNVBAgMBlRhaXdhbjEPMA0GA1UEBwwGVGFpcGVpMRAwDgYDVQQKDAdO
    VFUgQ05TMQ0wCwYDVQQLDARST09UMQ0wCwYDVQQDDARST09UMSIwIAYJKoZIhvcN
    AQkBFhNjbnNAY3NpZS5udHUuZWR1LnR3MB4XDTIzMDQwNzE0MzYxOFoXDTIzMDYw
    NjE0MzYxOFowgYAxCzAJBgNVBAYTAlRXMQ8wDQYDVQQIDAZUYWl3YW4xDzANBgNV
    BAcMBlRhaXBlaTEQMA4GA1UECgwHTlRVIENOUzELMAkGA1UECwwCVEExDDAKBgNV
    BAMMA0NOUzEiMCAGCSqGSIb3DQEJARYTY25zQGNzaWUubnR1LmVkdS50dzCCAiIw
    DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALT5ggDxMJ6KSGgkBRBRrIB5D45m
    2sR0TizlE0+0MhIfQcVHHjRZ0B5W5kvv0gNMZeswDr8ARTQiIb/yBrbN2n8zScF7
    CFY6V2cx+Vpk4vAK9wtcuy9POI1JzoLadspgmm7BUp8psPoL7cV2S4ZHLixaxRmM
    7bb14ejgypUOoRvEz15aBJfbOtlvWnRc+QLVa+OUolkGj+GYvJ3o/o0DSnEBP0bC
    rHJFEhHrEScobBlGfq86EASZQtRrD0nzxRwBwGovjJRBbMGq2usZHelZ8CQc6PMl
    dchIvS9Pj4TatG4qp61F3hxgYPu+6WaPjpy202a4zWzpn3i77xRfK3t+UiL3Ysy5
    XxexU4JgwupFVxBhsNhz++YNYd2HqkgzrHG4AvK5HTDzjjCunaOfvRxT6ASW9RFS
    EoWzux2j3HmTFGPSeNH+KKd4gKnyNoApxM7//ru9aQT4UpGzYG0LXtPv2MHuFFON
    wFEnRmX0sPVdbG4S0styisFfemVytxpb1voBvdsK8hEJG/9MjsfpPvrkZUsquuCe
    Nb4pr7/D9N+OQ0jFJbnYZioaw0Ta2xW5U5BfY5tI/sfPz98nzArYK5NtXv58DYkb
    +XUtP7CFfTgzffAz5LaB0Z7IYDU1UE0FpCEDbAd2lEgu7pGaRLMpbipMJyy/e78U
    ttYusZTk7oO6In/tAgMBAAEwDQYJKoZIhvcNAQELBQADggIBADUURCitnBqjR2LL
    EziFxRWGZTP6TtsqMgqRu1UJaeyeFR+8y+ou1IWQE+4T80ygsXvFiDyF+ZtrpEML
    qottWHOrN5/J5MxxLi6qvRbz/TpEQEn7iTWc56CyOzNStJ2hNyAzl2z/mkHefxog
    OuaVfr2qnC6k2Hy+7ZFxIZCIDs9/8pXrWO+0p7HzwMTAaZS5egzPASM5MYHkfBBO
    EIMjQVNxPJJq3XrQEUsHbgcgDnYrtx3z40Vg7phUEtxObXBvRL7pSVUDbSRORXcI
    kBJjgA950mQnBbDulfnu44qquJb/767SETMRIz7qWGEXHqiWG8XONYoi04Q/wOlg
    lVuenzCZWDDGV34CKhvKhJ6/TbOZ1GB2s1FZh8l0szjLiODditvlfE9VcV4OWH5u
    h7FgUC6bn2fclmybtEDX99YH23nKgpMgHliy8YsuK7t/hUS31HklUBKPRlrqc+nK
    VrrpH7Z+g/KeHqxVDnu0eM1wLqqCCe+QDiTZUOg1Ixu/7TjLVSBoNrjtqexj0KWK
    VYvXo8YskiZv0I5J9N1YXIutXWUSorGQPAhdE/wCNJKhdYxFjJy+F9qM8f4eaIWC
    f4Yv+m7tAwNjuNJBpj8R6GXWk0r4j6+vtrbanKru94BbG3tcUciVPGamhbSDLMgH
    sIkh+nDYy4AtBA87hAgUSKP/kkkA
    -----END CERTIFICATE-----
    subject=C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = TA, CN = CNS, emailAddress = cns@csie.ntu.edu.tw
    
    issuer=C = TW, ST = Taiwan, L = Taipei, O = NTU CNS, OU = ROOT, CN = ROOT, emailAddress = cns@csie.ntu.edu.tw
    
    ---
    No client certificate CA names sent
    Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224
    Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
    Peer signing digest: SHA256
    Peer signature type: RSA-PSS
    Server Temp Key: X25519, 253 bits
    ---
    SSL handshake has read 3713 bytes and written 424 bytes
    Verification error: self signed certificate in certificate chain
    ---
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Server public key is 4096 bit
    Secure Renegotiation IS NOT supported
    Compression: NONE
    Expansion: NONE
    No ALPN negotiated
    Early data was not sent
    Verify return code: 19 (self signed certificate in certificate chain)
    ---
    140631277094208:error:1409445C:SSL routines:ssl3_read_bytes:tlsv13 alert certificate required:ssl/record/rec_layer_s3.c:1563:SSL alert number 116
    ```

#### Exploit
1. Try to use the info above to register a verified CA
   
    The following info that you should fill in can be found in wireshark. You can use string search by `Taipei` or `NTU CNS`
    ![](https://i.imgur.com/pJgFLGU.png)
    
    ```bash
    $ openssl req -new -key private.key -out new_ca.csr
    $ openssl req -x509 -new -nodes -key private.key -sha256 -days 36500 -out rootCA.crt
    $ openssl x509 -req -in new_ca.csr -CAkey private.key -CA rootCA.crt -CAcreateserial -out new_ca.crt
    ```
    Using `ROOT` as your certificate info.
2. Create your own certificate
   
    ![](https://i.imgur.com/czn4yRS.png)
    
    ```bash
    $ openssl genrsa -out mykey.key
    $ openssl req -new -key mykey.key -out my_new_ca.csr
    $ openssl x509 -req -in my_new_ca.csr -CAkey private.key -CA rootCA.crt -CAcreateserial -out my_new_ca.crt
    ```
    Using `Alice413` as your certificate info.
3. Connect To Server with `.crt` & `.key`
    ```bash
    $ openssl s_client -connect cns.csie.org:12345 -cert my_new_ca.crt -key mykey.key
    ```
    Flag: `CNS{ph4Ul7y_K3y_93n3R471oN_15_D4N93rOU2!}`
    
    
    
    Another Payload From @`B10902070林鈺翔`(PS: thx a lot)
    
    ```bash
    $ openssl req -new -key CAkey -out CA.csr -subj "/C=TW/ST=Taiwan/L=Taipei/O=NTU CNS/OU=ROOT/CN=ROOT/emailAddress=cns@csie.ntu.edu.tw"
    $ openssl x509 -req -sha256 -days 365 -in CA.csr -signkey CAkey -out CA.crt
    $ openssl req -x509 -new -nodes -key CAkey -sha256 -days 36500 -out rootCA.crt -subj "/C=TW/ST=Taiwan/L=Taipei/O=NTU CNS/OU=ROOT/CN=ROOT/emailAddress=cns@csie.ntu.edu.tw"
    
    $ openssl genrsa -out mykey
    $ openssl req -new -key mykey -out mykey.csr -subj "/C=TW/ST=Taiwan/L=Taipei/O=NTU CNS/OU=VIP/CN=Alice413/emailAddress=cns@csie.ntu.edu.tw"
    $ openssl x509 -req -CAcreateserial -days 365 -sha256 -CA rootCA.crt -CAkey CAkey -in mykey.csr -out mykey.crt
    
    $ openssl s_client -connect cns.csie.org:12345 -cert mykey.crt -key mykey
    ```

### 5. Little Knowledge Proof
#### Recon
a) This problem is given two server to simulate Alice and Bob communication. How about Men-In-The-Middle attack?

b) Given $y=g^x\ (mod\ p)$, $a=g^r\ (mod\ p)$. And the output is $w=cx+r$. Therefore, if you want to know what $x$ is, the simplest way is $x={w-r\over c}$ and let $c=1$. Then what is $r$?
My first perspective is using the exploit of LCG, that is:
$$
\left\{ 
  \begin{array}{c}
    a^1=g^{S_0} (mod\ p)\\
    a^2=g^{S_1} (mod\ p)\\
    a^3=g^{S_2} (mod\ p)\\
  \end{array}
\right.
\ \ and\ \ 
\left\{ 
  \begin{array}{c}
  \begin{aligned}
    a^1&=g^{S_0} (mod\ p)\\
    a^2&=g^{(AS_0\ +\ C)\ (mod\ p)} (mod\ p)\\
    a^3&=g^{(AS_1\ +\ C)\ (mod\ p)} (mod\ p)\\
  \end{aligned}
  \end{array}
\right.
$$

But this is too complicated, there must exit an easy way~~
Our goal is we wanna know what $x$ is.

c) Hint: find the order of the group. Can you factorize the order?
The Pohlig-Hellman algorithm is very useful in practice if the order of the group in which we would like to solve a given discrete logarithm problem is smooth, that is it has only "small" prime divisors. Hence the discrete logarithm problem in a group $G$ is as hard as the discrete logarithm problem in the largest subgroup of prime order in $G$.
Refer to [online tool](https://shrek.unideb.hu/~tengely/crypto/section-6.html#p-204-part9) provided by @`B10902070林鈺翔`
#### Exploit
a) Assume 
$$
a=g^r (mod\ p) \\
w=cx+r \\
Verified\ Expression \to g^w=y^c*a(mod\ p) \\
$$
```sequence
Note left of Alice: Choose random r and compute a
Alice->Bob: a
Note right of Bob: Choose a random challenge c∈Zp
Bob->Alice: c
Note left of Alice: Compute w
Alice->Bob: w
Note right of Bob: Verify that verified expression
```
So, this problem's exploit solution is just access two server respectively and copy the $a$ and $w$ from Alice and paste it to Bob and copy $c$ from Bob and paste it to Alice. Finally, we'll fetch the flag 1.
* Flag 1: `CNS{Man_1n_4he_M1dd1e_a44ack}`

b) The main idea is if we input $c=0$, then we can fetch $r_0$ from server(because $w \leftarrow r_0$), and we can use $r_0$ to compute $r_1$ and let $c=1$ to get $x$(because $w \leftarrow x+r_1$, $x \leftarrow w-r_1$)
* Flag 2: `CNS{r&omne$$$hould_B_unp#ff0000ic\tle}`
	* Whole Exploit can refer to `code5b.py`


c)
* The source code is as below and just execute in [online tool](https://shrek.unideb.hu/~tengely/crypto/section-6.html#p-204-part9)
    ```sage
    def PohligHellman(g,h,p):
        pretty_print(html('The prime $p$ is $%s$'%latex(p)))
        F=GF(p)
        g1=F(g)
        h1=F(h)
        N=p-1
        qi=[r^N.valuation(r) for r in prime_divisors(N)]
        pretty_print(html('Prime power divisors of $p-1: %s$'%latex(qi)))
        lqi=len(qi)
        Nqi=[N/q for q in qi]
        gi=[g1^r for r in Nqi]
        hi=[h1^r for r in Nqi]
        xi=[discrete_log(hi[i],gi[i]) for i in range(lqi)]
        pretty_print(html('Discrete logarithms $x_i=%s$'%latex(xi)))
        x=CRT(xi,qi)
        pretty_print(html(r'We have that $\log_g h=%s$'%latex(x)))
        return x
    PohligHellman(11,9561649903826401194424429829087038008994189104830088932155338858706813419184358908819778209856931077467756994935446807814714436047612742953865073558777496,14441638348624213626083118173029616034636236203323405960283519413957104355762238013154233838351528737517308038661176687865191516418733778513644060317253479)
    ```
    
    ```
    The prime p is 14441638348624213626083118173029616034636236203323405960283519413957104355762238013154233838351528737517308038661176687865191516418733778513644060317253479
    Prime power divisors of p−1:[2,9904578032905937,288441413567621167681,3091058643093537522799545838540043339063,1080244137479689290215446159447411025741704035417740877269,756943935220796320321]
    Discrete logarithms xi=[1,5433650772715221,215701847164204296075,1765169489445336822335616493450319873721,522719848230573526650683484133826256116093515592372329920,371628781438728217083]
    We have that loggh=1995135457311837329338013220674023065119097253499626394183669323611116768755869053
    
    1995135457311837329338013220674023065119097253499626394183669323611116768755869053
    ```
    
    Then we can transfer the result to `ASCII` string that is a flag.
    Flag: `CNS{CDH_f@!l_wHEn_tHE_'_is_uns@Fe}`

### 6. Clandestine Operation II
#### Recon
#### Exploit
a) The detailed process is as below:
1. The client sends a negotiation request to the server, indicating that it wants to use NTLMv2 authentication.
2. The server responds with a challenge. The challenge is a random number that is generated by the server and sent to the client.
3. The client encrypts the challenge including **Client Nonce + Server Nonce + Timestamp + Username + Target** using its password and sends the result back to the server. The encryption process involves the use of a hash function(**HMAC-MD5**) to transform the password into a fixed-length value.
4. The server uses its copy of the user's password to encrypt the challenge, then compares the result with the encrypted value sent by the client. If the two values match, the user is authenticated. 

b) Ans: 
1. The client sends a negotiation request to the server, indicating that it wants to use NTLMv2 signing with key exchange scheme.
2. The server responds with a challenge, which includes a nonce (a random number).
3. The client generates a session key by hashing the user's password with the nonce.
4. The client encrypts the session key with the server's public key and sends it to the server.
5. The server decrypts the session key using its private key.
6. Both the client and the server now possess the same session key, which is used to sign messages exchanged between them.
7. Each message is signed using a Message Authentication Code (MAC), which is generated by applying a cryptographic hash function to the message and the session key.
8. When a message is received, the recipient verifies the MAC to ensure that the message has not been tampered with.

c) skip

d) skip


### 7. So Anonymous, So Hidden
#### Recon
1. The main purpose of this problem is just forward the packet to the correct recipient. But can not let the attacker use timing analysis to compromise the mixer. So, we can create a list as a buffer and send them at the same time.

2.  Just reflect the operation of decrypting and construct the encrypting part.

3. skip

4. skip
#### Exploit
1. Source Code can refer to `code7a.py`

    Flag: `CNS{H3Y_Y0u_Ar3_A_m1x3R_ma573R}`

2.  Source Code can refer to `code7b.py` and `code7b-lib.py`. <font color="FF0000">Though the result is not correct but theoretically, the logic is quite make sense.</font> I have no extra time to debug the code... Just FYR to TA..

3. skip

4. skip

## Reference
### 1. SYN Cookies
* [What is SYN flooding attack? - SYN 洪水攻擊](https://www.cloudflare.com/zh-tw/learning/ddos/syn-flood-ddos-attack/)

---
### 2. BGP
* [Characterizing Large-scale Routing Anomalies: A Case Study of the China Telecom Incident](https://people.cs.umass.edu/~phillipa/papers/Hiran_Pam2013_full.pdf)
* [Why Is It Taking So Long to Secure Internet Routing?](http://queue.acm.org/detail.cfm?id=2668966)


---
### 4. TLS
* [How would I encode RSA private key, given that I know the decimal representation of all of its components?](https://crypto.stackexchange.com/questions/46653/how-would-i-encode-rsa-private-key-given-that-i-know-the-decimal-representation)
* [使用 Wireshark 解密 SSL/TLS 流量](https://gohalo.me/post/decrypt-tls-ssl-with-wireshark.html)
* [SSL protocol seems to be missing in Wireshark](https://superuser.com/questions/1430350/ssl-protocol-seems-to-be-missing-in-wireshark)
* [Using OpenSSL s_client commands to test SSL connectivity](https://docs.pingidentity.com/r/en-us/solution-guides/htg_use_openssl_to_test_ssl_connectivity)
* [使用 OpenSSL 製作萬用字元 SSL 憑證](https://blog.darkthread.net/blog/issue-wildcard-ssl-cert-with-openssl/)
* [如何使用 OpenSSL 建立開發測試用途的自簽憑證 (Self-Signed Certificate)](https://blog.miniasp.com/post/2019/02/25/Creating-Self-signed-Certificate-using-OpenSSL)
* [openssl s_client -cert: Proving a client certificate was sent to the server](https://stackoverflow.com/questions/17203562/openssl-s-client-cert-proving-a-client-certificate-was-sent-to-the-server)


---
### 6. Clandestine Operation II
* [What is NTLMv2 - 冷知識 - NTLMv1 為什麼不安全?](https://blog.darkthread.net/blog/why-ntlmv1-not-secure/)

---
### 7. So Anonymous, So Hidden