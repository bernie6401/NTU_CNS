# NTU CNS Homework 1 - CTF

## Simple Crypto
In this problem, the first two round and last round I just use the online tools to decrypt it and access to the next round. Therefore, there is no extra code about ROT-based and rail fence cipher.
* Round 3: please execute `code5-3.py` directly, and input the `c1` base64, `m1` string, and `c2` base64 manually.
For example:
![](https://imgur.com/FDgDQA8.png)
In this round, you must enter the string like below, and you can fetch the `m2` and then copy the `m2` strings and paste to command prompt to get to next round
    ```bash!
    c1 base64 = ucgF6fkzj/TvPuZC2nNKYyR5SRorpYtu7x7lNDohhCj/ydIXs+kRm2kxo628BQAzLiQ1D2eLG28=
    m1 string = practice to program to generate cryptographic algorithms
    c2 base64 = qtUJ+vguhf+oavkN3WRXKHZoUVgzo8gp4RX5ans3lHy82thHs+4TyU0voqOyREEyKCgvD32G
    computing power, public key, but as the Enigma machine
    ```
    Note that, if the length of `c1` is less than `c2`, you must quit the query this time, because my code can not predict the key.

* Round 4: Just execute `code5-4.py` directly, and input the cipher `c` then you'll get a lot of 0 and 1, please copy them and use online tool that I provided in write up to decrypt bacon cipher and rail fence cipher respectively.

    For instance: 
    ![](https://imgur.com/eA2f5Fh.png)
    Then you should copy the cipher and enter it in my code.
    ```bash!
    Cipher Text of Round 4: oh gOod! I WAS juSt thInKING thaT thE SiLk FLOweRS aT the FeiyUN cOMmerce GuiLD NeeDed watEriNg. the transPOrT coOrdInaTORs wILL prOBablY MoaN ABouT the muDdy MOuNTaIn RoaDS again, thoUgh...
    11101100001101110100001110110010100011001011101110010011111011000110111110110111111111001011011011000110001100111001100011011111011001001010110011111111011
    ```
    And use the online tool like below, then you'll get into the next round
    ![](https://imgur.com/crmC7RQ.png)
## ElGamal Cyrptosystem
In this question, just execute `code6-1.py` and `code6-3.py` and they'll show the flag directly.
## Bank
Just execute `code7.py` and it'll show the flag directly. Note that, must let two `.pdf`files(`shattered-1.pdf` and `shattered-2.pdf`) be in the same folder with `code7.py` so that it can achieve collision.
## Clandestine Operation
Just execute `code8-1.py` and `code8-2.py` and they'll show the flag directly.