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

It is a QR code and it decodes to `asdsdgbrtvt4f5678k7v21ecxdzu7ib6453b3i76m65n4bvcx`. We send this string as a password to the netcat applcation and we get the flag:

#### Flag

ctf{1e894e796b65e40d46863907eafc9acd96c9591839a98b3d0c248d0aa23aab22}

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

#### Flag

ctf{cc3a329919391e291f0a41b7afd3877546f70813f0c06a8454912e0a92099369}

## Russian doll

Another challenge that keeps popping up in CTFs, archives in archives. I personally dislike this challenge because it's not much you can learn from it. I've written this really ugly bash script to extract the flag:

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

Using the ghidra decompiler we decompile the function main.main and we notice it calls three functions `func1`, `func2` and `func3`. After each function call it calls a formatting function and then a print function. Since the binary prints three lines, we can assume each function has something to do with each line.

Out of the three lines listed below the only line which is really interesting is the last one which looks like a part of the flag.

```
$ ./gogu.exe 
Welcome to gogu!
Good luck!
a961f71e0f287ac52a25aa93be854377
```

Disassembling the function is rather ugly so we fire up gdb with a breakpoint at the function start 

#### Flag

<details>
  <summary>Decode flag </summary>
</details>


