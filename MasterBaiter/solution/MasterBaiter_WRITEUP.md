# MasterBaiter – Writeup

## Overview

this binary looks like a simple fishing simulator.

You input something, wait a bit, and it prints a random fish. Nothing seems special.

Trying a few inputs just returns different fish names.

Running `strings` on the binary reveals:

zerosecurectf{very_common_fish}

This looks like a flag, but clearly it’s a bait.

---

## Reversing

Loading the binary into Ghidra shows a function `chk()` controlling the logic:

```c
int chk(char *input)
{
    int len = strlen(input);
    int sum = 0;

    for(int i=0;i<len;i++)
        sum += input[i] * (i+1);

    return (sum % 1337) == 420;
}
```

So the program is not random — it checks a condition on the input.

---

## Understanding the Condition

The logic:

sum = Σ(input[i] * (i + 1))
sum % 1337 == 420

We need to find an input string that satisfies this.

---

## Solving

Instead of guessing, we can brute force a small string:

```python
for c1 in range(32,127):
    for c2 in range(32,127):
        for c3 in range(32,127):
            s = chr(c1)+chr(c2)+chr(c3)
            total = sum(ord(s[i])*(i+1) for i in range(len(s)))
            if total % 1337 == 420:
                print(s)
                exit()
```

---

## Flag Decoding

When the condition is satisfied, the program calls `print_real_flag()`:

```c
while(enc_flag[i])
{
    flag[i] = enc_flag[i] ^ 0x55 ^ i;
    i++;
}
```

So each character is decoded using:

decoded_char = enc_flag[i] ^ 0x55 ^ i

---

## Reconstructing the Flag

We can replicate this in Python:

```python
enc = [0x2f,0x30,0x27,0x3a,0x26,0x30,0x36,0x20,0x27,0x36,0x21,0x33,0x0f,
       0x17,0x65,0x38,0x17,0x36,0x39,0x61,0x21,0x21,0x0a,0x33,0x3c,0x3d,0x28]

flag = ""
for i,b in enumerate(enc):
    flag += chr(b ^ 0x55 ^ i)

print(flag)
```

---

## Final Flag

zerosecurectf{b0mbacl4tt_fih}

---

## Notes

- The program is not random it uses a hidden condition
- The visible flag is a bait
- The real flag is XOR-encoded
- Requires both reversing and small scripting
