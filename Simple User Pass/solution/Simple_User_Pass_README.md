# Simple User Pass – Writeup

## Overview

this binary looks like a basic username/password checker.

You run it like:

./userpass <username> <password>

If the correct password is provided, it grants access and prints the flag.

There are no obvious strings or hardcoded passwords, so the value is being generated dynamically.

---

## Initial Analysis

Running `strings` on the binary doesn’t reveal anything useful , no flag, no password.

the next step is to load the binary into Ghidra and inspect the logic.

---

## Key Generation Logic

Inside the binary, there is a function responsible for generating the expected password from the username.

The logic is:

- Loop through each character of the username  
- Multiply each character by its position (i + 1)  
- Add all values together  
- Take the first character and multiply it by 3  
- XOR this with the sum  
- Left shift the result by the length of the program name (argv[0])  

In simplified form:

sum = Σ(user[i] * (i + 1))
key = (sum ^ (user[0] * 3)) << strlen(argv[0])

---

## Example Walkthrough

### Username:
binary

### Program name:
./userpass

Length:
10

---

### Step 1: ASCII values

b = 98  
i = 105  
n = 110  
a = 97  
r = 114  
y = 121  

---

### Step 2: Weighted sum

98*1 = 98  
105*2 = 210  
110*3 = 330  
97*4 = 388  
114*5 = 570  
121*6 = 726  

sum = 2322

---

### Step 3: First character

'b' = 98  
98 * 3 = 294  

---

### Step 4: XOR

2322 ^ 294 = 2100  

---

### Step 5: Shift

key = 2100 << 10  
= 2150400  

---

## Final Test

./userpass binary 2150400

Output:

[ access granted ]  
zerosecurectf{you_keygend_me!}

---

## Notes

- The password is not stored anywhere — it is computed  
- The binary name affects the result (argv[0])  
- Renaming the binary changes the correct password  
- The flag is constructed at runtime, not stored as a string  

---

## Flag

zerosecurectf{you_keygend_me!}
