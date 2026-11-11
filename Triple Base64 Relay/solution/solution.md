# Solution - Triple Base64 Relay

## Expected Flag
`ZeroSecure_CTF{TRIPLE_BASE64_CHAIN}`

## Walkthrough
Input payload (`challenge.txt`):

```
VjIxV2VXSXhUbXhaTTFaNVdsWTVSRlpGV2pkV1JrcEtWVVY0Umxnd1NrSlZNRlV5VGtZNVJGTkZSa3BVYmpBOQ==
```

Decode 1:

```
V21WeWIxTmxZM1Z5WlY5RFZFWjdWRkpKVUV4RlgwSkJVMFUyTkY5RFNFRkpUbjA9
```

Decode 2:

```
WmVyb1NlY3VyZV9DVEZ7VFJJUExFX0JBU0U2NF9DSEFJTn0=
```

Decode 3 (final):

```
ZeroSecure_CTF{TRIPLE_BASE64_CHAIN}
```

## Example One-Liner (Python)

```python
import base64
s = "VjIxV2VXSXhUbXhaTTFaNVdsWTVSRlpGV2pkV1JrcEtWVVY0Umxnd1NrSlZNRlV5VGtZNVJGTkZSa3BVYmpBOQ=="
print(base64.b64decode(base64.b64decode(base64.b64decode(s))).decode())
```
