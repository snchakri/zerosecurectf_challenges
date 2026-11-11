Hints
Hints for SIMULATION-ZIPBOMB
Hint 1: Look for encoded strings that appear after the ::  symbol in comment lines throughout the files.
Hint 2:
These are all Base64-encoded. Every file contains multiple candidates, but you need to figure out how to identify which
one is the real flag.
Hint 3:
Base64 decode the strings first, then apply ROT13 transformation to the decoded output.
Hints for StarkId:
Hint 1: Check the token's header — what algorithm is being used to sign it?Notice the clearance level in your
token vs. what you need for the ﬂag endpoint. Can you modify it?
Hint 2: Research JWT algorithm confusion attacks — what happens when a server accepts diﬀerent
algorithms than intended?
Hints for HYDRACORE:
Hint 1:The service accepts a webhookUrl parameter. What if you pointed that parameter at an internal URL
instead of an external one?"
Hint 2: "SSRF exploits often involve redirecting server-side requests to unintended targets. How could the
relay's fetch operation be weaponized?"
4/13/26, 4:04 PM Hints
https://app.notesnook.com/notes 1/1