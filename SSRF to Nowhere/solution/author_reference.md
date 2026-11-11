<a id="c105"></a>
## 105 · SSRF to Nowhere

**Chamber:** Web Exploitation · **Band:** broken set · **Status:** real flag  
**Flag:** `ZeroSecure{ssrf_l00pback_4dm1n} or zerosecurectf{ssrf_l00pback_4dm1n}`

### SSRF TO NOWHERE

**Category:** Web · **Difficulty:** ★★★ (40–60m)

> The bunker's monitoring console can still "preview" a sensor feed by URL.
> There's also an admin panel. It only talks to localhost.

#### Run
```
docker compose up --build
### then browse http://localhost:5000
```
> Deploy on Linux. The intended bypass relies on Linux treating a connection to
> `0.0.0.0` as loopback (Windows rejects it), so solve against the container,
> not a bare Windows host.

#### Notes
The preview box fetches whatever URL you give it — server-side (SSRF). The flag
sits at `/admin/flag`, which returns `403` unless the request comes **from the
server itself**. So make the server fetch its own admin endpoint.

There's a filter: it blocks the obvious loopback spellings (`localhost`,
`127.0.0.1`, `::1`). Reach loopback another way.

Flag format: `ZeroSecure{...}`

<details><summary>Spoiler — a working bypass</summary>

`/?url=http://0.0.0.0:5000/admin/flag` (or the decimal form,
`http://2130706433:5000/admin/flag`). The fetch originates from loopback, so
`/admin/flag` answers.
</details>


