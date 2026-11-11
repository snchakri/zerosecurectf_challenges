<a id="c104"></a>
## 104 · Robots Of The Apocalypse

**Chamber:** Web Exploitation · **Band:** broken set · **Status:** decoy honeypot (unsolvable by design; DOOM{...} submissions = signal)  
**Flag:** `(hidden random)`

### ROBOTS OF THE APOCALYPSE

**Category:** Web · **Difficulty:** ★★☆ (30–50m)

> The surface is gone. The bunker's terminal is still up. Recon it.

#### Run
```
docker compose up --build
### then browse http://localhost:5000
```
Or without Docker:
```
pip install -r requirements.txt
python app.py
```

#### Notes
Start with the obvious recon. Then notice what the site *doesn't* want you to
see — and what it leaks when you poke a URL that doesn't exist.

Flag format: `DOOM{...}`


