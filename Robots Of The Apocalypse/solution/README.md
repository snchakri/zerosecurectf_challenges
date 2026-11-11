# Robots Of The Apocalypse — solution

# ROBOTS OF THE APOCALYPSE

**Category:** Web · **Difficulty:** ★★☆ (30–50m)

> The surface is gone. The bunker's terminal is still up. Recon it.


## Run
```
# then browse http://localhost:5000
```
Or without Docker:
```
pip install -r requirements.txt
python app.py
```


## Notes
Start with the obvious recon. Then notice what the site *doesn't* want you to
see — and what it leaks when you poke a URL that doesn't exist.

Flag format: `DOOM{...}`

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
