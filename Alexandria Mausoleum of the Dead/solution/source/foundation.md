# CICADA://BROKEN-SHELL Solution

## Challenge Summary

- Author: AniLog
- Category: Web / Puzzle
- Diﬀiculty: Very Hard
- Final flag:zerosec{cicada_sings_through_dead_threads}
This challenge is a live browser shell, not a source-only reversing puzzle. The player solves it by
learning five consistent machine laws:
1. the shell wantsverb object, not normal Linux syntax
2. the archive lies with the first word and preserves the second
3. the mirror tells the truth backwards
4. the live thread path avoidsmirrorandash
5. the final rite must bind truths in cathedral order
The intended solve is fully in-browser. The player should not need source code or packet inspection.
The shell is allowed to mislead, but every lie is rule-based and recoverable from prior evidence.

## Solve Overview

The complete solve path is:
observe shell
observe wound
descend archive
observe archive
listen index
descend nest
observe nest
offer token to nest
descend mirror
observe mirror
reflect relic
descend threads
observe threads
observe loom
trace wound through veil
trace veil through choir
trace choir through husk
descend husk
observe husk
peel bridge
descend cathedral
observe cathedral
offer token to gate
descend nullroom
observe nullroom
stitch name with song with bridge with cable


That yields the final flag:
zerosec{cicada_sings_through_dead_threads}

## Full Step-by-Step Solve

**Step 0 - Recognize that Linux habits are wrong**
A normal first instinct is to try commands likels,cd, orhelp.
Example dead-end responses:
ls
The shell coughs teeth. Rooms are wounds here, not directories.
cd archive
The prompt bends around that verb, studies it, and spits it back as damaged phosphor.
help
Documentation is considered a breach. Learn from the damage.
Inference:

- this is not a filesystem shell
- the machine rejects ordinary verbs on purpose
- the solution path must be a custom language

**Step 1 - Learn the first safe verb**
Command:
observe shell
Output:
The shell hangs in black phosphor like a broken tooth.
Familiar commands rot on contact. This machine wants action before object.
A hairline cut below the prompt keeps reopening. Observe wound if you want the grammar.
A lower seam breathes one room-name: archive.
Inference:

- observeis a valid verb
- the shell itself states the grammar: action before object
- woundis the next noun to inspect
- archiveis the first destination room

**Step 2 - Confirm the grammar rule**
Command:
observe wound
Output:


The wound speaks in grammar, not in paths.
verb -> object
Rooms are descended into. Nothing here respects a slash.
Inference:

- the movement verb isdescend
- room traversal is noun-based, not slash/path-based
- archiveis now the obvious next move

**Step 3 - Enter the first real puzzle room**
Command:
descend archive
Output:
Drawers wake below the terminal glass.
current bruise: archive
Inference:

- room travel is working
- the shell now accepts room-local nouns and mechanics

**Step 4 - Read the archive carefully**
Command:
observe archive
Output:
The archive is drawers all the way down.
Every label seems to arrive in pairs.
The first word looks healthy. The second survived.
An index reel still listens.
Inference:

- the archive mechanic is explicit: paired labels
- the first word is suspect
- the second word is trustworthy
- indexis the next noun to use
- listenis likely the next valid verb because the reel “still listens”

**Step 5 - Recover the first fragment and the token**
Command:
listen index
Output:


The spool chatters in pairs:
salt / cicada
grave / nest
rust / token
The archive kills its first word. Keep the second.
truth recovered: name = cicada
Inference:

- apply the archive rule exactly: keep the second word from each pair
- second words arecicada,nest,token
- cicadais the first authentic fragment, stored asname
- nestis the next room
- tokenis an inventory object, not flavor text

**Step 6 - Move to the brood room**
Command:
descend nest
Output:
The nest warms the bezel with hidden legs.
current bruise: nest
Inference:

- this room is about the token recovered in archive

**Step 7 - Learn what the nest wants**
Command:
observe nest
Output:
The nest is warm with wire husks and patient teeth.
Nothing wakes here without an offering.
Small legs keep turning toward the token-shape in your pocket.
Inference:

- the room is telling the player exactly what to do
- offeris the next valid verb
- the offering target is the nest itself

**Step 8 - Mark the token and unlock the mirror rule**
Command:
offer token to nest
Output:


You set the token into the brood. Legs close over it and return it wet with phosphor.
Their trails scratch a law across the bezel:
WHAT HATCHES IN GLASS MUST BE READ BACKWARDS.
A silver seam opens toward mirror.
Inference:

- the token must be offered before later gate logic will accept it
- the mirror rule is now explicit: anything truthful in glass must be reversed
- mirroris the next room

**Step 9 - Enter the mirror**
Command:
descend mirror
Output:
Silver static folds inward and becomes a room.
current bruise: mirror

**Step 10 - Read the mirror output literally and then reverse it**
Command:
observe mirror
Output:
eht rorrim speek ylno detrevni .ytsenoh
eht ciler snepo ylno nehw uoy tcelfer .ti
Reverse each line mentally:
the mirror keeps only inverted honesty.
the relic opens only when you reflect it.
Inference:

- the nest’s rule was correct
- relicis the room’s active noun
- reflectis the next valid action

**Step 11 - Recover the second fragment**
Command:
reflect relic
Output:
You turn the relic toward itself.
It cracks and sings its dead name: sgnis
A cable-map wakes beyond the silver, in threads.
Inference:


- sgnisis a fragment, but because it came from mirror it must be reversed later
- reversingsgnisyieldssings
- threadsis the next room

**Step 12 - Enter the graph room**
Command:
descend threads
Output:
Thin lit wires cross the dark in front of you.
current bruise: threads

**Step 13 - Ask what threads wants**
Command:
observe threads
Output:
Threads cross the terminal like nerves under stripped skin.
A torn loom still remembers the live junctions.
Observe loom if you want the path instead of the panic.
Inference:

- loomcontains the graph
- the room is warning the player not to guess blind

**Step 14 - Read the thread graph and the live-route rule**
Command:
observe loom
Output:
wound -> veil, glass
veil -> choir, ash
glass -> mirror, rot
choir -> husk, ash
rot -> null, ash
A live cable reaches husk in three pulls and never crosses mirror or ash.
Inference:

- the graph has multiple syntactically valid edges
- only one path is alive
- the path must:
    **-** start atwound
    **-** reachhusk
    **-** take exactly three pulls


**-** never entermirror
**-** never enterash
The only valid path is:
wound -> veil -> choir -> husk

**Step 15 - Make the first correct trace**
Command:
trace wound through veil
Output:
Trace accepted: wound -> veil
The live strand tightens but does not break.
Inference:

- the partial path is correct so far

**Step 16 - Make the second correct trace**
Command:
trace veil through choir
Output:
Trace accepted: veil -> choir
The live strand tightens but does not break.
Inference:

- the live route is still intact

**Step 17 - Finish the graph puzzle and recover the cable**
Command:
trace choir through husk
Output:
The strand reaches husk and tears something free.
A corpse-cable falls into your hands: dead_threads
The husk is awake now.
Inference:

- dead_threadsis the third fragment
- huskis now unlocked


**Step 18 - Enter the husk**
Command:
descend husk
Output:
Discarded shells scrape together in the black.
current bruise: husk

**Step 19 - Learn the husk mechanic**
Command:
observe husk
Output:
The husk is a room built from discarded shell and old alarms.
One living span still twitches inside dead brackets.
The husk does not open. It peels.
Inference:

- the room is about removing outer shell from inner truth
- peelis the required action
- the hidden live span is the next fragment

**Step 20 - Recover the bridge fragment**
Command:
peel bridge
Output:
You peel back the dead angles until the living span shows.
Recovered bridge: <through>
The peeled span points toward cathedral.
Inference:

- the raw fragment is<through>
- because it came from husk, the outer shell must be removed later
- peeling<through>yieldsthrough
- cathedralis next

**Step 21 - Enter cathedral**
Command:
descend cathedral
Output:


Fans hum like a buried choir.
current bruise: cathedral

**Step 22 - Read the canonical ordering rule**
Command:
observe cathedral
Output:
The cathedral is fan-noise, dead keys, and machine prayer.
The choir repeats one procession without mercy: name, song, bridge, cable.
The gate will wake only for the token after the brood has marked it.
Inference:

- the final synthesis order is now fixed:
    1. name
    2. song
    3. bridge
    4. cable
- the gate also checks whether the token was previously offered to the nest

**Step 23 - Use the marked token to unlock nullroom**
Command:
offer token to gate
Output:
The marked token disappears into the gate with a sound like wet static.
The choir goes silent all at once.
A last descent opens: nullroom.
Inference:

- all prerequisite truths are present
- the seeded token passed the gate check
- nullroomis now reachable

**Step 24 - Enter nullroom**
Command:
descend nullroom
Output:
Sound leaves before you do.
current bruise: nullroom


**Step 25 - Read the transformation reminder**
Command:
observe nullroom
Output:
Nullroom eats every sound it does not need.
Only stitched nouns persist here.
The older laws still apply: mirror the song, peel the bridge, preserve name and cable.
Use with to bind the recovered truths.
Inference:

- all earlier room laws remain active
- the shell restates the exact transformations:
    **-** mirror the song
    **-** peel the bridge
    **-** preserve the name
    **-** preserve the cable
- the joining keyword iswith

**Step 26 - Perform the final stitch**
Command:
stitch name with song with bridge with cable
Output:
Nullroom accepts the procession.
zerosec{cicada_sings_through_dead_threads}
The shell stops pretending not to know you.
This is the final solve.

## Why the Final Flag Is Correct

The shell never stores the final flag as a single early plaintext in the player flow. Instead, the player
reconstructs it from four truths plus three laws.
Recovered truths:
name = cicada
song = sgnis
bridge = <through>
cable = dead_threads
Transformation laws:
name -> preserve -> cicada
song -> reverse -> sings
bridge -> peel shell -> through
cable -> preserve -> dead_threads


Cathedral ordering rule:
name, song, bridge, cable
Therefore:
zerosec{cicada_sings_through_dead_threads}

## False Paths and Why They Fail

**False Path 1 - Treating the challenge like Linux**
Examples:
ls
The shell coughs teeth. Rooms are wounds here, not directories.
cd archive
The prompt bends around that verb, studies it, and spits it back as damaged phosphor.
These are not random joke responses. They teach the first core lesson:

- no path syntax
- no POSIX verbs
- custom machine grammar only

**False Path 2 - Ignoring the archive rule**
Archive emits:
salt / cicada
grave / nest
rust / token
If the player trusts the first word, they get nonsense:

- saltis not a real fragment
- graveis not the next room
- rustis not the useful item
The room explicitly says:
The archive kills its first word. Keep the second.

**False Path 3 - Ignoring the mirror rule**
Mirror emits:
eht rorrim speek ylno detrevni .ytsenoh
eht ciler snepo ylno nehw uoy tcelfer .ti
If the player tries to parse these literally, nothing useful emerges. The nest already established the
law:
WHAT HATCHES IN GLASS MUST BE READ BACKWARDS.


**False Path 4 - Taking a locally valid but dead thread edge**
Wrong example from the live graph:
trace wound through glass
The strand dives into rot and forgets your hand.
Another wrong example:
trace veil through ash
The thread vanishes into reflection and comes back wearing your own lie.
These are important because they prove the graph puzzle is not “follow any edge” but “follow the
living edge under the stated constraint”.
The loom already tells the player:
A live cable reaches husk in three pulls and never crosses mirror or ash.
**False Path 5 - Offering the token to gate too early**
If the player tries the gate without earning the token:
offer token to gate
You search your hands for a token and find only static.
Even after archive, the gate still requires the token to be marked by the nest. The cathedral states
that plainly:
The gate will wake only for the token after the brood has marked it.

## Full Solve Transcript Only

```
For operators who only want the exact input sequence:
observe shell
observe wound
descend archive
observe archive
listen index
descend nest
observe nest
offer token to nest
descend mirror
observe mirror
reflect relic
descend threads
observe threads
observe loom
trace wound through veil
trace veil through choir
trace choir through husk
descend husk
observe husk
```

peel bridge
descend cathedral
observe cathedral
offer token to gate
descend nullroom
observe nullroom
stitch name with song with bridge with cable

## Operator Notes

**Intended player experience**

- The terminal is the primary interface.
- The shell should feel unreliable but still readable.
- Popups and glitch events should reinforce clues rather than replace them.
- The player should always be able to justify the next step from prior evidence.

**Live-instance behavior**

- Sessions are server-side and survive reconnects.
- The challenge includes HTTP rate limiting plus per-session terminal throttling.
- Very fast scripted input can trigger anti-bruteforce responses.
- Human pacing is part of the intended interaction model.

**Implementation notes**

- frontend: static HTML/CSS/JS CRT shell
- backend: Fastify + WebSocket + SQLite
- state storage: room progression, fragments, rules, token state, attempts
- final flag emission: stitched from fragments and transformations at solve time

## Validation Checklist

- observe shellteaches the first verb and points towound
- observe woundteaches grammar and movement
- listen indexgives enough information to infercicada,nest, andtoken
- offer token to nestexplicitly teaches the mirror law
- observe loomfully constrains the correct live graph path
- observe cathedralfixes the only valid final ordering
- observe nullroomrestates the exact transformations required for the final stitch
- the full live solve yieldszerosec{cicada_sings_through_dead_threads}


