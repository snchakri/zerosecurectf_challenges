ENCODED_PAYLOAD = "\x7f;agectvagfqegv{d}HVEagtwegUqtg\\"


def recover_flag():
    stage_one = ENCODED_PAYLOAD[::-1]
    out = []
    for ch in stage_one:
        out.append(chr(ord(ch) - 2))
    return "".join(out)
