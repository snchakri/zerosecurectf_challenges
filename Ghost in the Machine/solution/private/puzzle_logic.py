def recover_flag():
    payload = "{7]ca_pr]cbmanm]rqmfeyDRA]cpsacQmpcX"
    stage = payload[::-1]
    out = []
    for ch in stage:
        out.append(chr(ord(ch) + 2))
    return "".join(out)
