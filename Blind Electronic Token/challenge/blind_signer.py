import json
import sys

N = 7023800552605391553069181779541565402906444708994054338197061016196541057555761362404843897272895418200576507768686790538954611993496044816642965824017549
E = 65537
D = 840236756830893537636180861980345038051581953988027923332849510459448584635179921149519452180108124778104118929851327873799853038111472081770873971263873

def sign_blinded(blinded_int):
    return pow(blinded_int, D, N)

def verify_token(token_str, sig_int):
    m = int.from_bytes(token_str.encode('utf-8'), 'big')
    return pow(sig_int, E, N) == m

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "sign":
        val = int(sys.argv[2])
        print(sign_blinded(val))
    elif len(sys.argv) > 1 and sys.argv[1] == "verify":
        token = sys.argv[2]
        sig = int(sys.argv[3])
        if token == "ADMIN_AUTH_TOKEN_LEVEL_9" and verify_token(token, sig):
            print("ACCESS GRANTED: zerosecure{chaum_blind_signature_unblind_token_67b3}")
        else:
            print("VERIFICATION FAILED")
