EXPECTED_FLAG = "ZeroSecure_CTF{TRIPLE_BASE64_CHAIN}"


def is_correct_flag(submitted: str) -> bool:
    """Validate submitted flag with whitespace tolerance."""
    return submitted.strip() == EXPECTED_FLAG


def main() -> None:
    user_input = input("Enter flag: ")
    if is_correct_flag(user_input):
        print("Correct flag.")
    else:
        print("Incorrect flag. Decode carefully layer by layer.")


if __name__ == "__main__":
    main()
