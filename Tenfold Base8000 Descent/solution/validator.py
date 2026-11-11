EXPECTED_FLAG = "ZeroSecure_CTF{caught_it_ten}"


def is_correct_flag(submitted: str) -> bool:
    """Validate submitted flag with whitespace tolerance."""
    return submitted.strip() == EXPECTED_FLAG


def main() -> None:
    candidate = input("Enter flag: ")
    if is_correct_flag(candidate):
        print("Correct flag.")
    else:
        print("Incorrect flag. Decode all ten layers.")


if __name__ == "__main__":
    main()
