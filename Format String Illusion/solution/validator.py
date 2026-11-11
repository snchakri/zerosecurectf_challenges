EXPECTED_FLAG = "ZeroSecure_CTF{FORMAT_STRING_ILLUSION}"


def is_correct_flag(submitted: str) -> bool:
    """Validate submitted flag with whitespace tolerance."""
    return submitted.strip() == EXPECTED_FLAG


def main() -> None:
    user_input = input("Enter flag: ")
    if is_correct_flag(user_input):
        print("Correct flag.")
    else:
        print("Incorrect flag. Re-check letter extraction, case mapping, and 5-symbol grouping.")


if __name__ == "__main__":
    main()
