EXPECTED_FLAG = "ZeroSecure_CTF{KEYBOARD_SHIFT_RIGHT}"


def is_correct_flag(submitted: str) -> bool:
    """Validate submitted flag with whitespace tolerance."""
    return submitted.strip() == EXPECTED_FLAG


def main() -> None:
    user_input = input("Enter flag: ")
    if is_correct_flag(user_input):
        print("Correct flag.")
    else:
        print("Incorrect flag. Re-check the keyboard shift direction.")


if __name__ == "__main__":
    main()
