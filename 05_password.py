import re

def password_strength(password):

    # Length check
    if len(password) < 8:
        return "Weak: Password is too short"

    # Complexity check
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?`~' for char in password)

    complexity = sum([
        has_lowercase,
        has_uppercase,
        has_digit,
        has_special
    ])

    if complexity < 3:
        return "Weak: Password lacks complexity"

    # Common pattern check
    common_patterns = [
        r'123',
        r'abc',
        r'password',
        r'qwerty',
        r'111',
        r'admin',
        r'letmein',
        r'love',
        r'master',
        r'123456'
    ]

    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return "Weak: Password contains common pattern"

    return "Strong: Password meets criteria for strength"


# Test the function
password = input("Enter your password: ")
print(password_strength(password))