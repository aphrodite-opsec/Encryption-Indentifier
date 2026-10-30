
import re
import base64

def identify_hash(value):
    value = value.strip()

    results = []

    # Common hash formats
    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA-1": r"^[a-fA-F0-9]{40}$",
        "SHA-224": r"^[a-fA-F0-9]{56}$",
        "SHA-256": r"^[a-fA-F0-9]{64}$",
        "SHA-384": r"^[a-fA-F0-9]{96}$",
        "SHA-512": r"^[a-fA-F0-9]{128}$",
        "NTLM": r"^[a-fA-F0-9]{32}$",
        "MySQL 4.1+": r"^\*[a-fA-F0-9]{40}$",
        "bcrypt": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "Argon2": r"^\$argon2(id|i|d)\$",
        "scrypt": r"^\$scrypt\$",
        "PBKDF2": r"^\$pbkdf2-",
    }

    for name, pattern in patterns.items():
        if re.match(pattern, value):
            results.append(name)

    # Detect encrypted data / encoded formats
    if value.startswith("-----BEGIN"):
        results.append("PEM encoded cryptographic data")

    if value.startswith("gAAAAA"):
        results.append("Possible Fernet encryption token")

    if value.startswith("U2FsdGVkX1"):
        results.append("Possible OpenSSL/CryptoJS salted AES data")

    # Detect JWT
    if re.match(
        r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$",
        value
    ):
        results.append("JWT (JSON Web Token)")

    # Detect Base64
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(value) >= 8:
            results.append("Valid Base64 encoding")
    except Exception:
        pass

    # Results
    print("\n" + "=" * 45)
    print("       CRYPTOGRAPHIC IDENTIFIER")
    print("=" * 45)

    print(f"\nInput: {value[:60]}{'...' if len(value) > 60 else ''}")
    print(f"Length: {len(value)} characters")

    if results:
        print("\nPossible identification:")
        for result in results:
            print(f" [+] {result}")
    else:
        print("\n[-] No recognizable format detected.")

    if "MD5" in results and "NTLM" in results:
        print("\n[!] MD5 and NTLM have identical lengths.")
        print("    Additional context is required to distinguish them.")

    print("\nNOTE: Pattern matching does not prove the algorithm.")
    print("=" * 45)


# Main program
print("=" * 45)
print("       ENCRYPTION / HASH IDENTIFIER")
print("=" * 45)

while True:
    user_input = input("\nEnter hash or encrypted string (or 'exit'): ")

    if user_input.lower() == "exit":
        print("Exiting identifier...")
        break

    if not user_input.strip():
        print("Please enter a valid input.")
        continue

    identify_hash(user_input)
