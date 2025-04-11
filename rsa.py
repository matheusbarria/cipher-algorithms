def rsa_encrypt(value, exponent, n):
    return pow(value, exponent, n)

def rsa_decrypt(value, exponent, n):
    return pow(value, exponent, n)

def encrypt_text(plain_text, e, n):
    encrypted_numbers = [str(rsa_encrypt(ord(char), e, n)) for char in plain_text]
    return " ".join(encrypted_numbers)

def decrypt_text(encrypted_str, d, n):
    decrypted_chars = [chr(rsa_decrypt(int(num), d, n)) for num in encrypted_str.split()]
    return "".join(decrypted_chars)

def encrypt_file(input_path, output_path, e, n):
    with open(input_path, "rb") as f:
        data = f.read()
    # make sure that n > 255 for this to work correctly!!
    encrypted_numbers = [str(rsa_encrypt(b, e, n)) for b in data]
    encrypted_str = " ".join(encrypted_numbers)
    with open(output_path, "w") as f:
        f.write(encrypted_str)
    print(f"Encryption completed. Encrypted file saved at '{output_path}'.")

def decrypt_file(input_path, output_path, d, n):
    with open(input_path, "r") as f:
        encrypted_str = f.read()
    numbers = encrypted_str.split()
    decrypted_bytes = bytes([rsa_decrypt(int(num), d, n) for num in numbers])
    with open(output_path, "wb") as f:
        f.write(decrypted_bytes)
    print(f"Decryption completed. Decrypted file saved at '{output_path}'.")

def main():
    print("====== RSA Encryption/Decryption Program ======")
    print("Please enter your RSA parameters. (These should be generated securely in practice)")
    
    try:
        e = int(input("Enter public exponent (e): "))
        d = int(input("Enter private exponent (d): "))
        n = int(input("Enter modulus (n): "))
    except ValueError:
        print("Invalid input. Please make sure e, d, and n are integers.")
        return

    print("\nChoose an operation:")
    print("1. Encrypt")
    print("2. Decrypt")
    operation = input("Enter your choice (1 or 2): ").strip()

    if operation == "1":
        print("\nChoose data type for encryption:")
        print("a. Text")
        print("b. File/Image")
        mode = input("Enter your choice (a or b): ").strip().lower()
        if mode == "a":
            plain_text = input("Enter the text to encrypt: ")
            encrypted = encrypt_text(plain_text, e, n)
            print("\nEncrypted text:")
            print(encrypted)
        elif mode == "b":
            input_file = input("Enter the path to the input file (or image): ").strip()
            output_file = input("Enter the path for saving the encrypted output file: ").strip()
            try:
                encrypt_file(input_file, output_file, e, n)
            except Exception as ex:
                print("Error during file encryption:", ex)
        else:
            print("Invalid option selected for encryption mode.")
    
    elif operation == "2":
        print("\nChoose data type for decryption:")
        print("a. Text")
        print("b. File/Image")
        mode = input("Enter your choice (a or b): ").strip().lower()
        if mode == "a":
            encrypted_text = input("Enter the encrypted text: ")
            try:
                decrypted = decrypt_text(encrypted_text, d, n)
                print("\nDecrypted text:")
                print(decrypted)
            except Exception as ex:
                print("Error during text decryption:", ex)
        elif mode == "b":
            input_file = input("Enter the path to the encrypted file: ").strip()
            output_file = input("Enter the path for saving the decrypted output file: ").strip()
            try:
                decrypt_file(input_file, output_file, d, n)
            except Exception as ex:
                print("Error during file decryption:", ex)
        else:
            print("Invalid option selected for decryption mode.")
    
    else:
        print("Invalid operation choice. Please select 1 for encryption or 2 for decryption.")

if __name__ == "__main__":
    main()
