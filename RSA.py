import os

class RSA:
    def __init__(self, n, e, d):
        """
        Initialize RSA cipher with n, e, and d keys directly
        """
        self.n = n
        self.e = e
        self.d = d
        
        # Validate the keys provided
        # Simple test: encrypt and decrypt a test value
        test_value = 42
        if self._modexp(self._modexp(test_value, self.e, self.n), self.d, self.n) != test_value:
            raise ValueError("Invalid key parameters: encryption/decryption test failed.")
            
        # Find how many bytes can be encrypted per message chunk 
        self.block_size = (self.n.bit_length() - 1) // 8
        if self.block_size < 1:
            raise ValueError("Modulus is too small for encryption. Use larger values.")
    
    # Extended Euclidean Algorithm to find modular inverse of e 
    def _egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)    
        else:
            gcd, y, x = self._egcd(b % a, a)
            return (gcd, x - (b // a) * y, y)
    
    # Calculate the modular inverse of a modular m  
    def _modinv(self, a, m):
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise Exception("Modular inverse does not exist.")
        return x % m
    
    # Calculate base exp mod 
    def _modexp(self, base, exp, mod):
        result = 1
        base %= mod
        while exp > 0:
            if exp % 2:
                result = (result * base) % mod
            base = (base * base) % mod
            exp //= 2
        return result
    
    # Encrypt binary data and return a list of (chunk_size, encrypted_chunk) pairs 
    def encrypt_binary(self, data: bytes) -> list:
        chunks = []
        for i in range(0, len(data), self.block_size):
            chunk = data[i:i + self.block_size]
            chunks.append(chunk)

        encrypted_chunks = []
        
        for chunk in chunks:
            chunk_size = len(chunk)  # original chunk length 
            
            # Convert to integer
            m_int = int.from_bytes(chunk, byteorder='big')
            if m_int >= self.n:
                raise ValueError(f"Chunk message too large for given modulus. Max is {self.n-1}.")
            # Encrypt
            c_int = self._modexp(m_int, self.e, self.n)
            # store the chunk size and the encrypted val
            encrypted_chunks.append((chunk_size, c_int))
        
        return encrypted_chunks
    
    # Decrypt a list of (chunk_size, encrypted_chunk) pairs
    def decrypt_binary(self, encrypted_chunks: list) -> bytes:
        message_bytes = bytearray()
        
        for chunk_size, c_int in encrypted_chunks:
            # decrypt
            m_int = self._modexp(c_int, self.d, self.n)
            
            # convert back to bytes with the original length to keep leading zeros
            chunk_bytes = m_int.to_bytes(chunk_size, byteorder='big')
            message_bytes.extend(chunk_bytes)
        
        return bytes(message_bytes)
    
    # Encrypt text
    def encrypt_text(self, message: str) -> str:
        encrypted_chunks = self.encrypt_binary(message.encode('utf-8'))
        # Convert to a string format with both size and value
        return ' '.join(f"{size}:{format(chunk, 'x')}" for size, chunk in encrypted_chunks)
    
    # Decrypt text 
    def decrypt_text(self, encrypted_str: str) -> str:
        # Parse the size:value format
        parts = encrypted_str.strip().split()
        encrypted_chunks = []
        for part in parts:
            size, hex_val = part.split(':', 1)
            encrypted_chunks.append((int(size), int(hex_val, 16)))
        
        message_bytes = self.decrypt_binary(encrypted_chunks)
        return message_bytes.decode('utf-8', errors='ignore')
    
    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """Encrypt a file and save the encrypted data"""
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_chunks = self.encrypt_binary(data)
        
        with open(output_file, 'wb') as f:
            f.write(len(encrypted_chunks).to_bytes(8, byteorder='big'))  # Write the number of chunks

            # Find how many bytes needed for chunk size and for encrypted values
            chunk_value_bytes = (self.n.bit_length() + 7) // 8
            
            for chunk_size, chunk_value in encrypted_chunks:
                f.write(chunk_size.to_bytes(1, byteorder='big'))    # write original chunk size (1 byte enough)
                f.write(chunk_value.to_bytes(chunk_value_bytes, byteorder='big'))   # write the encrypted value
    
    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """Decrypt a file and save the decrypted data"""
        with open(input_file, 'rb') as f:
            # Read the number of chunks
            num_chunks = int.from_bytes(f.read(8), byteorder='big')
            
            # Calculate encrypted value size based on modulus
            chunk_value_bytes = (self.n.bit_length() + 7) // 8
            
            # Read each chunk
            encrypted_chunks = []
            for _ in range(num_chunks):
                # Read the original chunk size
                chunk_size = int.from_bytes(f.read(1), byteorder='big')
                # Read the encrypted value
                chunk_value = int.from_bytes(f.read(chunk_value_bytes), byteorder='big')
                encrypted_chunks.append((chunk_size, chunk_value))
        
        # Decrypt the data
        decrypted_data = self.decrypt_binary(encrypted_chunks)
        
        # Save the decrypted data
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

def main():
    print("_____ RSA Encryption/Decryption ____")
    print("Please enter your RSA key parameters.")

    try:
        # Ask for the RSA parameters
        n = int(input("Enter modulus n: "))
        e = int(input("Enter public exponent e: "))
        d = int(input("Enter private exponent d: "))
        rsa = RSA(n, e, d)
    except ValueError as ex:
        print(f"Invalid input: {ex}")
        return
    except Exception as ex:
        print(f"Error during key calculation: {ex}")
        return

    print("\nChoose operation:")
    print("1: Encrypt")
    print("2: Decrypt")
    operation = input("Enter your choice (1 or 2): ").strip()

    if operation == "1":
        print("\nWhat would you like to encrypt?")
        print("a. Text")
        print("b. File")
        print("c. Image")
        mode = input("Enter your choice (a, b or c): ").strip().lower()

        if mode == "a":
            message = input("Enter the text to encrypt: ")
            try:
                encrypted = rsa.encrypt_text(message)
                print("Encrypted Text:")
                print(encrypted)
            except Exception as ex:
                print(f"Encryption error: {ex}")

        elif mode == "b" or mode == "c":
            label = "image" if mode == "c" else "file"
            input_file = input(f"Enter the path to the input {label}: ").strip()
            base, _ = os.path.splitext(input_file)
            output_file = base + ".enc"
            try:
                rsa.encrypt_file(input_file, output_file)
                print(f"{label.capitalize()} encrypted and saved as '{output_file}'")
            except Exception as ex:
                print(f"{label.capitalize()} encryption error: {ex}")

        else:
            print("⚠️ Invalid option for encryption mode.")

    elif operation == "2":
        print("\nWhat would you like to decrypt?")
        print("a. Text")
        print("b. File")
        print("c. Image")
        mode = input("Enter your choice (a, b or c): ").strip().lower()

        if mode == "a":
            encrypted_text = input("Paste the encrypted text: ").strip()
            try:
                decrypted = rsa.decrypt_text(encrypted_text)
                print("\nDecrypted Text:")
                print(decrypted)
            except Exception as e:
                print(f"Decryption error: {e}")
        elif mode in ("b", "c"):
            label = "image" if mode == "c" else "file"
            input_file = input(f"Enter the path to the encrypted {label}: ").strip()
            base, _ = os.path.splitext(input_file)
            output_file = base + ".dec"
            try:
                rsa.decrypt_file(input_file, output_file)
                print(f"{label.capitalize()} decrypted and saved as '{output_file}'")
            except Exception as ex:
                print(f"{label.capitalize()} decryption error: {ex}")
        else:
            print("Invalid option for decryption mode.")

    else:
        print("Invalid operation. Choose 1 or 2.")

if __name__ == "__main__":
    main()