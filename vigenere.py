class VigenereCipher: 
    def __init__(self, key: str): 
        # initialize cipher with provided key 
        # removes non-letter characters & convert to uppercase 

        self.key = self._format_key(key) 
        if not self.key: 
            raise ValueError("Key must have at least one letter.") 

    def _format_key(self, key: str) -> str:
        # removes non-letters & make uppercase 
        return ''.join([letter.upper() for letter in key if letter.isalpha()])

    def _repeat_key(self, plaintext: str) -> str: 
        # repeat the key to match the length of the plaintext 
        key = self.key 
        repeated_key = ''
        key_index = 0 

        for char in plaintext:
            if char.isalpha():
                # if it's a letter, add the next letter from the key 
                # the % len(key) ensures we loop back to start if the key runs out 
                repeated_key += key[key_index % len(key)]
                key_index += 1 
            else: 
                repeated_key += char # keep non-letters in place
        return repeated_key

    def encrypt(self, plaintext: str) -> str: 
        # encypts given plaintext using vignere cipher & key 
        plaintext = plaintext.upper() 
        repeated_key = self._repeat_key(plaintext) 
        ciphertext = ''

        # paid each letter in the plaintext with orresponding letter from extended key
        for p_letter, k_letter in zip(plaintext, repeated_key):
            if p_letter.isalpha(): 
                p_val = ord(p_letter) - ord('A')    # plaintext letter as a number
                k_val = ord(k_letter) - ord('A')    # key letter as number, shift amount 
                c_val = (p_val + k_val) % 26        # apply shift for ciphertext
                ciphertext += chr(c_val + ord('A')) # converts back to letter 
            else: 
                ciphertext += p_letter  # keep spaces/ other symbols the same
        return ciphertext

    def decrypt(self, ciphertext: str) -> str: 
        # decrypt ciphertext back to its original plaintext 

        ciphertext = ciphertext.upper() 
        repeated_key = self._repeat_key(ciphertext)
        plaintext = ''

        # pair each ciphertext letter with its matching key letter
        for c_letter, k_letter in zip(ciphertext, repeated_key): 
            if c_letter.isalpha(): 
                c_val = ord(c_letter) - ord('A')    # ciphertext letter as number 
                k_val = ord(k_letter) - ord('A')    # key letter as number, shift amount
                p_val = (c_val - k_val + 26) % 26   # reverse encryption shift to original plaintext letter
                plaintext += chr(p_val + ord('A'))  # converts back to letter 
            else: 
                plaintext += c_letter   # keep spaces/ other symbols the same
        return plaintext

             
# SAMPLE TEST
if __name__ == "__main__": 
    key = "LUCKY"
    plaintext = "HELLO, world! Vigenere CIpher TEST."

    # create vigenere cipher object 
    vigenere_cipher = VigenereCipher(key)

    # encrypt plaintext
    encrypted = vigenere_cipher.encrypt(plaintext)
    print(f"Encrypted test: {encrypted}\n")

    # decrypt ciphertext
    decrypted = vigenere_cipher.decrypt(encrypted)
    print(f"Decrypted test: {decrypted}\n")

    assert decrypted == plaintext.upper()
    print("Test Passed: Decrypted text matches the original plaintext.")




    


    