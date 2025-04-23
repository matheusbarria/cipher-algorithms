import os
import sys
from typing import List, Tuple

# DES Constants
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]


Expansion_PBOX_Table = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P_BOX = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i - 1] for i in table]


def left_shift(bits: List[int], shift: int) -> List[int]:
    return bits[shift:] + bits[:shift]


def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [a[i] ^ b[i] for i in range(min(len(a), len(b)))]


def generate_subkeys(key: bytes) -> List[List[int]]:
    key_bits = bytes_to_bits(key)
    if len(key_bits) > 64:
        key_bits = key_bits[:64]  
    while len(key_bits) < 64:
        key_bits.append(0) 
        
    key_56 = permute(key_bits, PC1)
    left = key_56[:28]
    right = key_56[28:]

    subkeys = []
    for i in range(16):
        left = left_shift(left, SHIFT_SCHEDULE[i])
        right = left_shift(right, SHIFT_SCHEDULE[i])
        
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
        
    return subkeys


def s_box_substitution(bits: List[int]) -> List[int]:
    result = []
    for i in range(8):
        chunk = bits[i*6:(i+1)*6]
        row = (chunk[0] << 1) + chunk[5]
        col = (chunk[1] << 3) + (chunk[2] << 2) + (chunk[3] << 1) + chunk[4]
        
        val = S_BOXES[i][row][col]
        for j in range(4):
            result.append((val >> (3 - j)) & 1)
            
    return result


def f_function(right_half: List[int], subkey: List[int]) -> List[int]:
    expanded = permute(right_half, Expansion_PBOX_Table)
    xored = xor_bits(expanded, subkey)
    substituted = s_box_substitution(xored)
    return permute(substituted, P_BOX)


def des_encrypt_block(block: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block)
    bits = permute(bits, IP)
    left = bits[:32]
    right = bits[32:]
    for i in range(16):
        new_right = xor_bits(left, f_function(right, subkeys[i]))
        left = right
        right = new_right
    combined = right + left
    result = permute(combined, FP)
    return bits_to_bytes(result)


def des_decrypt_block(block: bytes, subkeys: List[List[int]]) -> bytes:
    return des_encrypt_block(block, subkeys[::-1])


def triple_des_encrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    subkeys1 = generate_subkeys(key1)
    subkeys2 = generate_subkeys(key2)
    subkeys3 = generate_subkeys(key3)
    temp = des_encrypt_block(block, subkeys1)
    temp = des_decrypt_block(temp, subkeys2)
    return des_encrypt_block(temp, subkeys3)


def triple_des_decrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    subkeys1 = generate_subkeys(key1)
    subkeys2 = generate_subkeys(key2)
    subkeys3 = generate_subkeys(key3)
    temp = des_decrypt_block(block, subkeys3)
    temp = des_encrypt_block(temp, subkeys2)
    return des_decrypt_block(temp, subkeys1)


def pad_data(data: bytes) -> bytes:
    pad_length = 8 - (len(data) % 8)
    return data + bytes([pad_length]) * pad_length


def unpad_data(data: bytes) -> bytes:
    pad_length = data[-1]
    if pad_length > 8:
        return data  
    for i in range(1, pad_length + 1):
        if data[-i] != pad_length:
            return data 
    return data[:-pad_length]


def process_keys(key_string: str) -> Tuple[bytes, bytes, bytes]:
    key_bytes = key_string.encode('utf-8')
    key1 = bytearray()
    key2 = bytearray()
    key3 = bytearray()
    for i in range(8):
        if i < len(key_bytes):
            key1.append(key_bytes[i])
        else:
            key1.append(0)
            
        if i + 8 < len(key_bytes):
            key2.append(key_bytes[i + 8])
        else:
            key2.append(0)
            
        if i + 16 < len(key_bytes):
            key3.append(key_bytes[i + 16])
        else:
            key3.append(0)
    
    return bytes(key1), bytes(key2), bytes(key3)


def encrypt_data_3des(data: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    padded_data = pad_data(data)
    iv = os.urandom(8)
    result = bytearray(iv)  
    
    prev_block = iv
    for i in range(0, len(padded_data), 8):
        block = padded_data[i:i+8]
        xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted_block = triple_des_encrypt_block(xored_block, key1, key2, key3)
        result.extend(encrypted_block)
        prev_block = encrypted_block
        
    return bytes(result)


def decrypt_data_3des(data: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    if len(data) < 8:
        raise ValueError("Data is too short to be valid 3DES encrypted data")
    iv = data[:8]
    ciphertext = data[8:]
    
    result = bytearray()
    prev_block = iv
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        decrypted_block = triple_des_decrypt_block(block, key1, key2, key3)
        xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        result.extend(xored_block)
        prev_block = block
    return unpad_data(bytes(result))


def encrypt_file_3des(input_path: str, output_path: str, key_string: str):
    key1, key2, key3 = process_keys(key_string)
    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_data_3des(data, key1, key2, key3)
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)


def decrypt_file_3des(input_path: str, output_path: str, key_string: str):
    key1, key2, key3 = process_keys(key_string)
    with open(input_path, 'rb') as f:
        data = f.read()
    try:
        decrypted_data = decrypt_data_3des(data, key1, key2, key3)
    except Exception as e:
        print(f"Error decrypting file: {e}")
        return
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Encrypt: python 3des.py encrypt <input_file> <output_file> <key>")
        print("  Decrypt: python 3des.py decrypt <input_file> <output_file> <key>")
        print("  Text:    python 3des.py text <message> <key>")
        return
    
    mode = sys.argv[1].lower()
    
    if mode == "encrypt" and len(sys.argv) >= 5:
        input_file = sys.argv[2]
        output_file = sys.argv[3]
        key = sys.argv[4]
        
        print(f"Encrypting {input_file} to {output_file}...")
        encrypt_file_3des(input_file, output_file, key)
        print("Encryption complete!")
        
    elif mode == "decrypt" and len(sys.argv) >= 5:
        input_file = sys.argv[2]
        output_file = sys.argv[3]
        key = sys.argv[4]
        
        print(f"Decrypting {input_file} to {output_file}...")
        decrypt_file_3des(input_file, output_file, key)
        print("Decryption complete!")
        
    elif mode == "text" and len(sys.argv) >= 4:
        message = sys.argv[2]
        key = sys.argv[3]
        print(sys.argv)
        key1, key2, key3 = process_keys(key)
        encrypted = encrypt_data_3des(message.encode('utf-8'), key1, key2, key3)
        print(f"Encrypted (hex): {encrypted.hex()}")
        decrypted = decrypt_data_3des(encrypted, key1, key2, key3)
        print(f"Decrypted: {decrypted.decode('utf-8')}")
        
    else:
        print("Invalid command or missing arguments.")
        print("Usage:")
        print("  Encrypt: python 3des.py encrypt <input_file> <output_file> <key>")
        print("  Decrypt: python 3des.py decrypt <input_file> <output_file> <key>")
        print("  Text:    python 3des.py text <message> <key>")


if __name__ == "__main__":
    main()