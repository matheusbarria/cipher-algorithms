#!/usr/bin/env python3
import os
import base64
import hashlib
from typing import List, Tuple

BLOCK_SIZE = 16
ROUNDS_BY_KEY_SIZE = {16: 10, 24: 12, 32: 14}

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
]

def xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def multiply_gf(a: int, b: int) -> int:
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def sub_word(word: List[int]) -> List[int]:
    return [SBOX[b] for b in word]

def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]

def key_expansion(key: bytes, key_size: int) -> List[List[int]]:
    key_bytes = list(key)
    nk = key_size // 4
    nr = ROUNDS_BY_KEY_SIZE[key_size]
    w = [key_bytes[4*i:4*i+4] for i in range(nk)]
    
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append([w[i-nk][j] ^ temp[j] for j in range(4)])
    
    return w

def add_round_key(state: List[List[int]], round_key: List[int]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i + j*4]
    return state

def sub_bytes(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    return state

def inv_sub_bytes(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]
    return state

def shift_rows(state: List[List[int]]) -> List[List[int]]:
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def mix_columns(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]
        
        state[0][i] = multiply_gf(0x02, s0) ^ multiply_gf(0x03, s1) ^ s2 ^ s3
        state[1][i] = s0 ^ multiply_gf(0x02, s1) ^ multiply_gf(0x03, s2) ^ s3
        state[2][i] = s0 ^ s1 ^ multiply_gf(0x02, s2) ^ multiply_gf(0x03, s3)
        state[3][i] = multiply_gf(0x03, s0) ^ s1 ^ s2 ^ multiply_gf(0x02, s3)
    
    return state

def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]
        
        state[0][i] = multiply_gf(0x0E, s0) ^ multiply_gf(0x0B, s1) ^ multiply_gf(0x0D, s2) ^ multiply_gf(0x09, s3)
        state[1][i] = multiply_gf(0x09, s0) ^ multiply_gf(0x0E, s1) ^ multiply_gf(0x0B, s2) ^ multiply_gf(0x0D, s3)
        state[2][i] = multiply_gf(0x0D, s0) ^ multiply_gf(0x09, s1) ^ multiply_gf(0x0E, s2) ^ multiply_gf(0x0B, s3)
        state[3][i] = multiply_gf(0x0B, s0) ^ multiply_gf(0x0D, s1) ^ multiply_gf(0x09, s2) ^ multiply_gf(0x0E, s3)
    
    return state

def bytes_to_state(data: bytes) -> List[List[int]]:
    assert len(data) == 16
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = data[i + 4*j]
    return state

def state_to_bytes(state: List[List[int]]) -> bytes:
    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[i + 4*j] = state[i][j]
    return bytes(result)

def aes_encrypt_block(block: bytes, expanded_key: List[List[int]], key_size: int) -> bytes:
    nr = ROUNDS_BY_KEY_SIZE[key_size]
    
    state = bytes_to_state(block)
    
    round_key = sum(expanded_key[:4], [])
    state = add_round_key(state, round_key)
    
    for round_num in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        round_key = sum(expanded_key[4*round_num:4*round_num+4], [])
        state = add_round_key(state, round_key)
    
    state = sub_bytes(state)
    state = shift_rows(state)
    round_key = sum(expanded_key[4*nr:4*nr+4], [])
    state = add_round_key(state, round_key)
    
    return state_to_bytes(state)

def aes_decrypt_block(block: bytes, expanded_key: List[List[int]], key_size: int) -> bytes:
    nr = ROUNDS_BY_KEY_SIZE[key_size]
    
    state = bytes_to_state(block)
    
    round_key = sum(expanded_key[4*nr:4*nr+4], [])
    state = add_round_key(state, round_key)
    
    for round_num in range(nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        round_key = sum(expanded_key[4*round_num:4*round_num+4], [])
        state = add_round_key(state, round_key)
        state = inv_mix_columns(state)
    
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    round_key = sum(expanded_key[:4], [])
    state = add_round_key(state, round_key)
    
    return state_to_bytes(state)

def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad_pkcs7(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def derive_key_and_iv(password: str, salt: bytes, key_size: int = 16, iv_size: int = 16) -> Tuple[bytes, bytes]:
    material = b''
    password_bytes = password.encode('utf-8')
    
    while len(material) < key_size + iv_size:
        h = hashlib.md5()
        h.update(material + password_bytes + salt)
        material += h.digest()
    
    return material[:key_size], material[key_size:key_size+iv_size]

def aes_encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")
    
    key_size = len(key)
    if key_size not in ROUNDS_BY_KEY_SIZE:
        raise ValueError(f"Invalid key size. Must be {', '.join(map(str, ROUNDS_BY_KEY_SIZE.keys()))} bytes.")
    
    padded_data = pad_pkcs7(data, BLOCK_SIZE)
    
    expanded_key = key_expansion(key, key_size)
    
    result = bytearray()
    prev_block = iv
    
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        
        xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
        
        encrypted_block = aes_encrypt_block(xored_block, expanded_key, key_size)
        result.extend(encrypted_block)
        
        prev_block = encrypted_block
    
    return bytes(result)

def aes_decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")
    
    key_size = len(key)
    if key_size not in ROUNDS_BY_KEY_SIZE:
        raise ValueError(f"Invalid key size. Must be {', '.join(map(str, ROUNDS_BY_KEY_SIZE.keys()))} bytes.")
    
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of block size")
    
    expanded_key = key_expansion(key, key_size)
    
    result = bytearray()
    prev_block = iv
    
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        
        decrypted_block = aes_decrypt_block(block, expanded_key, key_size)
        
        xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        result.extend(xored_block)
        
        prev_block = block
    
    return unpad_pkcs7(result)

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(8)
    
    key, iv = derive_key_and_iv(password, salt, key_size=32)
    
    data = text.encode('utf-8')
    
    encrypted = aes_encrypt_cbc(data, key, iv)
    
    result = b'Salted__' + salt + encrypted
    
    return base64.b64encode(result).decode('utf-8')

def decrypt_text(encrypted_text: str, password: str) -> str:
    encrypted_data = base64.b64decode(encrypted_text)
    
    if encrypted_data[:8] != b'Salted__':
        raise ValueError("Invalid encrypted data format")
    
    salt = encrypted_data[8:16]
    ciphertext = encrypted_data[16:]
    
    key, iv = derive_key_and_iv(password, salt, key_size=32)
    
    decrypted = aes_decrypt_cbc(ciphertext, key, iv)
    
    return decrypted.decode('utf-8')

def encrypt_file(input_file: str, output_file: str, password: str) -> None:
    salt = os.urandom(8)
    
    key, iv = derive_key_and_iv(password, salt, key_size=32)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted = aes_encrypt_cbc(data, key, iv)
    
    with open(output_file, 'wb') as f:
        f.write(b'Salted__' + salt + encrypted)

def decrypt_file(input_file: str, output_file: str, password: str) -> None:
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    
    if encrypted_data[:8] != b'Salted__':
        raise ValueError("Invalid encrypted file format")
    
    salt = encrypted_data[8:16]
    ciphertext = encrypted_data[16:]
    
    key, iv = derive_key_and_iv(password, salt, key_size=32)
    
    decrypted = aes_decrypt_cbc(ciphertext, key, iv)
    
    with open(output_file, 'wb') as f:
        f.write(decrypted)

def encrypt_image(input_file: str, output_file: str, password: str) -> None:
    encrypt_file(input_file, output_file, password)

def decrypt_image(input_file: str, output_file: str, password: str) -> None:
    decrypt_file(input_file, output_file, password)


def print_menu():
    menu = """
    [1] Encrypt Text
    [2] Decrypt Text
    [3] Encrypt File
    [4] Decrypt File
    [5] Encrypt Image
    [6] Decrypt Image
    [0] Exit
    """
    print(menu)

def get_password() -> str:
    while True:
        password = input("Enter password: ")
        if len(password) < 4:
            print("Password must be at least 4 characters long.")
            continue
        confirm = input("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        return password

def main():
    while True:
        print_menu()
        choice = input("Enter your choice [0-6]: ")
        
        if choice == '0':
            break
        
        elif choice == '1':
            text = input("Enter text to encrypt: ")
            password = get_password()
            
            try:
                encrypted = encrypt_text(text, password)
                print("\nEncrypted text (base64):")
                print(encrypted)
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == '2':
            encrypted = input("Enter encrypted text (base64): ")
            password = input("Enter password: ")
            
            try:
                decrypted = decrypt_text(encrypted, password)
                print("\nDecrypted text:")
                print(decrypted)
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == '3':
            input_file = input("Enter path to input file: ")
            output_file = input("Enter path to output file: ")
            password = get_password()
            
            try:
                encrypt_file(input_file, output_file, password)
                print(f"File encrypted successfully to {output_file}")
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == '4':
            input_file = input("Enter path to encrypted file: ")
            output_file = input("Enter path to output file: ")
            password = input("Enter password: ")
            
            try:
                decrypt_file(input_file, output_file, password)
                print(f"File decrypted successfully to {output_file}")
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == '5':
            input_file = input("Enter path to input image: ")
            output_file = input("Enter path to output file: ")
            password = get_password()
            
            try:
                encrypt_image(input_file, output_file, password)
                print(f"Image encrypted successfully to {output_file}")
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == '6':
            input_file = input("Enter path to encrypted image: ")
            output_file = input("Enter path to output image: ")
            password = input("Enter password: ")
            
            try:
                decrypt_image(input_file, output_file, password)
                print(f"Image decrypted successfully to {output_file}")
            except Exception as e:
                print(f"Error: {str(e)}")
        
        else:
            print("Invalid choice. Please try again.")
        
        print("\n" + "-" * 50)

if __name__ == "__main__":
    main()