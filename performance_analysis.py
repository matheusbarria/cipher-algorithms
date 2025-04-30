import time
import os
import statistics
import csv
from tabulate import tabulate
from aes import encrypt_text as aes_encrypt, decrypt_text as aes_decrypt
from des3 import encrypt_data_3des, decrypt_data_3des
from RSA import RSA
from vigenere import VigenereCipher

def measure_execution_time(func, *args, iterations=10):
    times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        func(*args)
        end_time = time.perf_counter()
        times.append((end_time - start_time) * 1000)  # convert to ms
    return {
        'mean': statistics.mean(times),
        'median': statistics.median(times),
        'std_dev': statistics.stdev(times)
    }

def analyze_algorithm(name, encrypt_func, decrypt_func, *args):
    try:
        encrypt_stats = measure_execution_time(encrypt_func, *args)
        
        if name == "RSA":
            encrypted = encrypt_func(*args)
            decrypt_stats = measure_execution_time(decrypt_func, encrypted)
        else:
            encrypted = encrypt_func(*args)
            decrypt_args = (encrypted,) + args[1:]
            decrypt_stats = measure_execution_time(decrypt_func, *decrypt_args)
        
        return {
            'encryption': encrypt_stats,
            'decryption': decrypt_stats
        }
    except Exception as e:
        return {
            'encryption': {'mean': float('inf'), 'std_dev': 0},
            'decryption': {'mean': float('inf'), 'std_dev': 0},
            'error': str(e)
        }

def prepare_results_data(all_results):
    headers = ["Text Length", "Algorithm", "Operation", "Mean (ms)", "Std Dev (ms)", "Notes"]
    rows = []
    
    for length, results in all_results.items():
        for algo, stats in results.items():
            error_msg = stats.get('error', '')
            
            rows.append([
                length,
                algo,
                "Encryption",
                "Failed" if stats['encryption']['mean'] == float('inf') else f"{stats['encryption']['mean']:.4f}",
                "N/A" if stats['encryption']['mean'] == float('inf') else f"±{stats['encryption']['std_dev']:.4f}",
                error_msg
            ])
            rows.append([
                length,
                algo,
                "Decryption",
                "Failed" if stats['decryption']['mean'] == float('inf') else f"{stats['decryption']['mean']:.4f}",
                "N/A" if stats['decryption']['mean'] == float('inf') else f"±{stats['decryption']['std_dev']:.4f}",
                error_msg
            ])
    
    return headers, rows

def create_performance_table(headers, rows):
    return tabulate(rows, headers=headers, tablefmt="grid")

def save_results_to_csv(headers, rows, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(rows)

def main():
    text_lengths = [50, 100, 500, 1000, 5000]
    base_text = "This is a sample text for encryption performance testing. " * 100
    
    aes_key = "ThisIsASecretKey"
    des3_key1 = b"key1"
    des3_key2 = b"key2"
    des3_key3 = b"key3"
    vigenere_key = "SECRETKEY"
    rsa = RSA(61, 53)  

    all_results = {}
    
    for length in text_lengths:
        sample_text = base_text[:length]
        
        results = {
            'RSA': analyze_algorithm(
                "RSA",
                rsa.encrypt_text,
                rsa.decrypt_text,
                sample_text
            ),
            'AES': analyze_algorithm(
                "AES",
                aes_encrypt,
                aes_decrypt,
                sample_text,
                aes_key
            ),
            '3DES': analyze_algorithm(
                "3DES",
                lambda t, k1, k2, k3: encrypt_data_3des(t.encode(), k1, k2, k3).hex(),
                lambda t, k1, k2, k3: decrypt_data_3des(bytes.fromhex(t), k1, k2, k3).decode(),
                sample_text,
                des3_key1,
                des3_key2,
                des3_key3
            ),
            'Vigenere': analyze_algorithm(
                "Vigenere",
                VigenereCipher(vigenere_key).encrypt,
                VigenereCipher(vigenere_key).decrypt,
                sample_text
            )
        }
        
        all_results[length] = results
    
    headers, rows = prepare_results_data(all_results)
    
    table = create_performance_table(headers, rows)
    print("\nPerformance Analysis Results")
    print(table)

    with open('performance_results.txt', 'w') as f:
        f.write("Performance Analysis Results\n")
        f.write(table)
    
    save_results_to_csv(headers, rows, 'performance_results.csv')

if __name__ == "__main__":
    main()