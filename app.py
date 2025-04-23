from flask import Flask, render_template, request, send_from_directory
from aes import encrypt_text, decrypt_text, encrypt_image, decrypt_image, encrypt_file, decrypt_file
from des3 import encrypt_data_3des, decrypt_data_3des, encrypt_file_3des, decrypt_file_3des
from RSA import RSA
from vigenere import VigenereCipher
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'testing_files/uploads'
DOWNLOAD_FOLDER = 'testing_files/download'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
file_name_extension = {}

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/", methods=['GET', 'POST'])
def home():
    return render_template('home.html')

@app.route("/3des", methods=['GET', 'POST'])
def triple_des():
    if request.method == 'POST':
        values = {}
        try:
            # Get all three keys
            key1 = request.form['key1']
            key2 = request.form['key2']
            key3 = request.form['key3']
            request_type = request.form['inputMode']
            action = request.form.get('action', 'encrypt')

            if request_type == 'text':
                text = request.form['text']
                if action == 'encrypt':
                    result = encrypt_data_3des(text.encode('utf-8'),
                                            key1.encode(),
                                            key2.encode(),
                                            key3.encode()).hex()
                elif action == 'decrypt':
                    encrypted_bytes = bytes.fromhex(text)
                    result = decrypt_data_3des(encrypted_bytes,
                                            key1.encode(),
                                            key2.encode(),
                                            key3.encode()).decode('utf-8')
                else:
                    result = "Invalid action."

                values = {
                    'request_type': request_type,
                    'action': action,
                    'key1': key1,
                    'key2': key2,
                    'key3': key3,
                    'result': result
                }

            elif request_type in ['file', 'image']:
                file = request.files.get('file_sub')
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                if action == 'encrypt':
                    file_name = 'encrypted_' + filename.split('.')[0]
                    file_name_extension[file_name] = filename.split('.')[1]
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    encrypt_file_3des(file_path, output_path, key1)
                elif action == 'decrypt':
                    extension = file_name_extension.get(filename.split('.')[0],
                                                      'png' if request_type == 'image' else 'txt')
                    file_name = 'decrypted_' + filename.split('.')[0] + '.' + extension
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    decrypt_file_3des(file_path, output_path, key1)

                values = {
                    'request_type': request_type,
                    'action': action,
                    'key1': key1,
                    'key2': key2,
                    'key3': key3,
                    'result': f'{"Image" if request_type == "image" else "File"} {action}ed successfully to {output_path}',
                    'output_path': output_path,
                    'file_name': file_name,
                }

            return render_template('3des.html', values=values)
        except ValueError as e:
            return f'Error: {e}'
        except Exception as e:
            return f'Error: {str(e)}'

    return render_template('3des.html', values=None)


@app.route("/aes", methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        values={}
        try:
            key = request.form['key']
            request_type = request.form['inputMode']
            action = request.form.get('action', 'encrypt')
            print(request.form)
            if request_type == 'text':
                text = request.form['text']
                if action == 'encrypt':
                    result = encrypt_text(text, key)
                elif action == 'decrypt':
                    result = decrypt_text(text, key)
                else:
                    result = "Invalid action."

                values = {
                    'request_type': request_type,
                    'action': action,
                    'key': key,
                    'result': result
                }
            elif request_type == 'image':
                if action == 'encrypt':
                    file = request.files.get('file_sub')
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_name = 'encrypted_' + filename.split('.')[0]
                    file_name_extension[file_name] = filename.split('.')[1]
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    encrypt_image(file_path, output_path, key)
                    values = {
                        'request_type': request_type,
                        'action': action,
                        'key': key,
                        'result': f'Image encrypted successfully to {output_path}',
                        'output_path': output_path,
                        'file_name': file_name,
                    }
                elif action == 'decrypt':
                    file = request.files.get('file_sub')
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_name = 'decrypted_' + filename.split('.')[0] + '.' + file_name_extension.get(filename, 'png')
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    decrypt_image(file_path, output_path, key)
                    values = {
                        'request_type': request_type,
                        'action': action,
                        'key': key,
                        'result': f'Image decrypted successfully to {output_path}',
                        'output_path': output_path,
                        'file_name': file_name,
                    }
            elif request_type == 'file':
                if action == 'encrypt':
                    file = request.files.get('file_sub')
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_name = 'encrypted_' + filename.split('.')[0]
                    file_name_extension[file_name] = filename.split('.')[1]
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'],file_name )
                    encrypt_file(file_path, output_path, key)
                    values = {
                        'request_type': request_type,
                        'action': action,
                        'key': key,
                        'result': f'File encrypted successfully to {output_path}',
                        'output_path': output_path,
                        'file_name': file_name,
                    }
                elif action == 'decrypt':
                    file = request.files.get('file_sub')
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_name = 'decrypted_' + filename.split('.')[0] + '.' + file_name_extension.get(filename, 'txt')
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    decrypt_file(file_path, output_path, key)
                    values = {
                        'request_type': request_type,
                        'action': action,
                        'key': key,
                        'result': f'File decrypted successfully to {output_path}',
                        'output_path': output_path,
                        'file_name': file_name,
                    }
            print(file_name_extension)
            return render_template('aes.html', values=values)
        except ValueError as e:
            return f'Error: {e}'

    return render_template('aes.html', values=None)

@app.route("/rsa", methods=['GET', 'POST'])
def rsa():
    if request.method == 'POST':
        values = {}
        try:
            # Get prime numbers
            p = int(request.form['p'])
            q = int(request.form['q'])
            request_type = request.form['inputMode']
            action = request.form.get('action', 'encrypt')

            # Create RSA instance
            rsa_cipher = RSA(p, q)

            if request_type == 'text':
                text = request.form['text']
                if action == 'encrypt':
                    result = rsa_cipher.encrypt_text(text)
                elif action == 'decrypt':
                    result = rsa_cipher.decrypt_text(text)
                else:
                    result = "Invalid action."

                values = {
                    'request_type': request_type,
                    'action': action,
                    'p': p,
                    'q': q,
                    'result': result
                }

            elif request_type in ['file', 'image']:
                file = request.files.get('file_sub')
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                if action == 'encrypt':
                    file_name = 'encrypted_' + filename.split('.')[0]
                    file_name_extension[file_name] = filename.split('.')[1]
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    rsa_cipher.encrypt_file(file_path, output_path)
                elif action == 'decrypt':
                    extension = file_name_extension.get(filename.split('.')[0],
                                                     'png' if request_type == 'image' else 'txt')
                    file_name = 'decrypted_' + filename.split('.')[0] + '.' + extension
                    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_name)
                    rsa_cipher.decrypt_file(file_path, output_path)

                values = {
                    'request_type': request_type,
                    'action': action,
                    'p': p,
                    'q': q,
                    'result': f'{"Image" if request_type == "image" else "File"} {action}ed successfully to {output_path}',
                    'output_path': output_path,
                    'file_name': file_name,
                }

            return render_template('rsa.html', values=values)
        except ValueError as e:
            return f'Error: {e}'
        except Exception as e:
            return f'Error: {str(e)}'

    return render_template('rsa.html', values=None)

@app.route("/vigenere", methods=['GET', 'POST'])
def vigenere():
    if request.method == 'POST':
        values = {}
        try:
            # Get key
            key = request.form['key']
            request_type = request.form['inputMode']
            action = request.form.get('action', 'encrypt')

            # Create Vigenere Cipher instance
            vigenere_cipher = VigenereCipher(key)

            if request_type == 'text':
                text = request.form['text']
                if action == 'encrypt':
                    result = vigenere_cipher.encrypt(text)
                elif action == 'decrypt':
                    result = vigenere_cipher.decrypt(text)
                else:
                    result = "Invalid action."

                values = {
                    'request_type': request_type,
                    'action': action,
                    'key': key,
                    'result': result
                }

            return render_template('vigenere.html', values=values)
        except ValueError as e:
            return f'Error: {e}'
        except Exception as e:
            return f'Error: {str(e)}'

    return render_template('vigenere.html', values=None)

if __name__ == "__main__":
    app.run(debug=True)
