from flask import Flask, render_template, request, send_from_directory
from aes import encrypt_text, decrypt_text, encrypt_image, decrypt_image, encrypt_file, decrypt_file
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

if __name__ == "__main__":
    app.run(debug=True)
