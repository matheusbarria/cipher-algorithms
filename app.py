from flask import Flask, render_template, request
from aes import encrypt_text, decrypt_text 

app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def home():
    return render_template('home.html')

@app.route("/aes", methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        try:
            key = request.form['key']
            text = request.form['text']
            action = request.form.get('action', 'encrypt')  
            if action == 'encrypt':
                result = encrypt_text(text, key)
            elif action == 'decrypt':
                result = decrypt_text(text, key)
            else:
                result = "Invalid action."
            
            values = {
                'key': key,
                'text': text,
                'action': action,
                'result': result
            }

            return render_template('aes.html', values=values)
        except ValueError as e:
            return f'Error: {e}'

    return render_template('aes.html')

if __name__ == "__main__":
    app.run(debug=True)
