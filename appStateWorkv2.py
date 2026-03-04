from flask import Flask, render_template, redirect, url_for, request
import random

app = Flask(__name__)

def generate_keypair():
    a1, b1, c1, a2, b2, c2 = random.randint(1, 1073741824), random.randint(1, 1073741824), random.randint(1, 1073741824), random.randint(1, 1073741824), random.randint(1, 1073741824), random.randint(1, 1073741824)
    
    def equation_1_private(x):
        return a1*x**2 + b1*x + c1

    def equation_2_private(x):
        return a2*x**2 + b2*x + c2

    def equation_1_public(x):
        return a1*x**2 + b1*x + c1
    
    def equation_2_public(x):
        return a2*x**2 + b2*x + c2

    public_key = (equation_1_public, equation_2_public)
    private_key = (equation_1_private, equation_2_private)
    
    return public_key, private_key

public_key, private_key = generate_keypair()

def encrypt(message, public_key):
    equation_1 = public_key[0]
    equation_2 = public_key[1]
    encrypted = []
    for char in message:
        numerical_value = ord(char)
        encrypted.append((equation_1(numerical_value), equation_2(numerical_value)))
    return encrypted

def decrypt(encrypted, private_key):
    equation_1, equation_2 = private_key
    decrypted = ""
    for pair in encrypted:
        found = False
        for x in range(256):
            if equation_1(x) == pair[0] and equation_2(x) == pair[1]:
                decrypted += chr(x)
                found = True
                break
        if not found:
            decrypted += "?"
    return decrypted

def caesar_encrypt(message, shift):
    encrypted_chars = []
    for char in message:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26) + ord('a' if char.islower() else 'A'))
            encrypted_chars.append(shifted_char)
        else:
            encrypted_chars.append(char)
    encrypted_message = ''.join(encrypted_chars)
    return encrypted_message

def caesar_decrypt(encrypted_message, shift):
    decrypted_chars = []
    for char in encrypted_message:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') - shift) % 26) + ord('a' if char.islower() else 'A'))
            decrypted_chars.append(shifted_char)
        else:
            decrypted_chars.append(char)
    decrypted_message = ''.join(decrypted_chars)
    return decrypted_message

def string_to_binary(message):
    binary_list = [format(ord(char), '08b') for char in message]
    binary_string = ' '.join(binary_list)
    return binary_string

def binary_to_string(binary_string):
    binary_list = binary_string.split()
    message = ''.join(chr(int(binary, 2)) for binary in binary_list)
    return message

@app.route('/', methods=['GET', 'POST'])
def index():
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Healthcare Encryption System</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        h1 {
            color: #007bff;
            text-align: center;
            margin-top: 30px;
        }
        form {
            background-color: #fff;
            max-width: 400px;
            margin: 20px auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        label {
            font-weight: bold;
            margin-bottom: 5px;
            display: block;
        }
        input[type="text"], input[type="submit"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="submit"] {
            background-color: #007bff;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        p {
            margin-top: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>Healthcare Encryption System</h1>
    
    <!-- Form for encryption -->
    <form method="POST" action="/">
        <label for="message">Enter Data to Encrypt:</label><br>
        <input type="text" id="message" name="message"><br>
        <input type="submit" name="encrypt" value="Encrypt">
    </form>

    <!-- Form for decryption -->
    <form method="POST" action="/">
        <label for="encrypted_message">Enter Data to Decrypt:</label><br>
        <input type="text" id="encrypted_message" name="encrypted_message"><br>
        <input type="submit" name="decrypt" value="Decrypt">
    </form>

    <div style="text-align: center;">
        <img src="https://www.appviewx.com/wp-content/uploads/2020/12/blog-Encryption-is-Critical-to-the-Healthcare-inner.png" alt="Healthcare Encryption" style="margin-top: 30px;">
    </div>

    <p>Encrypted Message: {{ encrypted_message }}</p>
    <p>Decrypted Message: {{ decrypted_message }}</p>
</body>
</html>
"""

    if request.method == 'POST':
        if 'encrypt' in request.form:
            message = request.form['message']
            if "REDACTED" in message:
                encrypted_message = string_to_binary(caesar_encrypt(message, shift=3))
            else:
                encrypted_pairs = encrypt(message, public_key)
                encrypted_message = str(encrypted_pairs)
            
            return html_content.replace('{{ encrypted_message }}', encrypted_message).replace('{{ decrypted_message }}', '')
        
        elif 'decrypt' in request.form:
            encrypted_message = request.form['encrypted_message']
            
            if all(char in '01 ' for char in encrypted_message):
                encrypted_message = binary_to_string(encrypted_message)
            
            try:
                encrypted_pairs = eval(encrypted_message)
            except SyntaxError:
                encrypted_pairs = []
            
            if encrypted_pairs and isinstance(encrypted_pairs, list) and all(isinstance(pair, tuple) and len(pair) == 2 for pair in encrypted_pairs):
                decrypted_message = decrypt(encrypted_pairs, private_key)
            else:
                decrypted_message = caesar_decrypt(encrypted_message, shift=3)
            
            return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', decrypted_message)
    
    return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', '')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
