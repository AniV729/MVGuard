from flask import Flask, render_template, redirect, url_for, request
import json
import os

app = Flask(__name__)

# Multivariate cryptography functions
def equation_1(x):
    return x**2 + 3*x + 5

def equation_2(x):
    return 2*x**2 + 4*x + 7

def encrypt(message):
    encrypted = []
    for char in message:
        numerical_value = ord(char)  # Convert character to ASCII value
        encrypted.append((equation_1(numerical_value), equation_2(numerical_value)))
    return encrypted

def decrypt(encrypted):
    decrypted = ""
    for pair in encrypted:
        for x in range(256):          # Assume ASCII range
            if equation_1(x) == pair[0] and equation_2(x) == pair[1]:
                decrypted += chr(x)  # Convert ASCII value to character
                break
    return decrypted

# HTML content with embedded Flask variables
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Healthcare Multivariate Encryption/Decryption System</title>
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
    <form method="POST">
        <label for="message">Enter Data to Encrypt:</label><br>
        <input type="text" id="message" name="message"><br>
        <input type="submit" name="encrypt" value="Encrypt">
    </form>

    <!-- Form for decryption -->
    <form method="POST">
        <label for="encrypted_message">Enter Data to Decrypt:</label><br>
        <input type="text" id="encrypted_message" name="encrypted_message"><br>
        <input type="submit" name="decrypt" value="Decrypt">
    </form>

    <div style="text-align: center;">
        <img src="https://www.appviewx.com/wp-content/uploads/2020/12/blog-Encryption-is-Critical-to-the-Healthcare-inner.png" alt="Healthcare Encryption" style="margin-top: 30px;">
    </div>

    <p>Encrypted Message: {{ encrypted message }}</p>
    <p>Decrypted Message: {{ decrypted message }}</p>
</body>
</html>

"""
# Flask route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Encrypt or Decrypt based on form submission
        if 'encrypt' in request.form:
            message = request.form['message']
            encrypted_message = encrypt(message)
            return html_content.replace('{{ encrypted message }}', str(encrypted_message))
        elif 'decrypt' in request.form:
            encrypted_message = eval(request.form['encrypted_message'])  # Convert string representation of list to list
            decrypted_message = decrypt(encrypted_message)
            return html_content.replace('{{ decrypted message }}', decrypted_message)
    # Render the HTML content without encrypted or decrypted messages
    return html_content.replace('{{ encrypted message }}', '').replace('{{ decrypted message }}', '')


if __name__ == '__main__':
    app.run(debug=False)
