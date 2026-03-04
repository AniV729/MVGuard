from flask import Flask, request
import random

app = Flask(__name__)

# Define multivariate cryptography functions with enhanced security features
def generate_keypair():
    # Random coefficients for equations
    a1, b1, c1, a2, b2, c2 = random.randint(1, 100), random.randint(1, 100), random.randint(1, 100), random.randint(1, 100), random.randint(1, 100), random.randint(1, 100)
    
    # Define equations for private key
    def equation_1_private(x):
        return a1*x**2 + b1*x + c1

    def equation_2_private(x):
        return a2*x**2 + b2*x + c2

    # Define equations for public key (subset of private key)
    def equation_1_public(x):
        return a1*x**2 + b1*x + c1
    
    def equation_2_public(x):
        return a2*x**2 + b2*x + c2

    public_key = (equation_1_public, equation_2_public)
    private_key = (equation_1_private, equation_2_private)
    
    return public_key, private_key

public_key, private_key = generate_keypair()  # Generate key pair once

def encrypt(message, public_key):
    equation_1 = public_key[0]
    equation_2 = public_key[1]
    encrypted = []
    for char in message:
        numerical_value = ord(char)  # Convert character to ASCII value
        encrypted.append((equation_1(numerical_value), equation_2(numerical_value)))
    return encrypted

def decrypt(encrypted, private_key):
    equation_1, equation_2 = private_key
    decrypted = ""
    for pair in encrypted:
        found = False
        for x in range(256):          # Assume ASCII range
            if equation_1(x) == pair[0] and equation_2(x) == pair[1]:
                decrypted += chr(x)  # Convert ASCII value to character
                found = True
                break
        if not found:
            decrypted += "?"  # Placeholder for characters not found
    return decrypted

# Flask route
@app.route('/', methods=['GET', 'POST'])
def index():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Healthcare Multivariate Encryption/Decryption System</title>
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

        <p>Encrypted Message: {{ encrypted_message }}</p>
        <p>Decrypted Message: {{ decrypted_message }}</p>
    </body>
    </html>
    """

    if request.method == 'POST':
        if 'encrypt' in request.form:
            message = request.form['message']
            encrypted_message = encrypt(message, public_key)
            return html_content.replace('{{ encrypted_message }}', str(encrypted_message)).replace('{{ decrypted_message }}', '')
        elif 'decrypt' in request.form:
            encrypted_message = eval(request.form['encrypted_message'])
            decrypted_message = decrypt(encrypted_message, private_key)
            return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', decrypted_message)
    
    return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', '')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
