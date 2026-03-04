from flask import Flask, request
import numpy as np
from sympy import symbols

app = Flask(__name__)

# Generate random coefficients for the equations (private key)
coefficients_1 = np.random.randint(-10, 10, size=3)
coefficients_2 = np.random.randint(-10, 10, size=3)

# Define multivariate polynomial equations based on the generated coefficients
x = symbols('x')
equation_1 = coefficients_1[0]*x**2 + coefficients_1[1]*x + coefficients_1[2]
equation_2 = coefficients_2[0]*x**2 + coefficients_2[1]*x + coefficients_2[2]

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

    <p>Encrypted Message: {{ encrypted_message }}</p>
    <p>Decrypted Message: {{ decrypted_message }}</p>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Encrypt or Decrypt based on form submission
        if 'encrypt' in request.form:
            message = request.form['message']
            if "REDACTED" in message:
                # Perform separate encryption for "REDACTED" content
                encrypted_message = symmetric_encrypt(message)
            else:
                # Perform multivariate encryption for other content
                encrypted_message = encrypt_multivariate(message, coefficients_1, coefficients_2)
            return html_content.replace('{{ encrypted_message }}', str(encrypted_message)).replace('{{ decrypted_message }}', '')
        elif 'decrypt' in request.form:
            encrypted_message = eval(request.form['encrypted_message'])  # Convert string representation of list to list
            decrypted_message = decrypt(encrypted_message, coefficients_1, coefficients_2)
            return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', decrypted_message)
    # Render the HTML content without encrypted or decrypted messages
    return html_content.replace('{{ encrypted_message }}', '').replace('{{ decrypted_message }}', '')

def encrypt_multivariate(message, coefficients_1, coefficients_2):
    # Encryption process using multivariate cryptography
    encrypted = []
    for char in message:
        numerical_value = ord(char)  # Convert character to ASCII value
        encrypted.append((evaluate_equation(equation_1, numerical_value, coefficients_1),
                          evaluate_equation(equation_2, numerical_value, coefficients_2)))
    return encrypted

def symmetric_encrypt(message):
    # Perform symmetric encryption for "REDACTED" content
    # Add your symmetric encryption code here
    return "Symmetrically Encrypted: " + message

def decrypt(encrypted, coefficients_1, coefficients_2):
    # Decryption process
    decrypted = ""
    for pair in encrypted:
        for x in range(256):  # Assume ASCII range
            if evaluate_equation(equation_1, x, coefficients_1) == pair[0] \
                    and evaluate_equation(equation_2, x, coefficients_2) == pair[1]:
                decrypted += chr(x)  # Convert ASCII value to character
                break
    return decrypted

def evaluate_equation(equation, x_value, coefficients):
    return equation.subs({'x': x_value, coefficients[0]: 'a', coefficients[1]: 'b', coefficients[2]: 'c'})

if __name__ == '__main__':
    app.run(debug=True)
