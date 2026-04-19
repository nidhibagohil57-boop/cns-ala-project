from flask import Flask, render_template, request
from logic.ala1_signature import *
from logic.ala2_hash import *
from logic.ala3_mac import *

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ala1', methods=['GET', 'POST'])
def ala1():
    sign_result = None
    sign_message_value = ""
    verify_result = None
    verify_error = None
    verify_form = {
        "message": "",
        "signature": "",
        "public_e": "",
        "public_n": ""
    }

    if request.method == 'POST':
        action = request.form.get('action', 'sign')
        sign_message_value = request.form.get('sign_message_value', '')

        if action == 'sign':
            message = request.form['message']
            sign_message_value = message
            signature, public_key, signed_hash = sign_message(message)
            verify, expected_hash, recovered_hash = verify_signature(message, signature, public_key)
            sign_result = {
                "message": message,
                "signature": signature,
                "public_key": public_key,
                "signed_hash": signed_hash,
                "expected_hash": expected_hash,
                "recovered_hash": recovered_hash,
                "verified": verify
            }

            verify_form = {
                "message": str(message),
                "signature": str(signature),
                "public_e": str(public_key[0]),
                "public_n": str(public_key[1])
            }

        elif action == 'verify':
            message = request.form.get('verify_message', '')
            signature_str = request.form.get('verify_signature', '').strip()
            public_e_str = request.form.get('verify_public_e', '').strip()
            public_n_str = request.form.get('verify_public_n', '').strip()

            verify_form = {
                "message": message,
                "signature": signature_str,
                "public_e": public_e_str,
                "public_n": public_n_str
            }

            try:
                signature = int(signature_str)
                public_e = int(public_e_str)
                public_n = int(public_n_str)
                verify, expected_hash, recovered_hash = verify_signature(message, signature, (public_e, public_n))
                verify_result = {
                    "verified": verify,
                    "expected_hash": expected_hash,
                    "recovered_hash": recovered_hash
                }
            except ValueError:
                verify_error = "Signature, public exponent (e), and modulus (n) must be valid integers."

    return render_template(
        'ala1.html',
        sign_result=sign_result,
        sign_message_value=sign_message_value,
        verify_result=verify_result,
        verify_error=verify_error,
        verify_form=verify_form
    )

@app.route('/ala2', methods=['GET', 'POST'])
def ala2():
    result = None
    original_text = ""
    changed_text = ""

    if request.method == 'POST':
        original_text = request.form.get('text', '')
        changed_text = request.form.get('changed_text', '')
        if not changed_text:
            changed_text = original_text + "."

        result = analyze_sha_integrity(original_text, changed_text)

    return render_template(
        'ala2.html',
        result=result,
        original_text=original_text,
        changed_text=changed_text
    )

@app.route('/ala3', methods=['GET', 'POST'])
def ala3():
    sender_result = None
    receiver_result = None
    receiver_error = None

    sender_form = {
        "message": "",
        "key": ""
    }

    receiver_form = {
        "message": "",
        "key": "",
        "mac": ""
    }

    if request.method == 'POST':
        action = request.form.get('action', 'send')

        sender_form = {
            "message": request.form.get('sender_message', ''),
            "key": request.form.get('sender_key', '')
        }

        receiver_form = {
            "message": request.form.get('receiver_message', ''),
            "key": request.form.get('receiver_key', ''),
            "mac": request.form.get('receiver_mac', '').strip().lower()
        }

        if action == 'send':
            msg = sender_form["message"]
            key = sender_form["key"]
            mac = generate_mac(msg, key)
            sender_result = {
                "message": msg,
                "mac": mac
            }

            receiver_form["message"] = msg
            receiver_form["key"] = key
            receiver_form["mac"] = mac

        elif action == 'verify':
            msg = receiver_form["message"]
            key = receiver_form["key"]
            mac = receiver_form["mac"]

            if not mac:
                receiver_error = "Received MAC is required for verification."
            else:
                is_valid, expected_mac = verify_mac(msg, key, mac)
                receiver_result = {
                    "verified": is_valid,
                    "received_mac": mac,
                    "expected_mac": expected_mac,
                    "integrity_status": "Intact" if is_valid else "Modified",
                    "auth_status": "Authenticated" if is_valid else "Authentication Failed"
                }

    return render_template(
        'ala3.html',
        sender_result=sender_result,
        receiver_result=receiver_result,
        receiver_error=receiver_error,
        sender_form=sender_form,
        receiver_form=receiver_form
    )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)