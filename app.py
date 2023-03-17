
import requests
from flask import Flask, jsonify ,request
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

app = Flask(__name__)

@app.route("/start", methods = ['POST'])
def start():
    data = request.get_json()
    ip = data['ip']
    banner = 'B00838277'
    url = 'http://44.202.179.158:8080/start'
    response = requests.post(url, json={"banner": banner, "ip":ip})
    if (response.status_code != 204):
        # response.headers["content-type"].strip().startswith("application/json")
        try:
            return response.content, 200
        except ValueError:
            return response.content, 500
    else:
        return response.content,400


@app.route("/encrypt", methods=['POST'])
def encryptMessage():
    data = request.get_json()
    textToEncrypt = data['message']
    f = open('folder1/public_key_1.pem', 'r')
    RSApublic= RSA.importKey(f.read())
    cipher = PKCS1_OAEP.new(RSApublic)
    textToEncrypt = str.encode(textToEncrypt)
    encryptedMsg = cipher.encrypt(textToEncrypt)
    BinToBase64 = base64.b64encode(encryptedMsg)

    return jsonify({"response": BinToBase64.decode()}), 200

@app.route("/decrypt", methods = ['POST'])
def decryptMessage():
    data = request.get_json()
    messageToDecrypt = data['message']
    base64ToBin = base64.b64decode(messageToDecrypt)
    f = open('folder1/private_key_1.pem', 'r')
    RSApriv = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(RSApriv)
    finalDecryt = cipher.decrypt(base64ToBin)
    return jsonify({"response" : finalDecryt.decode('utf-8')}),200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)