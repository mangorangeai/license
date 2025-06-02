from flask import Flask, jsonify
import os
import time
import base64
from crypto import encrypt

app = Flask(__name__)


@app.route('/')
def index():
    unix = str(int(time.time()))
    e_data = encrypt(str(unix))
    return {"license": e_data}


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
