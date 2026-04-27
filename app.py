import os
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from smart_defense import bp as smart_defense_bp

app = Flask(__name__, template_folder='templates')
CORS(app)
app.register_blueprint(smart_defense_bp)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/health')
def health():
    return jsonify({'ok': True, 'service': 'bbtec-smart-defense-standalone'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=False)
