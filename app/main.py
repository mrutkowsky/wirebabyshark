from flask import Flask, request, jsonify, render_template
import os
from utils.managing_files import read_pcap, extract

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'pcapFile' not in request.files:
        return jsonify({'success': False, 'message': 'No file part in the request.'})

    file = request.files['pcapFile']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected.'})

    if file and allowed_file(file.filename):
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        p = read_pcap(file_path)
        # p_df = extract(p)
        return jsonify({'success': True, 'message': f'File "{filename}" imported successfully! Summary: {p}', 'filename': filename })
    else:
        return jsonify({'success': False, 'message': 'Invalid file format. Please upload a .pcap file.'})

@app.route('/files', methods=['GET'])
def list_files():
    try:
        files = os.listdir(UPLOAD_FOLDER)
        return jsonify(files)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete', methods=['POST'])
def delete_files():
    try:
        files_to_delete = request.json.get('files', [])
        for filename in files_to_delete:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        return jsonify({'success': True, 'message': 'Selected files deleted successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
