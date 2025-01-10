from flask import Flask, request, jsonify, render_template, session
import os
import uuid
from utils.managing_files import read_pcap, extract, generate_session_id, get_or_create_session_id, combine_pcap_files
from utils.packet_analyzer import PacketAnalyzer

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'  # Replace 'your_secret_key_here' with a unique and secret key
rename_map = {
    'version': 'ip_version',
    'ihl': 'ip_ihl',
    'tos': 'ip_tos',
    'len': 'ip_len',
    'id': 'ip_id',
    'flags': 'flags',
    'frag': 'ip_frag',
    'ttl': 'ip_ttl',
    'proto': 'ip_proto',
    'chksum': 'chksum',
    'src': 'ip_src',
    'dst': 'ip_dst',
    'options': 'options',
    'sport': 'udp_sport',
    'dport': 'udp_dport',
    'chksum': 'chksum',
    'seq': 'tcp_seq',
    'ack': 'tcp_ack',
    'dataofs': 'tcp_dataofs',
    'reserved': 'tcp_reserved',
    'flags': 'flags',
    'window': 'tcp_window',
    'urgptr': 'tcp_urgptr',
    'options': 'options',
    'payload': 'app_payload',
    'payload_raw': 'app_payload_raw',
    'payload_hex': 'app_payload_hex',
}
rename_map_2 = {
    5: 'ip_flags',
    20: 'tcp_flags',
    12: 'ip_options',
    24: 'tcp_options',
    9: 'ip_chskum',
    22: 'udp_chskum'
}


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
        
        session_id = get_or_create_session_id(session)

        session_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
        os.makedirs(session_folder, exist_ok=True)

        filename = file.filename
        file_path = os.path.join(session_folder, filename)
        file.save(file_path)
        p_summary = read_pcap(file_path)

        return jsonify({'success': True, 'message': f'File "{filename}" imported successfully! Summary: {p_summary}', 'filename': filename })
    else:
        return jsonify({'success': False, 'message': 'Invalid file format. Please upload a .pcap file.'})

@app.route('/files', methods=['GET'])
def list_files():
    try:
        session_id = get_or_create_session_id(session)
        session_files_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
        files = os.listdir(session_files_folder)
        return jsonify(files)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete', methods=['POST'])
def delete_files():
    try:
        files_to_delete = request.json.get('files', [])
        for filename in files_to_delete:
            session_id = get_or_create_session_id(session)
            session_files_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id)            
            file_path = os.path.join(session_files_folder, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        return jsonify({'success': True, 'message': 'Selected files deleted successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/filter_view')
def filter_view():
    return render_template('filter_view.html')

@app.route('/filter_data', methods=['POST'])
def filter_data():


    # Get filter parameters from request JSON
    filter_object = request.get_json()
    columns = filter_object.get('columns', {})
    
    print(columns)

    session_id = get_or_create_session_id(session)
    print(session_id)

    data = combine_pcap_files(app.config['UPLOAD_FOLDER'], session_id)
    print(session_id)
    print(data)
    analyzer = PacketAnalyzer(data)
    filtered_df = print(analyzer.display())
    
    for column, operation in columns.items():
        # Apply filters based on the operation
        if operation.get('filter'):
            filter_type = operation['filter'].get('type')
            filter_value = operation['filter'].get('value')
            
            if filter_type == 'equal':
                print(column)
                print(filter_value[0])
                analyzer.filter_by_column_value(column, filter_value[0])
            elif filter_type == 'not_equal':
                filtered_df = filtered_df[~filtered_df[column].isin(filter_value)]
            else:
                return jsonify({'error': f"Unsupported filter type: {filter_type}"}), 400
    filtered_df = analyzer.display()
    print(filtered_df)
    print(filtered_df.columns)
    filtered_df.rename(columns=rename_map, inplace=True)
    columns = list(filtered_df.columns)

    filtered_df.columns.values[5] = 'ip_flags' 
    filtered_df.columns.values[20] = 'tcp_flags'

    filtered_df.columns.values[12] = 'ip_options' 
    filtered_df.columns.values[24] = 'tcp_options' 

    filtered_df.columns.values[9] = 'ip_chskum' 
    filtered_df.columns.values[22] = 'udp_chskum'

    # columns_to_drop = ['app_payload', 'app_payload_raw', 'app_payload_hex']
    # filtered_df.drop(columns=columns_to_drop, inplace=True)

    print(filtered_df.columns)

    print(filtered_df)
    
    return jsonify({'success': True, 'message' : f'Data has been filtered successfully! Filter: {filter_object}'})

        
    # Check if data was successfully parsed
    # if not data:
    #     return jsonify({'error': 'Invalid or missing JSON filtering data'}), 400
    
    # Process the data (example: print it)
   #  print("Received JSON data:", data)

    # Send a response back
    # return jsonify({'message': 'JSON received successfully', 'data': data}), 200

if __name__ == '__main__':
    app.run(debug=True)
