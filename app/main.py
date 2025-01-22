from flask import Flask, request, jsonify, render_template, session,  make_response
import os
import uuid
import zipfile
import io
import pandas as pd
from utils.managing_files import \
    read_pcap, \
    generate_session_id, \
    get_or_create_session_id, \
    combine_pcap_files, \
    create_response_report, \
    write_to_txt
from utils.data_processing import \
    clean_value, \
    summarize_df, \
    summarize_networking_df, \
    rag_prompt, \
    preprocess_csv
from utils.packet_analyzer import PacketAnalyzer

app = Flask(__name__)

app.secret_key = os.environ["SECRET_KEY"] 
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
inteligent_overview_extension = "enabled"

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
        files = [f for f in os.listdir(session_files_folder) if f != 'tmp']
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
    print(analyzer.display())
    filtered_df = pd.DataFrame()
    
    for column, operation in columns.items():
        # Apply filters based on the operation
        if operation.get('filter'):
            filter_type = operation['filter'].get('type')
            filter_value = operation['filter'].get('value')
            filter_value = clean_value(filter_value)
            
            if filter_type == 'equal':
                print(column)
                print(filter_value)
                analyzer.filter_by_column_values(column, filter_value)
            elif filter_type == 'not_equal':
                analyzer.filter_by_column_values_neg(column, filter_value)
            elif filter_type == 'range':
                print(filter_value)
                analyzer.filter_by_column_range(column, filter_value)
            else:
                    return jsonify({'error': f"Unsupported filter type: {filter_type}"}), 400

    filtered_df = analyzer.display()
    tmp_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id, 'tmp')
    os.makedirs(tmp_folder, exist_ok=True)
    csv_path = os.path.join(tmp_folder, 'filtered_data.csv')
    filtered_df.to_csv(csv_path, index=False)
    summarization = summarize_networking_df(filtered_df)
    if inteligent_overview_extension == "enabled":
        documents = preprocess_csv(csv_path)
        inteligent_overview = rag_prompt(api_key=OPENAI_API_KEY, documents=documents,
                                        query="Please analyze provided traffic and check if you are able to spot any anomalies."
        )
        write_to_txt(os.path.join(tmp_folder, f'inteligent_overview_{session_id}.txt'), inteligent_overview)
    
        return jsonify({'success': True, 'message' : f'Data has been filtered successfully! Filter: {filter_object}. \n Data summary: {summarization} \n Intelligent overview: {inteligent_overview}'})
    else:  
        return jsonify({'success': True, 'message' : f'Data has been filtered successfully! Filter: {filter_object}. \n Data summary: {summarization}'})


@app.route('/filtering_summary', methods=['GET'])
def get_filtering_summary():

    session_id = get_or_create_session_id(session)
    tmp_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id, 'tmp')
    csv_path = os.path.join(tmp_folder, 'filtered_data.csv')
    if inteligent_overview_extension == "enabled":
        inteligent_overview_path = os.path.join(tmp_folder, f'inteligent_overview_{session_id}.txt')
        with open(inteligent_overview_path, 'r') as file:
            inteligent_overview = file.read()
    if os.path.exists(csv_path):
        filtered_df = pd.read_csv(csv_path)
    else:
        return jsonify({'success': False, 'message': 'Filtered data not found.'})
    summarization = summarize_networking_df(filtered_df)
    if inteligent_overview_extension == "enabled":
        return render_template('summary.html', filtering_results=summarization, inteligent_overview=inteligent_overview)
    else:
        return render_template('summary.html', filtering_results=summarization)

@app.route('/get_filtered_data', methods=['GET'])
def get_filtered_data():
    report_type = "csv"
    print(report_type)
    session_id = get_or_create_session_id(session)
    tmp_folder = os.path.join(app.config['UPLOAD_FOLDER'], session_id, 'tmp')
    file_path = os.path.join(tmp_folder, 'filtered_data.csv')
    filtered_df = pd.read_csv(file_path)
    print(filtered_df.head())  
    summarization = summarize_networking_df(filtered_df)
    if inteligent_overview_extension == "enabled":
        inteligent_overview_path = os.path.join(tmp_folder, f'inteligent_overview_{session_id}.txt')
        with open(inteligent_overview_path, 'r') as file:
                inteligent_overview = file.read()
        print(inteligent_overview)

    try:
        response_filtered_data = create_response_report(
            content=filtered_df,
            filename=f"filtered_data_{session_id}",
            ext=".csv",
            mimetype="text/csv",
            file_format="csv"
        )

        response_filtered_data_summarization = create_response_report(
            content=str(summarization),
            filename=f"filtered_data_summarization_{session_id}",
            ext=".txt",
            mimetype="text/plain",
            file_format="txt"
        )
        if inteligent_overview_extension == "enabled":
            response_inteligent_summary = create_response_report(
                content=inteligent_overview,
                filename=f"inteligent_summary_{session_id}",
                ext=".txt",
                mimetype="text/plain",
                file_format="txt"
            )
        # Create in-memory ZIP file
            zip_buffer = io.BytesIO()

            # Create a ZIP file in memory
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add both responses as separate files in the ZIP
                zip_file.writestr("filtered_data_report.csv", response_filtered_data.data.decode('utf-8'))
                zip_file.writestr("filtered_data_summarization.csv", response_filtered_data_summarization.data.decode('utf-8'))
                zip_file.writestr("intelligent_summary_report.txt", response_inteligent_summary.data.decode('utf-8'))

            # Seek to the beginning of the in-memory file before sending
            zip_buffer.seek(0)

            # Create the response with the ZIP file
            resp = make_response(zip_buffer.read())
            resp.headers["Content-Disposition"] = "attachment; filename=reports.zip"
            resp.headers["Content-type"] = "application/zip"

            return resp
        else:
            zip_buffer = io.BytesIO()

            # Create a ZIP file in memory
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add both responses as separate files in the ZIP
                zip_file.writestr("filtered_data_report.csv", response_filtered_data.data.decode('utf-8'))
                zip_file.writestr("filtered_data_summarization.csv", response_filtered_data_summarization.data.decode('utf-8'))
                zip_file.writestr("intelligent_summary_report.txt", response_inteligent_summary.data.decode('utf-8'))

            # Seek to the beginning of the in-memory file before sending
            zip_buffer.seek(0)

            # Create the response with the ZIP file
            resp = make_response(zip_buffer.read())
            resp.headers["Content-Disposition"] = "attachment; filename=reports.zip"
            resp.headers["Content-type"] = "application/zip"

            return resp
    except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

    

if __name__ == '__main__':
    app.run(debug=True)
