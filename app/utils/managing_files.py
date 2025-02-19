import pandas as pd
import io
from scapy.all import *
import random
import string
import pandas as pd
from pcap_handler import pcapHandler
from progressbar import ProgressBar
import binascii # Binary to Ascii 
from flask import make_response

def extract(pcap_file):
    pbar = ProgressBar()
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex']

    df = pd.DataFrame(columns=dataframe_fields)
    for packet in pbar(pcap_file[IP]):
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])
        
        field_values.append(packet.time)
        
        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)
        
        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)
        df = df.reset_index()
        # Drop old index column
        df = df.drop(columns="index")
    return df

def read_pcap(file_path):
    p = scapy.utils.rdpcap(file_path)
    return p


def generate_session_id():
    """
    Generates an 8-digit numeric folder name.
    """
    return ''.join(random.choices(string.digits, k=8))

def get_or_create_session_id(session):
    if 'session_id' not in session:
        session['session_id'] = generate_session_id()
    return session['session_id']

def combine_pcap_files(upload_folder, session_id):
    print(upload_folder)
    print(session_id)
    session_files_folder = os.path.join(upload_folder, session_id)
    print(session_files_folder)
    combined_data = pd.DataFrame()

    for filename in os.listdir(session_files_folder):
        print(filename)
        file_path = os.path.join(session_files_folder, filename)
        if os.path.isfile(file_path):
            print(file_path)
            data = read_pcap(file_path)
            data_extracted = extract(data)
            print(data_extracted)
            combined_data = pd.concat([combined_data, data_extracted], ignore_index=True)
            print(combined_data)
    print(combined_data) 
    return combined_data


def create_response_report(
        content,
        filename: str,
        ext: str,
        mimetype: str,
        file_format: str = 'csv'):
    
    CSV_EXT, EXCEL_EXT, HTML_EXT, TXT_EXT = 'csv', 'excel', 'html', 'txt'
    
    buffer = io.BytesIO() if file_format in (CSV_EXT, EXCEL_EXT) else io.StringIO()

    if file_format == CSV_EXT:

        print("save to csv")

        content.to_csv(buffer, index=False)

    elif file_format == TXT_EXT:
        print("Saving as TXT...")
        buffer.write(content) 

    else:
        return None
    
    resp = make_response(buffer.getvalue())
    resp.headers["Content-Disposition"] = \
        f"attachment; filename={filename}.{ext}"
    resp.headers["Content-type"] = mimetype

    return resp


def write_to_txt(file_name, variable, append=False):
    """
    Writes the value of a variable to a .txt file.

    Parameters:
        file_name (str): The name of the .txt file to write to.
        variable (any): The variable whose value should be written.
        append (bool): Whether to append to the file (default: False, which overwrites the file).

    Returns:
        None
    """
    try:
        mode = 'a' if append else 'w'  # Append or overwrite mode
        with open(file_name, mode) as file:
            # Convert variable to string and write it
            file.write(str(variable) + '\n')
        print(f"Variable written to {file_name} successfully.")
    except Exception as e:
        print(f"Error writing to file: {e}")