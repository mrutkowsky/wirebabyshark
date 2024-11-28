from pcap_handler import pcapHandler
import pandas as pd

from scapy.all import *
import pandas as pd
from pcap_handler import pcapHandler
from progressbar import ProgressBar
import binascii # Binary to Ascii 

def read_pcap(file_path):
    p = scapy.utils.rdpcap(file_path)
    return p


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