from pcap_handler import pcapHandler
import pandas as pd

def read_pcap(file_path):
    pcap2df = pcapHandler(file=file_path, verbose=True)
    df = pcap2df.to_DF(head=True)
    return df
