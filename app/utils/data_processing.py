from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
import pandas as pd
from scapy.all import *
from datetime import datetime


def clean_value(array):
    """
    Transforms string digits in the input array to integers.
    
    Args:
        array (list): The input array containing elements to process.
        
    Returns:
        list: A new array with string digits converted to integers.
    """
    if not isinstance(array, list):
        raise ValueError("Input must be a list.")
    
    return [int(x) if isinstance(x, str) and x.isdigit() else x for x in array]

def summarize_df(df):
    """
    Summarizes the DataFrame by providing basic statistics and information.
    """
    summary = {
        'Number of rows': df.shape[0],
        'Number of columns': df.shape[1],
        'Column names': df.columns.tolist(),
        'Data types': df.dtypes.to_dict(),
        'Missing values': df.isnull().sum().to_dict(),
        'Basic statistics': df.describe(include='all').to_dict()
    }
    return summary


def convert_timestamp_to_human_readable(timestamp):
    """
    Converts a Unix epoch timestamp to a human-readable date and time format.

    Args:
    timestamp (float): The Unix epoch timestamp.

    Returns:
    str: The human-readable date and time.
    """
    # Convert timestamp to datetime object
    dt_object = datetime.fromtimestamp(timestamp)

    # Format datetime object to a human-readable string
    human_readable = dt_object.strftime('%Y-%m-%d %H:%M:%S.%f')

    return human_readable


def summarize_networking_df(df, top_n=5):
    """
    Summarizes the DataFrame by providing statistics and information specific to networking data.
    """
    summary = {
        'Number of packets': df.shape[0],
        'Unique source IP addresses': df['src'].nunique() if 'src' in df.columns else 'N/A',
        'Unique destination IP addresses': df['dst'].nunique() if 'dst' in df.columns else 'N/A',
        'Top source IP addresses': df['src'].value_counts().head(top_n).to_dict() if 'src' in df.columns else 'N/A',
        'Top destination IP addresses': df['dst'].value_counts().head(top_n).to_dict() if 'dst' in df.columns else 'N/A',
        'Top protocols': df['proto'].value_counts().head(top_n).to_dict() if 'proto' in df.columns else 'N/A',
        'Packet size distribution': df['len'].describe().to_dict() if 'len' in df.columns else 'N/A',
        'Time range': {
            'start': convert_timestamp_to_human_readable(float(df['time'].min())) if 'time' in df.columns else 'N/A',
            'end': convert_timestamp_to_human_readable(float(df['time'].max())) if 'time' in df.columns else 'N/A'
        },
        'Potential anomalies': {
            'Large packets': df[df['len'] > df['len'].quantile(0.99)].shape[0] if 'len' in df.columns else 'N/A',
            'High traffic from single IP': df['src'].value_counts().max() if 'src' in df.columns else 'N/A'
        }
        # 'Basic statistics': df.describe(include='all').to_dict()
    }
    return summary

def preprocess_csv(csv_file):

    try:
        df = pd.read_csv(csv_file)
        columns_to_drop = ['payload', 'payload_raw', 'payload_hex']
        df.drop(columns=columns_to_drop, inplace=True)
        # Convert each row into a string by concatenating its column values
        documents = df.apply(lambda row: ", ".join(row.astype(str)), axis=1).tolist()
        return documents
    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return []


def rag_prompt(api_key, documents, query, model_name="gpt-4o", k=5):
    """
    Sets up Retrieval-Augmented Generation (RAG) using LangChain and OpenAI with a list of documents.
    
    Parameters:
        api_key (str): OpenAI API key.
        documents (list): List of strings representing the documents.
        query (str): User's query to retrieve relevant information.
        model_name (str): OpenAI model to use (default: "gpt-3.5-turbo").
        k (int): Number of documents to retrieve (default: 5).
    
    Returns:
        str: The generated response from the RAG pipeline.
    """

    # Step 1: Embed documents
    embeddings = OpenAIEmbeddings()
    vector_store = FAISS.from_texts(documents, embeddings)
    
    # Step 2: Create Retriever
    retriever = vector_store.as_retriever(search_kwargs={"k": k})

    # Step 3: Setup RetrievalQA Chain
    llm = ChatOpenAI(model_name=model_name)
    prompt_template = PromptTemplate(
        input_variables=["context", "question"],
        template="""
        You are a highly knowledgeable assistant. Use the context provided to answer the question accurately. You are an expert in a field of computer forensics in cybersecurity. You will receive pcap traffic data in the format created with provided function:
        df = pd.read_csv(csv_file)
        columns_to_drop = ['payload', 'payload_raw', 'payload_hex']
        df.drop(columns=columns_to_drop, inplace=True)
        # Convert each row into a string by concatenating its column values
        documents = df.apply(lambda row: ", ".join(row.astype(str)), axis=1).tolist()
        return documents
         As you are expert please analyze provided traffic and check if you are able to spot any anomalies. Do not tell general information, only anomalies. only refer to provided data.Create flowing text instead of bullet points.
        Context: {context}
        Question: {question}
        """
    )
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=retriever,
        chain_type_kwargs={"prompt": prompt_template}
    )

    # Step 4: Get response
    response = qa_chain.run(query)
    return response