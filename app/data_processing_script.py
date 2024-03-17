import subprocess
import csv
import json
import pandas as pd
import tensorflow as tf
import os
# Load the inference model
ICMP_inference_model = "Models/Inferance/NMAP-inference_model.keras"
loaded_model = tf.keras.models.load_model(ICMP_inference_model)

def run_tshark_command(pcap_file):
    tshark_cmd = [
        "tshark",
        "-r", pcap_file,  # Specify the input pcap file
        "-Y", "tcp",      # Filter for TCP traffic
        "-E", "header=y",  # Add header to output
        "-T", "fields",  # Output fields
        "-E", "separator=,",  # CSV separator
        "-e", "frame.time",  # Add frame time
        "-e", "ip.dst",
        "-e", "ip.src",
        "-e", "tcp.dstport",
        "-e", "tcp.srcport",
        "-e", "tcp.window_size_value",
        "-e", "tcp.flags",
    ]
    # Capture TCP traffic using subprocess
    process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, universal_newlines=True)
    return process

def make_predictions(data):
    input_data = {name: tf.convert_to_tensor(data[name].values.reshape(-1, 1)) for name in data.columns if name not in ['ip.src', 'ip.dst']}
    predictions = loaded_model.predict(input_data)
    return predictions.flatten()

########################
#### First Function ####
########################

def process_pcap_to_csv(pcap_file):
    process = run_tshark_command(pcap_file)

    csv_filename = pcap_file.split('.')[0] + ".csv"
    with open(csv_filename, "w", newline="") as csvfile:
        fieldnames = ["date", "time", "ip.dst", "ip.src", "tcp.dstport", "tcp.srcport", "tcp.window_size_value", "tcp.flags"]  # Define CSV header field names
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write CSV header
        writer.writeheader()

        # Skip the first line containing the field names
        next(process.stdout)
                
        for line in process.stdout:
            fields = line.strip().split(',')
            date_str = fields[0]
            time_str = fields[1]
            row = {"date": fields[0],"time": fields[1], "ip.dst": fields[2], "ip.src": fields[3], "tcp.dstport": fields[4], "tcp.srcport": fields[5], "tcp.window_size_value": fields[6], "tcp.flags": fields[7]}
            writer.writerow(row)
            csvfile.flush()  # Flush the buffer to ensure data is written to the file

    process.terminate()
    print("PCAP to CSV conversion completed.")

    # Load the inference model
    ICMP_inference_model = "Models/Inferance/NMAP-inference_model.keras"
    loaded_model = tf.keras.models.load_model(ICMP_inference_model)

    # Load data from CSV file
    data = pd.read_csv(csv_filename)

    # Make predictions for the entire dataset
    all_predictions = make_predictions(data)

    # Set thresholds for writing to JSON
    write_threshold = 0.95

    # Prepare output data for predictions above threshold
    output_data = []
    for index, prediction in enumerate(all_predictions):
        if prediction > write_threshold:
            output_data.append({"Index": index, "Prediction": prediction * 100, "Details": data.iloc[index].to_dict()})
        
    # Write predictions with additional information to a JSON file
    predictions_filename = pcap_file.split('.')[0] + "_predictions.json"
    with open(predictions_filename, 'w') as f:
        json.dump(output_data, f, indent=4)

    print("Predictions above the threshold have been written to", predictions_filename)

    return csv_filename, predictions_filename

def get_top_predictions(predictions_file, top_n=10):
    with open(predictions_file) as f:
        predictions_data = json.load(f)
    
    top_predictions = predictions_data[:top_n]
    return top_predictions

#########################
#### second function ####
#########################

def process_pcap_to_csv1(pcap_file):
    process = run_tshark_command(pcap_file)

    csv_filename = pcap_file.split('.')[0] + ".csv"
    with open(csv_filename, "w", newline="") as csvfile:
        fieldnames = ["date", "time", "ip.dst", "ip.src", "tcp.dstport", "tcp.srcport", "tcp.window_size_value", "tcp.flags"]  # Define CSV header field names
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write CSV header
        writer.writeheader()

        # Skip the first line containing the field names
        next(process.stdout)
                
        for line in process.stdout:
            fields = line.strip().split(',')
            date_str = fields[0]
            time_str = fields[1]
            row = {"date": fields[0],"time": fields[1], "ip.dst": fields[2], "ip.src": fields[3], "tcp.dstport": fields[4], "tcp.srcport": fields[5], "tcp.window_size_value": fields[6], "tcp.flags": fields[7]}
            writer.writerow(row)
            csvfile.flush()  # Flush the buffer to ensure data is written to the file

    process.terminate()

    print("PCAP to CSV conversion completed.")

    # Load data from CSV file
    data = pd.read_csv(csv_filename)

    # Make predictions for the entire dataset
    all_predictions = make_predictions(data)

    # Set thresholds for printing and writing to JSON
    write_threshold = 0.95

    # Initialize a dictionary to store unique IP addresses and port counts
    unique_ips_ports = {}

    # Gather unique IP addresses and port numbers from predictions
    for index, prediction in enumerate(all_predictions):
        if prediction > write_threshold:
            ip_dst = str(data.at[index, 'ip.dst'])
            tcp_dstport = int(data.at[index, 'tcp.dstport'])
            
            # Add IP address if not present, otherwise increment port count
            if ip_dst not in unique_ips_ports:
                unique_ips_ports[ip_dst] = set()
            unique_ips_ports[ip_dst].add(tcp_dstport)

    # Convert dictionary to list of dictionaries
    result = [{"ip": ip, "ports_scanned": len(ports)} for ip, ports in unique_ips_ports.items()]

    # Write the result to a new JSON file
    with open('unique_ip_ports_count.json', 'w') as f:
        json.dump(result, f, indent=4)

    print("Unique IP addresses and number of ports scanned JSON file created successfully.")

    return csv_filename, 'unique_ip_ports_count.json'

def get_top_predictions1(predictions_file, top_n=10):
    with open(predictions_file) as f:
        predictions_data = json.load(f)
    
    return predictions_data[:top_n]  # Return the top N predictions

# For testing purposes
if __name__ == "__main__":
    pcap_file = "example.pcap"  # Replace with your actual PCAP file
    csv_file, json_file = process_pcap_to_csv(pcap_file)
    print("CSV file:", csv_file)
    print("JSON file:", json_file)
