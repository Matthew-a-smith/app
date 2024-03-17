from flask import Flask, render_template, request, jsonify
import os
import subprocess
import data_processing_script as dps
import data_processing_script_2 as dps2  # Rename the second import
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_pcap', methods=['POST'])
def process_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    
    output_option = request.form.get('output')  # Get the selected output option
    
    filename = 'model_data.pcap'
    file.save(filename)

    try:
        if output_option == '1':
            csv_file, predictions_file = dps.process_pcap_to_csv(filename)
            top_predictions = dps.get_top_predictions(predictions_file, top_n=10)
            return jsonify({'top_predictions': top_predictions})
        elif output_option == '2':
            csv_file, json_file = dps.process_pcap_to_csv1(filename)
            top_predictions = dps.get_top_predictions1(json_file, top_n=10)
            unique_ip_ports = json.load(open('unique_ip_ports_count.json'))
            return jsonify({'unique_ip_ports': unique_ip_ports})
        
        elif output_option == '3':
            csv_file, predictions_file = dps2.process_pcap_to_csv(filename)
            top_predictions = dps2.get_top_predictions(predictions_file, top_n=10)
            return jsonify({'top_predictions': top_predictions})
        elif output_option == '4':
            csv_file, predictions_file = dps2.process_pcap_to_csv1(filename)
            top_predictions = dps2.get_top_predictions1(predictions_file, top_n=10)
            return jsonify({'top_predictions': top_predictions})
        else:
            return jsonify({'error': 'Invalid output option'})
    except Exception as e:
        os.remove(filename)  # Remove temporary file
        app.logger.error(f"Error processing pcap file: {str(e)}")
        return jsonify({'error': str(e)})
    
if __name__ == '__main__':
    app.run(debug=True, host='192.168.4.133')

