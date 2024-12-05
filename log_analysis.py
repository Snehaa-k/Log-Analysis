import re
import csv
from collections import Counter


LOG_FILE = "sample.log"


def read_log_file(file_path):
    
    """
    Reads the content of a log file and handles file-related errors.

    This function attempts to read the contents of a log file located at the 
    provided file path. If the file is not found, it gracefully handles the 
    error using a try-except block and returns an empty list.

    Parameters:
    - file_path (str): The path to the log file to be read.

    Returns:
    list of str: A list of lines from the log file if successfully read, 
    or an empty list if the file is not found.

    """

    
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print("Error: Log file not found!")
        return []


def extract_ip_requests(log_lines):
   
    """
    Extracts and counts IP addresses from log lines.

    This function scans each line in the provided log data to extract IP addresses
    at the start of the line. It counts the number of requests made by each IP 
    address, enabling the identification of high-traffic sources, detection of 
    potentially suspicious activity, and optimization of server resources.

    Parameters:
    - log_lines (list of str): A list of log file lines containing IP and request data.

    Returns:
    Counter: A Counter object where keys are IP addresses and values are the count 
            of requests made by each IP.
    """

    
    ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"  
    ip_counter = Counter()
    for line in log_lines:
        match = re.match(ip_pattern, line)
        if match:
            ip_counter[match.group(1)] += 1
    return ip_counter


def extract_endpoints(log_lines):
    
    """
    Extracts and counts API endpoints accessed from log lines.

    This function identifies API endpoints accessed in a log file by searching for HTTP methods 
    (GET, POST, PUT, DELETE) and their corresponding paths. It counts the number of times each 
    endpoint is accessed, which can help determine API usage trends, optimize performance, 
    and monitor for unusual activity.

    Parameters:
    - log_lines (list of str): Lines from a log file containing HTTP request information.

    Returns:
    Counter: A Counter object where keys are endpoint paths and values are their respective 
            access counts.
    """

    
    endpoint_pattern = r"\"(?:GET|POST|PUT|DELETE) ([^\s]+)"
    endpoint_counter = Counter()
    for line in log_lines:
        match = re.search(endpoint_pattern, line)
        if match:
            endpoint_counter[match.group(1)] += 1
    return endpoint_counter


def detect_suspicious_activity(log_lines, threshold=5):
   
    """
    Detects suspicious IP addresses based on failed login attempts in log data.

    This function analyzes log lines to identify IP addresses with failed login attempts 
    (extracted using HTTP status code 401) that exceed a specified threshold.

    Parameters:
    - log_lines (list of str): Lines from a log file containing access information.
    - threshold (int): The minimum number of failed login attempts to consider an IP suspicious. Default is 3.

    Returns:
    dict: A dictionary where keys are suspicious IP addresses and values are their corresponding 
        counts of failed login attempts exceeding the threshold.
    """

    
    ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"
    failed_login_pattern = r"401"
    failed_attempts = Counter()

    for line in log_lines:
        if re.search(failed_login_pattern, line):
            match = re.match(ip_pattern, line)
            if match:
                failed_attempts[match.group(1)] += 1

    
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}


def display_results(ip_counter, endpoint_counter, suspicious_activity):

    """
    Displays analysis results from log data.

    This function outputs:
    1. A list of IP addresses and their request counts in descending order.
    2. The most frequently accessed endpoint along with its access count.
    3. Suspicious activity, showing IPs with failed login attempts exceeding a threshold.

    Parameters:
    - ip_counter (Counter): A Counter object containing IP addresses and their request counts.
    - endpoint_counter (Counter): A Counter object containing API endpoints and their access counts.
    - suspicious_activity (dict): A dictionary of IPs and their failed login attempt counts.

    Returns:
    None. Outputs are printed to the console for review.
    """

    print("\nRequests per IP Address (Descending):")
    print(f"{'IP Address':<20}{'Request Count':<10}")
    
    for ip, count in ip_counter.most_common():
        
        print(f"{ip:<20}{count:<10}")

    print("\nMost Frequently Accessed Endpoint:")
    if endpoint_counter:
        most_accessed = endpoint_counter.most_common(1)[0]
        print(f"Endpoint: {most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoints were accessed in the log file.")

    print("\nSuspicious Activity (Failed Login Attempts Exceeding Threshold):")
    if suspicious_activity:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<10}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count:<10}")
    else:
        print("No suspicious activity detected.")


def save_to_csv(ip_counter, endpoint_counter, suspicious_activity, output_file):

    """
    Saves IP traffic, endpoint accesses, and suspicious activity analysis to a CSV file.

    Args:
        ip_counter (Counter): A Counter object with IP addresses and their request counts.
        endpoint_counter (Counter): A Counter object with API endpoints and their access counts.
        suspicious_activity (dict): A dictionary with IP addresses and their failed login attempt counts.
        output_file (str): The file path or name where the data should be saved.

    This function writes the following sections to the specified CSV file:
        - IP addresses and their respective request counts.
        - API endpoints and their access counts.
        - Suspicious IP addresses with failed login attempts exceeding a specified threshold.

    The resulting CSV file is formatted for easy review and analysis.

    """
    
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counter.most_common():
            csv_writer.writerow([ip, count])

        csv_writer.writerow([])  

        csv_writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counter.most_common():
            csv_writer.writerow([endpoint, count])

        csv_writer.writerow([])  
        csv_writer.writerow(["Suspicious IP", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            csv_writer.writerow([ip, count])


def main():

    """
    The main function that orchestrates the entire log analysis process.

    1. Reads the log file specified by `LOG_FILE`.
    2. Checks if the log file is empty or contains invalid data.
    3. Analyzes the log data to:
        - Count requests per IP address.
        - Count accesses per API endpoint.
        - Detect suspicious activity, such as multiple failed login attempts.
    4. Displays the results of the analysis in a human-readable format.
    5. Saves the analysis results to a CSV file (`log_analysis_results.csv`) for further review.

    It uses helper functions to perform tasks such as extracting IP requests, counting endpoint accesses,
    detecting suspicious activity, displaying results, and saving to a CSV file.

    Note:
        The `LOG_FILE` variable should point to a valid log file for analysis.
    """

    log_lines = read_log_file(LOG_FILE)

    
    if not log_lines:
        print("Log file is empty or contains no valid data.")
        return

    
    ip_counter = extract_ip_requests(log_lines)
    endpoint_counter = extract_endpoints(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)

    
    display_results(ip_counter, endpoint_counter, suspicious_activity) 
    save_to_csv(ip_counter, endpoint_counter, suspicious_activity, "log_analysis_results.csv")


if __name__ == "__main__":
    main()
