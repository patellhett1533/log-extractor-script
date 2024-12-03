import re
import csv
from collections import defaultdict


def parse_log_file(log_file):
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    # Regular expression to match log entries
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>[A-Z]+) (?P<endpoint>/\S*) HTTP/\d\.\d".* (?P<status>\d+) \d+')

    # Read the log file line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Extract relevant information from each log entry
            match = log_pattern.search(line)
            if match:
                # extract ip, endpoint and status from log
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))

                # update counts for ip and endpoint access
                ip_request_count[ip] += 1
                endpoint_access_count[endpoint] += 1

                # update count for failed login attempts
                if status == 401:
                    failed_login_attempts[ip] += 1

    return ip_request_count, endpoint_access_count, failed_login_attempts


# Function to find the most accessed endpoint
def find_most_accessed_endpoint(endpoint_access_count):
    # Find the endpoint with the highest access count
    most_accessed_endpoint = max(
        endpoint_access_count, key=endpoint_access_count.get)
    return most_accessed_endpoint, endpoint_access_count[most_accessed_endpoint]


# Function to detect suspicious activity
def detect_suspicious_activity(failed_login_attempts):
    # Filter out IP addresses with failed login attempts
    suspicious_ips = {ip: count for ip,
                      count in failed_login_attempts.items() if count > 0}
    return suspicious_ips


# Function to save results to a CSV file
def save_results_to_csv(ip_request_count, most_accessed_endpoint, endpoint_access_count, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write the results to the CSV file in a readable format
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed_endpoint)

        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    # Parse the log file and store the results in dictionaries
    ip_request_count, endpoint_access_count, failed_login_attempts = parse_log_file(
        log_file)
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_access_count)
    suspicious_ips = detect_suspicious_activity(failed_login_attempts)

    print("\nRequests per IP Address:")
    for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(
        f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save the results to a CSV file
    save_results_to_csv(ip_request_count, most_accessed_endpoint,
                        endpoint_access_count, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")


if __name__ == '__main__':
    main()
