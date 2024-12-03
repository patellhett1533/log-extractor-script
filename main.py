import re
import csv
from collections import defaultdict


def parse_log_file(log_file):
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>[A-Z]+) (?P<endpoint>/\S*) HTTP/\d\.\d".* (?P<status>\d+) \d+')

    with open(log_file, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))

                ip_request_count[ip] += 1
                endpoint_access_count[endpoint] += 1

                if status == 401:
                    failed_login_attempts[ip] += 1

    return ip_request_count, endpoint_access_count, failed_login_attempts


def find_most_accessed_endpoint(endpoint_access_count):
    most_accessed_endpoint = max(
        endpoint_access_count, key=endpoint_access_count.get)
    return most_accessed_endpoint, endpoint_access_count[most_accessed_endpoint]


def detect_suspicious_activity(failed_login_attempts):
    suspicious_ips = {ip: count for ip,
                      count in failed_login_attempts.items() if count > 0}
    return suspicious_ips


def save_results_to_csv(ip_request_count, most_accessed_endpoint, endpoint_access_count, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
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

    save_results_to_csv(ip_request_count, most_accessed_endpoint,
                        endpoint_access_count, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")


if __name__ == '__main__':
    main()
