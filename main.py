import re
import json
import xml.etree.ElementTree as ET
import csv
import hashlib
from urllib.parse import urlparse, urlunparse
import os
from datetime import datetime

def ip_sanitized(input_ip):
    re.search(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',input_ip)  # (example: 1[.]1[.]1[.]1)
    # sanitized.append(re.search(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\|\.\|){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', input_ip)) # (example: 1|.|1|.|1|.|1)
    # return sanitized

class IndicatorParser:
    def __init__(self):
        self.indicators = {
            'url': [],
            'ip': [],
            'hash': [],
            'email': []
        }

    def parse(self, input_text):
        lines = input_text.split('\n')
        for line in lines:
            line = line.strip()
            if self._is_url(line):
                self.indicators['url'].append(self._normalize_url(line))
            elif self._is_ip(line):
                self.indicators['ip'].append(self._normalize_ip(line))
            elif self._is_hash(line):
                self.indicators['hash'].append(self._normalize_hash(line))
            elif self._is_email(line):
                self.indicators['email'].append(self._normalize_email(line))

    def _is_url(self, text):
        url_pattern = re.compile(r'^(https?:\/\/)?(www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        return bool(url_pattern.match(text))

    def _normalize_url(self, url):
        url = url.replace('hxxp', 'http').replace('[.]', '.').replace('|.', '.').replace('(.)', '.')
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url
        parsed = urlparse(url)
        return urlunparse(parsed._replace(netloc=parsed.netloc.lower()))

    def _is_ip(self, text):
        ip_pattern = re.compile(r'^(\d{1,3}[.,|\[\]]\d{1,3}[.,|\[\]]\d{1,3}[.,|\[\]]\d{1,3})$')
        return bool(ip_pattern.match(text))

    def _normalize_ip(self, ip):
        return ip.replace('[.]', '.').replace('|.', '.').replace(',', '.')

    def _is_hash(self, text):
        return len(text) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in text)

    def _normalize_hash(self, hash_value):
        return hash_value.lower()

    def _is_email(self, text):
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_pattern.match(text))

    def _normalize_email(self, email):
        return email.lower()

    def ip_sanitized(self, input_ip):
        re.search(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', input_ip) # (example: 1[.]1[.]1[.]1)
        #sanitized.append(re.search(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\|\.\|){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', input_ip)) # (example: 1|.|1|.|1|.|1)
        #return sanitized

    def search_regex_in_csv(csv_file, regex_pattern):
        results = []
        with open(csv_file, 'r', newline='') as file:
            reader = csv.reader(file)
            for row in reader:
                for cell in row:
                    sanitized = ip_sanitized(cell)
                    results.append(sanitized)
        return results

    def export_string(self):
        result = []
        for indicator_type, indicators in self.indicators.items():
            result.append(f"{indicator_type.upper()}:")
            result.extend(indicators)
            result.append("")
        return "\n".join(result)

    def export_json(self):
        return json.dumps(self.indicators, indent=2)

    def export_xml(self):
        root = ET.Element("indicators")
        for indicator_type, indicators in self.indicators.items():
            type_element = ET.SubElement(root, indicator_type)
            for indicator in indicators:
                ET.SubElement(type_element, "value").text = indicator
        return ET.tostring(root, encoding='unicode', method='xml')

    def export_csv(self, filename):
        current_date = datetime.now().strftime("%d%m%Y")
        filename = f"{current_date}-Normalized_Indicators.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Type', 'Value'])
            for indicator_type, indicators in self.indicators.items():
                for indicator in indicators:
                    writer.writerow([indicator_type, indicator])



# Parse Usage
parser = IndicatorParser()
input_text = """
hxxps://example.com
domain[.]com
1[.]1[.]1[.]1
e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e
user@example.com
"""

parser.parse(input_text)
parser.search_regex_in_csv("IOCs- FC309242855$08092024_13_34_16.csv")

"""
print("String Export:")
print(parser.export_string())

print("\nJSON Export:")
print(parser.export_json())

print("\nXML Export:")
print(parser.export_xml())

parser.export_csv('indicators.csv')
print("\nCSV file 'indicators.csv' has been created.")
"""

