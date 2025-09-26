import requests
import csv
import yaml
import os
import uuid
from datetime import date

URLHAUS_API_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OUTPUT_DIR = "rules"

def fetch_recent_iocs():
    """Mengambil Indikator Kompromi (URL) terbaru dari URLhaus API."""
    print("Mengambil IoC terbaru dari URLhaus...")
    iocs = []
    try:
        response = requests.get(URLHAUS_API_URL)
        response.raise_for_status()  

        decoded_content = response.content.decode('utf-8')
        csv_reader = csv.reader(decoded_content.splitlines(), delimiter=',')
        
        for row in csv_reader:
            if row and not row[0].startswith('#'):
                url = row[2]
                iocs.append(url)
        
        print(f"Berhasil mendapatkan {len(iocs)} IoC URL.")
        return iocs
    except requests.exceptions.RequestException as e:
        print(f"Gagal mengambil data dari API: {e}")
        return []

def create_sigma_rule(url_ioc: str):
    """Membuat struktur aturan Sigma dalam format dictionary Python."""
    try:
        domain = url_ioc.split('/')[2]
    except IndexError:
        domain = url_ioc

    rule = {
        'title': f"Koneksi ke URL Berbahaya Dikenal: {domain}",
        'id': str(uuid.uuid4()),
        'status': 'stable',
        'description': f"Aturan ini mendeteksi lalu lintas jaringan ke URL berbahaya yang terdaftar di URLhaus. URL: {url_ioc}",
        'references': [
            f"https://urlhaus.abuse.ch/url/{url_ioc.split('://')[1]}/"
        ],
        'author': 'Threat-Rule-Generator',
        'date': date.today().isoformat(),
        'logsource': {
            'category': 'proxy',
            'product': 'zeek' 
        },
        'detection': {
            'selection': {
                'url.original': url_ioc
            },
            'condition': 'selection'
        },
        'falsepositives': [
            'Sangat jarang terjadi, tetapi bisa jika domain telah bersih dan diambil alih untuk tujuan yang sah.'
        ],
        'level': 'high'
    }
    return rule

def save_rule_to_yaml(rule: dict, url_ioc: str):
    """Menyimpan aturan dalam format YAML ke folder output."""
    sanitized_url = url_ioc.replace('http://', '').replace('https://', '').replace('/', '_').replace('.', '-')
    filename = f"url_{sanitized_url}.yml"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            yaml.dump(rule, f, sort_keys=False, default_flow_style=False)
        print(f"  -> Aturan disimpan di: {filepath}")
    except IOError as e:
        print(f"Gagal menyimpan file aturan: {e}")

def main():
    """Fungsi utama untuk menjalankan seluruh proses."""
    print("Memulai proses pembuatan aturan deteksi otomatis...")
    
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Folder '{OUTPUT_DIR}' dibuat.")

    iocs = fetch_recent_iocs()
    
    if not iocs:
        print("Tidak ada IoC yang diproses. Selesai.")
        return

    print("\n Membuat dan menyimpan aturan Sigma...")
    for ioc in iocs:
        sigma_rule = create_sigma_rule(ioc)
        save_rule_to_yaml(sigma_rule, ioc)
        
    print(f"\n Proses selesai. Total {len(iocs)} aturan baru telah dibuat di folder '{OUTPUT_DIR}'.")

if __name__ == "__main__":
    main()