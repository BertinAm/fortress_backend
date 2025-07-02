from zapv2 import ZAPv2
from threat_logs.models import SQLScanLog
import time
import logging
import requests
from utils.logger import log_info, log_error

logger = logging.getLogger(__name__)

ZAP_API = 'http://localhost:8090'
SCAN_TIMEOUT = 300  # seconds (5 minutes)

def run_sql_scan_and_save(url, api_key=None, zap_address='localhost', zap_port=8090, scan_status=None):
    """
    Runs an active SQL injection scan using ZAP and saves results to SQLScanLog.
    Args:
        url (str): Target URL to scan.
        api_key (str, optional): ZAP API key if set.
        zap_address (str): ZAP proxy address.
        zap_port (int): ZAP proxy port.
        scan_status (object, optional): ScanStatus object for progress tracking.
    """
    try:
        log_info(f"[+] Starting SQL injection scan on: {url}")
        print(f"[+] Starting SQL injection scan on: {url}")
        
        if scan_status:
            scan_status.status = 'spider_running'
            scan_status.spider_progress = 0
            scan_status.scan_progress = 0
            scan_status.total_progress = 0
            scan_status.save()

        # Spider scan
        log_info(f"[+] Starting spider on: {url}")
        print(f"[+] Starting spider on: {url}")
        spider_url = f"{ZAP_API}/JSON/spider/action/scan/?url={url}&recurse=true"
        spider_response = requests.get(spider_url)
        spider_scan_id = spider_response.json().get('scan')

        while True:
            time.sleep(3)
            status_url = f"{ZAP_API}/JSON/spider/view/status/?scanId={spider_scan_id}"
            status = requests.get(status_url).json().get('status')
            print(f"[Spider Progress] {status}%")
            log_info(f"[Spider Progress] {status}%")
            if scan_status:
                scan_status.spider_progress = int(status)
                scan_status.total_progress = int(status) // 2  # Spider is 50% of total
                scan_status.save()
            if status == '100':
                break

        # Active scan
        log_info(f"[+] Starting active scan on: {url}")
        print(f"[+] Starting active scan on: {url}")
        if scan_status:
            scan_status.status = 'scan_running'
            scan_status.save()

        scan_url = f"{ZAP_API}/JSON/ascan/action/scan/?url={url}&recurse=true&inScopeOnly=false"
        response = requests.get(scan_url)
        scan_id = response.json().get('scan')

        while True:
            time.sleep(5)
            progress_url = f"{ZAP_API}/JSON/ascan/view/status/?scanId={scan_id}"
            progress = requests.get(progress_url).json().get('status')
            print(f"[Scan Progress] {progress}%")
            log_info(f"[Scan Progress] {progress}%")
            if scan_status:
                scan_status.scan_progress = int(progress)
                scan_status.total_progress = 50 + (int(progress) // 2)  # Active scan is 50% of total
                scan_status.save()
            if progress == '100':
                break

        # Get alerts
        result_url = f"{ZAP_API}/JSON/core/view/alerts/?baseurl={url}"
        alerts = requests.get(result_url).json().get('alerts')
        log_info(f"[+] Total Alerts Found: {len(alerts)}")
        print(f"[+] Total Alerts Found: {len(alerts)}")

        sql_injection_count = 0
        for alert in alerts:
            print(f"[ALERT] {alert.get('alert')} - {alert.get('risk')}")
            if "SQL Injection" in alert.get('alert', ''):
                sql_injection_count += 1
                SQLScanLog.objects.create(
                    url=alert.get('url', url),
                    param=alert.get('param', ''),
                    risk=alert.get('risk', ''),
                    description=alert.get('description', '')
                )
                log_info(f"[SQLi] Found SQL injection: {alert.get('alert')} on {alert.get('url')}")

        log_info(f"[+] SQL Injection alerts found: {sql_injection_count}")
        print(f"[+] SQL Injection alerts found: {sql_injection_count}")
        log_info(f"All SQL injection alerts saved for {url}")
        print("[+] SQL injection scan completed successfully.")

        if scan_status:
            scan_status.status = 'complete'
            scan_status.total_progress = 100
            scan_status.save()

    except Exception as e:
        log_error(f"Error running SQL injection scan: {e}")
        print(f"Error running SQL injection scan: {e}")
        if scan_status:
            scan_status.status = 'failed'
            scan_status.error_message = str(e)
            scan_status.save()
        raise 