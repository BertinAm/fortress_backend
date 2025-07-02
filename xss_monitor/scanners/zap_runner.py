# xss_monitor/scanners/zap_runner.py

import time
import requests
from ..models import XSSScanLog, ScanStatus
from utils.logger import log_info, log_error
from threat_logs.models import ThreatLog


ZAP_API = 'http://localhost:8090'
SCAN_TIMEOUT = 300  # seconds (5 minutes)


def run_scan_and_save(target, scan_status=None):
    log_info(f"[+] Starting spider on: {target}")
    try:
        print(f"[+] Starting spider on: {target}")
        spider_url = f"{ZAP_API}/JSON/spider/action/scan/?url={target}&recurse=true"
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
                scan_status.status = 'spider_running'
                scan_status.update_progress()
            if status == '100':
                break
        
        log_info(f"[+] Starting active scan on: {target}")
        print(f"[+] Starting active scan on: {target}")
        scan_url = f"{ZAP_API}/JSON/ascan/action/scan/?url={target}&recurse=true&inScopeOnly=false"
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
                scan_status.status = 'scan_running'
                scan_status.update_progress()
            if progress == '100':
                break

        result_url = f"{ZAP_API}/JSON/core/view/alerts/?baseurl={target}"
        alerts = requests.get(result_url).json().get('alerts')
        log_info(f"[+] Total Alerts Found: {len(alerts)}")
        print(f"[+] Total Alerts Found: {len(alerts)}")

        for alert in alerts:
            print(f"[ALERT] {alert.get('alert')} - {alert.get('risk')}")
            XSSScanLog.objects.create(
                alert=alert.get('alert'),
                risk=alert.get('risk'),
                url=alert.get('url'),
                description=alert.get('description', ''),
                solution=alert.get('solution', '')
            )
            ThreatLog.objects.create(
                type='XSS',
                source_ip='0.0.0.0',
                description=f"{alert.get('alert')} - {alert.get('description', '')} (URL: {alert.get('url')})"
            )
        log_info(f"[+] Total Alerts Found: {len(alerts)}")
        log_info(f"All alerts saved for {target}")
        log_info("[+] Scan results saved successfully.")
        print("[+] Scan results saved successfully.")
        print(f"[DEBUG] Alerts received: {alerts}")

        if scan_status:
            scan_status.status = 'complete'
            scan_status.total_progress = 100
            scan_status.save()

    except Exception as e:
        log_error(f"Error during scan: {str(e)}")
        if scan_status:
            scan_status.status = 'failed'
            scan_status.error_message = str(e)
            scan_status.save()
        raise

