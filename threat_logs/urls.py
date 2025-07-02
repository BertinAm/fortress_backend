# threat_logs/urls.py

from django.urls import path
from .views import ThreatLogListCreateView, TriggerSQLScanView, SQLScanLogListView, SQLScanStatusView

urlpatterns = [
    path('logs/', ThreatLogListCreateView.as_view(), name='threat-log-list-create'),
    path('sql-scan/', TriggerSQLScanView.as_view(), name='sql-scan'),
    path('sql-scan/logs/', SQLScanLogListView.as_view(), name='sql-scan-logs'),
    path('sql-scan/status/<str:scan_id>/', SQLScanStatusView.as_view(), name='sql-scan-status'),
]
