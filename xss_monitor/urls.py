from django.urls import path
from .views import TriggerXSSScanView, XSSScanLogListView, ScannerConfigView, ScanStatusView, ScannerConfigResetView, LogsExportView, ScanStatsView

urlpatterns = [
    path('scan/', TriggerXSSScanView.as_view(), name='trigger-xss-scan'),
    path('logs/', XSSScanLogListView.as_view(), name='xss-scan-logs'),
    path('logs/export/', LogsExportView.as_view(), name='logs-export'),
    path('scanner-config/', ScannerConfigView.as_view(), name='scanner-config'),
    path('scanner-config/reset/', ScannerConfigResetView.as_view(), name='scanner-config-reset'),
    path('scan-status/<str:scan_id>/', ScanStatusView.as_view(), name='scan-status'),
    path('stats/', ScanStatsView.as_view(), name='scan-stats'),
]
