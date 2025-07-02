import uuid
import threading
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import XSSScanLog, ScanStatus, ScannerConfig
from .serializers import XSSScanLogSerializer, ScanStatusSerializer, ScannerConfigSerializer
from .scanners.zap_runner import run_scan_and_save
from utils.logger import log_info, log_error
from django.http import StreamingHttpResponse
import csv
from django.db.models import Count, Q, Max, Min
from django.utils.timezone import now
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated


class ScannerConfigView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        config = ScannerConfig.get_solo()
        serializer = ScannerConfigSerializer(config)
        return Response(serializer.data)

    def put(self, request):
        config = ScannerConfig.get_solo()
        serializer = ScannerConfigSerializer(config, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScannerConfigResetView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        config = ScannerConfig.get_solo()
        config.scan_depth = 2
        config.timeout = 60
        config.exclude_urls = ''
        config.enable_alerts = True
        config.enable_toast = True
        config.enable_email = False
        config.save()
        serializer = ScannerConfigSerializer(config)
        return Response(serializer.data)


class TriggerXSSScanView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        target_url = request.data.get('url')
        if not target_url:
            log_error("Scan request failed: No URL provided")
            return Response({"error": "URL is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan status record
        scan_status = ScanStatus.objects.create(
            scan_id=scan_id,
            target_url=target_url,
            status='pending'
        )
        
        # Run scan in background thread
        def run_scan():
            try:
                scan_status.status = 'spider_running'
                scan_status.save()
                
                # Run the actual scan
                run_scan_and_save(target_url, scan_status)
                
                scan_status.status = 'complete'
                scan_status.total_progress = 100
                scan_status.save()
                
            except Exception as e:
                log_error(f"Scan failed for {target_url}: {str(e)}")
                scan_status.status = 'failed'
                scan_status.error_message = str(e)
                scan_status.save()
        
        # Start scan in background
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        log_info(f"Triggered scan for: {target_url} with ID: {scan_id}")
        return Response({
            "message": "Scan started successfully.",
            "scan_id": scan_id,
            "status": "pending"
        }, status=status.HTTP_202_ACCEPTED)


class ScanStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, scan_id):
        try:
            scan_status = ScanStatus.objects.get(scan_id=scan_id)
            serializer = ScanStatusSerializer(scan_status)
            return Response(serializer.data)
        except ScanStatus.DoesNotExist:
            return Response(
                {"error": "Scan not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )


class XSSScanLogListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # Fetch query parameters
        risk = request.query_params.get('risk')
        url = request.query_params.get('url')

        # Start with all logs
        logs = XSSScanLog.objects.all()

        # Apply filters if specified
        if risk:
            logs = logs.filter(risk__iexact=risk)
        if url:
            logs = logs.filter(url__icontains=url)

        logs = logs.order_by('-timestamp')
        serializer = XSSScanLogSerializer(logs, many=True)
        return Response(serializer.data)


class LogsExportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        export_format = request.query_params.get('format', 'csv').lower()
        logs = XSSScanLog.objects.all().order_by('-timestamp')
        if export_format == 'json':
            serializer = XSSScanLogSerializer(logs, many=True)
            return Response(serializer.data, content_type='application/json')
        elif export_format == 'csv':
            # Prepare CSV streaming response
            def generate():
                header = ['id', 'alert', 'risk', 'url', 'description', 'solution', 'timestamp']
                yield ','.join(header) + '\n'
                for log in logs:
                    row = [
                        str(log.id),
                        '"' + (log.alert or '').replace('"', '""') + '"',
                        '"' + (log.risk or '').replace('"', '""') + '"',
                        '"' + (log.url or '').replace('"', '""') + '"',
                        '"' + (log.description or '').replace('"', '""') + '"',
                        '"' + (log.solution or '').replace('"', '""') + '"',
                        log.timestamp.isoformat() if log.timestamp else ''
                    ]
                    yield ','.join(row) + '\n'
            response = StreamingHttpResponse(generate(), content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="logs.csv"'
            return response
        else:
            return Response({'error': 'Invalid format. Use "csv" or "json".'}, status=400)


class ScanStatsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # Risk counts
        total_scans = ScanStatus.objects.count()
        high_risk_count = XSSScanLog.objects.filter(risk__iexact='high').count()
        medium_risk_count = XSSScanLog.objects.filter(risk__iexact='medium').count()
        low_risk_count = XSSScanLog.objects.filter(risk__iexact='low').count()

        # Risk distribution over time (last 14 days)
        today = now().date()
        days = [today - timedelta(days=i) for i in range(13, -1, -1)]
        risk_counts_over_time = []
        for day in days:
            day_logs = XSSScanLog.objects.filter(timestamp__date=day)
            risk_counts_over_time.append({
                'date': day.isoformat(),
                'high': day_logs.filter(risk__iexact='high').count(),
                'medium': day_logs.filter(risk__iexact='medium').count(),
                'low': day_logs.filter(risk__iexact='low').count(),
            })

        # Top vulnerable URLs (by high risk count)
        top_vulnerable_urls = (
            XSSScanLog.objects.filter(risk__iexact='high')
            .values('url')
            .annotate(high_count=Count('id'))
            .order_by('-high_count')[:5]
        )

        # Scan durations (if available)
        scan_durations = []
        for scan in ScanStatus.objects.filter(status='complete'):
            if scan.created_at and scan.updated_at:
                duration = (scan.updated_at - scan.created_at).total_seconds()
                scan_durations.append({
                    'scan_id': scan.scan_id,
                    'target_url': scan.target_url,
                    'duration_seconds': duration,
                    'started_at': scan.created_at,
                    'ended_at': scan.updated_at,
                })

        return Response({
            'total_scans': total_scans,
            'high_risk_count': high_risk_count,
            'medium_risk_count': medium_risk_count,
            'low_risk_count': low_risk_count,
            'risk_counts_over_time': risk_counts_over_time,
            'top_vulnerable_urls': list(top_vulnerable_urls),
            'scan_durations': scan_durations,
        })
