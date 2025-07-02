# threat_logs/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ThreatLog, SQLScanLog, SQLScanStatus
from .serializers import ThreatLogSerializer, SQLScanLogSerializer
from .scanners.sql_injection_runner import run_sql_scan_and_save
import uuid
import threading

class ThreatLogListCreateView(APIView):
    def get(self, request):
        logs = ThreatLog.objects.all().order_by('-timestamp')
        serializer = ThreatLogSerializer(logs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ThreatLogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TriggerSQLScanView(APIView):
    def post(self, request):
        target_url = request.data.get('url')
        if not target_url:
            return Response({"error": "URL required"}, status=400)
        
        # Create scan status
        scan_id = str(uuid.uuid4())
        scan_status = SQLScanStatus.objects.create(
            scan_id=scan_id,
            target_url=target_url,
            status='pending'
        )
        
        # Run scan in background thread
        def run_scan():
            try:
                run_sql_scan_and_save(target_url, scan_status=scan_status)
            except Exception as e:
                scan_status.status = 'failed'
                scan_status.error_message = str(e)
                scan_status.save()
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return Response({
            "message": "SQL Scan started",
            "scan_id": scan_id
        }, status=200)

class SQLScanStatusView(APIView):
    def get(self, request, scan_id):
        try:
            scan_status = SQLScanStatus.objects.get(scan_id=scan_id)
            return Response({
                "scan_id": scan_status.scan_id,
                "target_url": scan_status.target_url,
                "status": scan_status.status,
                "spider_progress": scan_status.spider_progress,
                "scan_progress": scan_status.scan_progress,
                "total_progress": scan_status.total_progress,
                "error_message": scan_status.error_message,
                "created_at": scan_status.created_at,
                "updated_at": scan_status.updated_at
            })
        except SQLScanStatus.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)

class SQLScanLogListView(APIView):
    def get(self, request):
        logs = SQLScanLog.objects.all().order_by('-timestamp')
        serializer = SQLScanLogSerializer(logs, many=True)
        return Response(serializer.data)
