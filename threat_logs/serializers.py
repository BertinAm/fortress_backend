# threat_logs/serializers.py

from rest_framework import serializers
from .models import ThreatLog, SQLScanLog

class ThreatLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatLog
        fields = '__all__'

class SQLScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SQLScanLog
        fields = '__all__'
