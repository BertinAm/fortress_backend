from rest_framework import serializers
from .models import XSSScanLog, ScanStatus, ScannerConfig

class XSSScanSerializer(serializers.Serializer):
    url = serializers.URLField()

class XSSScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = XSSScanLog
        fields = '__all__'

class ScanStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanStatus
        fields = '__all__'

class ScannerConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScannerConfig
        fields = '__all__'

