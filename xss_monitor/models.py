from django.db import models
from django.utils import timezone

class XSSScanLog(models.Model):
    alert = models.CharField(max_length=255)
    risk = models.CharField(max_length=50)
    url = models.URLField()
    description = models.TextField(blank=True)
    solution = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.alert} - {self.risk}"


class ScanStatus(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('spider_running', 'Spider Running'),
        ('spider_complete', 'Spider Complete'),
        ('scan_running', 'Scan Running'),
        ('complete', 'Complete'),
        ('failed', 'Failed'),
    ]
    
    scan_id = models.CharField(max_length=100, unique=True)
    target_url = models.URLField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    spider_progress = models.IntegerField(default=0)
    scan_progress = models.IntegerField(default=0)
    total_progress = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    error_message = models.TextField(blank=True)
    
    def __str__(self):
        return f"Scan {self.scan_id} - {self.target_url}"
    
    def update_progress(self):
        """Calculate total progress based on spider and scan progress"""
        # Spider is 30% of total, scan is 70%
        self.total_progress = int((self.spider_progress * 0.3) + (self.scan_progress * 0.7))
        self.save()


class ScannerConfig(models.Model):
    scan_depth = models.IntegerField(default=2)
    timeout = models.IntegerField(default=60, help_text="Scan timeout in seconds")
    exclude_urls = models.TextField(blank=True, help_text="Comma-separated URLs to exclude")
    enable_alerts = models.BooleanField(default=True)
    enable_toast = models.BooleanField(default=True)
    enable_email = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "Scanner Config"

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
