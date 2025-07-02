from django.db import models

# Create your models here.
class ThreatLog(models.Model):
    THREAT_TYPES = [
        ('XSS', 'Cross Site Scripting'),
        ('BruteForce', 'Brute Force Attack'),
        ('Other', 'Other')
    ]

    type = models.CharField(max_length=50, choices=THREAT_TYPES)
    source_ip = models.GenericIPAddressField()
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.type} from {self.source_ip} at {self.timestamp}"

class SQLScanLog(models.Model):
    url = models.URLField()
    param = models.CharField(max_length=255)
    risk = models.CharField(max_length=50)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.param} - {self.risk}"

class SQLScanStatus(models.Model):
    scan_id = models.CharField(max_length=100, unique=True)
    target_url = models.URLField()
    status = models.CharField(max_length=20, default='pending')  # pending, spider_running, scan_running, complete, failed
    spider_progress = models.IntegerField(default=0)
    scan_progress = models.IntegerField(default=0)
    total_progress = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def update_progress(self):
        self.total_progress = (self.spider_progress + self.scan_progress) // 2
        self.save()

    def __str__(self):
        return f"SQL Scan {self.scan_id} - {self.target_url} - {self.status}"
