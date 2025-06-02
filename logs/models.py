# logs/models.py
from django.db import models


class LogEntry(models.Model):
    timestamp = models.DateTimeField()
    source = models.CharField(max_length=100)  # e.g., "auth", "application", "system"
    user = models.CharField(max_length=100, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    action = models.CharField(max_length=200)  # e.g., "login", "file_access"
    status = models.CharField(max_length=50)  # e.g., "success", "failed"
    details = models.JSONField(default=dict)  # Additional context

    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['action']),
        ]