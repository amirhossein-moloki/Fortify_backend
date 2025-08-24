from django.db import models
from django.conf import settings
from django.utils import timezone

class Call(models.Model):
    STATUS_CHOICES = [
        ('initiating', 'Initiating'),
        ('ringing', 'Ringing'),
        ('active', 'Active'),
        ('ended', 'Ended'),
        ('rejected', 'Rejected'),
        ('missed', 'Missed'),
        ('cancelled', 'Cancelled'),
    ]

    caller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='outgoing_calls')
    callee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='incoming_calls')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='initiating')

    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)

    def end_call(self):
        if self.status in ['ringing', 'active']:
            self.status = 'ended'
            self.end_time = timezone.now()
            self.duration = self.end_time - self.start_time
            self.save()

    def reject_call(self):
        if self.status == 'ringing':
            self.status = 'rejected'
            self.end_time = timezone.now()
            self.save()

    def miss_call(self):
        if self.status == 'ringing':
            self.status = 'missed'
            self.end_time = timezone.now()
            self.save()

    def cancel_call(self):
        if self.status in ['initiating', 'ringing']:
            self.status = 'cancelled'
            self.end_time = timezone.now()
            self.save()

    def answer_call(self):
        if self.status == 'ringing':
            self.status = 'active'
            self.save()

    def __str__(self):
        return f"Call from {self.caller} to {self.callee} at {self.start_time} ({self.status})"

    class Meta:
        ordering = ['-start_time']
