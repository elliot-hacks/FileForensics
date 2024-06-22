from django.contrib.auth.models import AbstractUser
from django.db import models

# Custom User Model
class User(AbstractUser):
    email = models.EmailField(unique=True)

# Model to store uploaded files
class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    analyzed = models.BooleanField(default=False)  # Track if file analysis is done

    def __str__(self):
        return self.file.name


class Malware(models.Model):
    uploaded_file = models.OneToOneField(UploadedFile, on_delete=models.CASCADE, related_name='malware')
    type = models.CharField(max_length=255, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    version = models.CharField(max_length=255, null=True, blank=True)
    author = models.CharField(max_length=255, null=True, blank=True)
    language = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateField(null=True, blank=True)
    architecture = models.CharField(max_length=255, null=True, blank=True)
    platform = models.CharField(max_length=255, null=True, blank=True)
    vip = models.BooleanField(default=False)
    comments = models.TextField(null=True, blank=True)
    tags = models.CharField(max_length=255, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name if self.name else str(self.id)



# For networkCapture
class Packet(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=50)
    destination_ip = models.CharField(max_length=50)
    protocol = models.CharField(max_length=10)
    payload = models.TextField()

class Event(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
