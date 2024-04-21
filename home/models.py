from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.
class User(AbstractUser):
    email = models.EmailField(unique=True)


class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')

    def __str__(self):
        return self.file.name  # Return the file name as the string representation

class Malware(models.Model):
    location = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    type = models.CharField(max_length=255, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    version = models.CharField(max_length=255, null=True, blank=True)
    author = models.CharField(max_length=255, null=True, blank=True)
    language = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateField(auto_now=True, null=True)
    architecture = models.CharField(max_length=255, null=True, blank=True)
    platform = models.CharField(max_length=255, null=True, blank=True)
    vip = models.BooleanField(default=0)
    comments = models.CharField(max_length=255, null=True, blank=True)
    tags = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "Malwares"

    def __str__(self):
        return self.name if self.name else str(self.id)  # Return the name if available, otherwise return ID


class Signature(models.Model):
    malware = models.ForeignKey(Malware, related_name='signatures', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField()
    file = models.FileField(upload_to='signatures/')

    def __str__(self):
        return self.name


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
