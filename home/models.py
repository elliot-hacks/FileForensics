from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.
class User(AbstractUser):
  email = models.EmailField(unique=True)


class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')


class Malware(models.Model):
    # source = models.ForeignKey(Customer, on_delete=models.PROTECT)
    location = models.FileField(upload_to='uploads/')  # A name or description of the sample
    type = models.ForeignKey(UploadedFile, on_delete=models.PROTECT)
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

    def __str__(self) -> str:
        return self.name


class MalwareAnalysis(models.Model):
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)
    malware_sample = models.ForeignKey(Malware, on_delete=models.CASCADE)
    analysis_file = models.FileField(upload_to='uploads/')
    md5_checksum = models.CharField(max_length=100)
    sha256_checksum = models.CharField(max_length=100, null=True, blank=True)
    upload_time = models.DateTimeField(auto_now_add=True)
    analysis_time = models.DateTimeField(null=True, blank=True)
    # Additional analysis details can be added here
    # Add PDFs and links to other sites

    def __str__(self):
        return f"{self.malware_sample} - {self.upload_time}"
