from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.
class User(AbstractUser):
  email = models.EmailField(unique=True)


class Malware(models.Model):
    # source = models.ForeignKey(Customer, on_delete=models.PROTECT)
    location = models.FileField(upload_to='uploads/')  # A name or description of the sample
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

    def __str__(self) -> str:
        return self.name


class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
