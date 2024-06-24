from django.contrib import admin
from .import models


@admin.register(models.Malware)
class MalwareSampleAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'type', 'version', 'author', 'language', 'date', 'architecture', 'platform', 'vip', 'comments', 'tags']
    list_per_page = 20


@admin.register(models.UploadedFile)
class UploadedFileSampleAdmin(admin.ModelAdmin):
    list_display = ['file', 'uploaded_at', 'uploaded_by', 'analyzed']
    list_select_related = ['uploaded_by']
    # autocomplete_fields = ['uploaded_by']
    list_per_page = 20

# @admin.register(models.Professionnals)
# class ProffesionalsAdmin(admin.ModelAdmin):
#     list_display = ['user', 'email', 'photograph', 'biography']


# @admin.register(models.Contact)
# class ContactAdmin(admin.ModelAdmin):
#     list_display = ['professionnals', 'phone_number', 'linkdeln', 'twitter', 'youtube', 'website']

# @admin.register(models.Services)
# class ServicesAdmin(admin.ModelAdmin):
#     list_display = ['name', 'description', 'professionnals']

# @admin.register(models.Customer)
# class CustomerAdmin(admin.ModelAdmin):
#     list_display = ['user', 'phone', 'birth_date', 'services', 'request_time']
