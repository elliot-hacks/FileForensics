import os
import re
import magic
import zipfile
import urllib
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from .forms import UploadFileForm,UserRegistrationForm


def index(request):
    return render(request, 'index.html')

def u_register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful.")
            return redirect("login")
        else:
            messages.error(request, "Unsuccessful registration. Invalid information.")
    else:
        form = UserRegistrationForm()
    return render(request=request, template_name="registration/register.html", context={"register_form": form})

def u_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"You are now logged in as {username}.")
                # Update the redirect URL as needed
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request=request, template_name="registration/login.html", context={"login_form": form})


def analyse(request, language_name):
    return render(request, 'analyse.html', {'language_name': language_name})


def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        file = request.FILES['file']
        file_type = magic.from_buffer(file.read(1024), mime=True)
        # Clean special characters from file_type using regex
        cleaned_file_type = re.sub(r'[^\w.-]', '', file_type)
        # Look up language name from language_map dictionary
        language_name = language_map.get(cleaned_file_type, 'Unknown')
        # Print the file name to the console for debugging
        if language_name == 'Unknown':
            print("Unknown file type for file:", file.name)
        
        return redirect(reverse('analyse', kwargs={'language_name': urllib.parse.quote(language_name)}))
    return render(request, 'malware.html')



# import re
# import urllib.parse
# import magic

# # Define a dictionary to map MIME types to language names
language_map = {
    'textplain': 'Palin-text',
    # Progamiing languages
    'textx-script.python': 'Python-Script',
    'textx-c': 'C-Script',
    'textx-ruby': 'Ruby-Script',
    'textx-c++': 'C++_Script',
    'textx-java': 'Java-Code',
    'texthtml': 'HTML-Script',
    'textcss': 'CSS-Script',
    'applicationjavascript': 'JavaScript-Code',
    'applicationx-ruby': 'Ruby-Script',
    'textx-php': 'PHP-Script',
    'textx-shellscript': 'Bash-Scripts',
    # Executables and file systems
    'applicationx-executable': 'ELF-Executable',
    'applicationx-dosexec': 'PE32-Executable',
    'applicationvnd.android.package-archive': 'APK-Executable',
    'applicationvnd.microsoft.portable-executable':  'Windows-PE32-Executable',
    # Applications
    'applicationoctet-stream': 'MP3-File',
    'audiompeg': 'MP3-File',
    'applicationjava-archive': 'Java-Archive',
    'imagepng': 'PNG-Image',
    'imagejpeg': 'JPG-Image',
    'imagegif': 'GIF-Image',
    'videomp4': 'MP4-File',
    'applicationx-xz': 'XZ-Compression',
    'applicationgzip': 'GZIP-Compression'
}
