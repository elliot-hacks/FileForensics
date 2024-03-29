import os
import zipfile
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.conf import settings


import magic
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

def analyse(request):
    return render(request, 'index.html')


def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        file_type = magic.from_buffer(uploaded_file.read(1024), mime=True)
        return render(request, 'analyse.html', {'file_type': file_type})
    return render(request, 'malware.html')



# def upload_file(request):
#     if request.method == 'POST':
#         form = UploadFileForm(request.POST, request.FILES)
#         if form.is_valid():
#             uploaded_file = request.FILES['file']
#             file_type = magic.from_buffer(uploaded_file.read(1024), mime=True)
#             # uploaded_file = form.save()
#             # file_path = uploaded_file.file.path
#
#             # # Determine file type using magic numbers
#             # # mime = magic.Magic(mime=True)
#             # file_type = magic.from_file(file_path)
#
#             # # Determine language based on file type
#             language = determine_language(file_type)
#             return render(request, 'analyse.html', {'language': language})
#     else:
#         form = UploadFileForm()
#     return render(request, 'malware.html', {'form': form})


# Determine lang...
def determine_language(file_type):
    # Mapping file types to programming languages
    language_map = {
        'text/x-python': 'Python',
        'text/x-csrc': 'C',
        'text/x-c++src': 'C++',
        'text/x-java': 'Java',
        'text/html': 'HTML',
        'text/css': 'CSS',
        'application/javascript': 'JavaScript',
        'application/x-ruby': 'Ruby',
        'text/x-php': 'PHP',
        # Add more mappings as needed
    }
    return language_map.get(file_type, 'Unknown')
