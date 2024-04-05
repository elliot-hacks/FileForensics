print("Some backup functions for views.py")
"""
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from django.contrib.auth.decorators import login_required
# from .forms import UserRegistrationForm, MalwareSampleUploadForm
from django.contrib.auth import login, authenticate
from django.contrib import messages
# import r2pipe
import yara
import hashlib
import subprocess
from .models import Malware
import os
from pathlib import Path


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



# Import any other necessary modules or tools here
def upload_sample(request):
    if request.method == 'POST':
        form = MalwareSampleUploadForm(request.POST, request.FILES)
        if form.is_valid():
            # Save the form without committing to get access to the object before saving
            sample = form.save(commit=False)
            sample.uploaded_by = request.user  # Set the user who uploaded the sample
            sample.save()

            # Call the analysis function
            is_malware, malware_type, apt_detected, comments = analyze_malware_sample(sample)
            
            if is_malware:
                # If malware signature exists
                return render(request, 'malware_analysis/malware_detected.html', {'malware_type': malware_type, 'apt_detected': apt_detected})
            else:
                # If no matching malware signature exists
                return render(request, 'malware_analysis/no_malware_detected.html')
    else:
        form = MalwareSampleUploadForm()
    
    return render(request, 'malware_analysis/upload_sample.html', {'form': form})


@login_required(login_url='login')
def analyze_malware_sample(sample):
    file_path = sample.file.path

    r2 = r2pipe.open(file_path)
    disassembly = r2.cmd('pd @entry0')  # Adjust the address as needed
    r2.quit()

    md5_hash = hashlib.md5(disassembly.encode()).hexdigest()


    pedump_results = run_pedump(file_path)
    pescan_results = run_pescan(file_path)
    yara_results = run_yara(file_path)

    # Store the analysis results in the database
    sample.pescan_results = pescan_results
    sample.pedump_results = pedump_results
    sample.yara_results = yara_results
    sample.md5_hash = md5_hash
    sample.save()

    # Check for malware signature and APT indicators in the disassembly
    is_malware, malware_type, apt_detected = check_for_malware_signature(disassembly)

    # You can store APT indicators, malware type, and comments in the database
    sample.is_malware = is_malware
    sample.malware_type = malware_type
    sample.apt_detected = apt_detected
    sample.save()

    # Retrieve user comments for similar file signatures
    comments = get_user_comments_for_matching_signature(md5_hash)

    return is_malware, malware_type, apt_detected, comments


def run_pedump(file_path):
    try:
        # Execute pedump and capture its output
        pedump_command = ['pedump', file_path]
        pedump_output = subprocess.check_output(pedump_command, universal_newlines=True)
        return pedump_output
    except subprocess.CalledProcessError as e:
        # Handle any errors or exceptions, if necessary
        print(f"Error running pedump: {e}")
        return ""

def run_pescan(file_path):
    try:
        # Execute pescan and capture its output
        pescan_command = ['pescan', file_path]
        pescan_output = subprocess.check_output(pescan_command, universal_newlines=True)
        return pescan_output
    except subprocess.CalledProcessError as e:
        # Handle any errors or exceptions, if necessary
        print(f"Error running pescan: {e}")
        return ""


def run_yara(sample_path, rule_folder):
    BASE_DIR = Path(__file__).resolve().parent.parent
    rule_folder = os.path.join(BASE_DIR, 'YARA')  # BASE_DIR is defined in settings.py
    try:
        # Load YARA rules from all files in the rule folder
        compiled_rules = yara.compile(filepaths=[os.path.join(rule_folder, rule_file) for rule_file in os.listdir(rule_folder)])

        # Scan the sample with the loaded rules
        matches = compiled_rules.match(filepath=sample_path)

        # Extract matching rule names or other relevant information from 'matches'
        matched_rules = [match.rule for match in matches]

        return matched_rules
    except yara.Error as e:
        print(f"YARA error: {e}")
        return ""


def check_for_malware_signature(pescan_output, pedump_output):
    # Implement logic to check for malware signatures and APT indicators
    # You can use regular expressions or specific keywords in the analysis results
    # Example:
    is_malware = "Malware Signature" in pescan_output or "APT Indicator" in pedump_output
    malware_type = "Trojan" if "Trojan" in pescan_output else "Unknown"
    apt_detected = "APT" in pescan_output
    return is_malware, malware_type, apt_detected


def get_user_comments_for_matching_signature(signature):
    matching_samples = MalwareSample.objects.filter(md5_hash=signature).exclude(comments__isnull=True).order_by('-date_of_submission')
    comments = [(sample.date_of_submission, sample.comments) for sample in matching_samples]
    return comments


def generate_pdf_report(request, sample_id):
    sample = MalwareSample.objects.get(id=sample_id)
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="malware_report_{sample_id}.pdf"'

    # Create a PDF document using ReportLab
    p = canvas.Canvas(response, pagesize=letter)
    p.drawString(100, 750, f"Malware Analysis Report - Sample ID: {sample_id}")
    # Add more content to the PDF as needed

    p.showPage()
    p.save()

    return response





# ZIpping and unzipping during upload/download
def upload_file(request):
    if request.method == 'POST':
        uploaded_file = request.FILES['file']
        file_path = f'media/uploads/{uploaded_file.name}'  # Adjust the path as needed

        with open(file_path, 'wb') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        detector = MalwareDetector(settings.YARA_RULE_FILE)
        is_infected = detector.scan_file(file_path)

        response_data = {
            'file_name': uploaded_file.name,
            'is_infected': is_infected,
        }

        if is_infected:
            zip_path = f'media/uploads/{uploaded_file.name}.zip'
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.write(file_path, os.path.basename(file_path))

            # Clean up the original file after zipping
            os.remove(file_path)

            response_data['zip_path'] = zip_path

        return JsonResponse(response_data)

    return render(request, 'upload_file.html')

"""