import os
import re
import yara
import json
import magic
import socket
import urllib
import logging
import zipfile
import subprocess
from base64 import *
from PIL import Image
from io import BytesIO
from pathlib import Path
from scapy.layers.l2 import ARP
from scapy.all import sniff, get_if_list
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from threading import Thread
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.shortcuts import get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from .models import Malware, Packet,UploadedFile
from .forms import UserRegistrationForm, ImageUploadForm, UploadFileForm, MalwareForm
    

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


# Network Capture
def select_interface(request):
    interfaces = get_if_list()
    return render(request, 'idsapp/select_interface.html', {'interfaces': interfaces})


from scapy.utils import wrpcap

def capture_packets(request):
    if request.method == 'POST':
        interface = request.POST.get('interface')
        filename = f'{interface}_capture.pcap'

        def process_packet(packet):
            if ARP in packet:
                sender_ip = packet[ARP].psrc
                sender_mac = packet[ARP].hwsrc.upper()
                
                try:
                    sender_host = socket.gethostbyaddr(sender_ip)[0]
                except socket.herror:
                    sender_host = 'Unknown'
                
                # Store the device information in the Packet model
                Packet.objects.create(
                    timestamp=packet.time,
                    source_ip=sender_ip,
                    destination_ip=packet[ARP].pdst,
                    protocol='ARP',
                    payload=str(packet),
                    hostname=sender_host
                )

                print(f"Device found: {sender_host} ({sender_ip}) - {sender_mac}")

        # Start capturing packets in a separate thread
        t = Thread(target=sniff, kwargs={'iface': interface, 'prn': process_packet, 'store': False})
        t.start()

        # Keep the thread running until the request is completed
        t.join()

        # Save captured packets to a pcap file
        # Replace [] with the list of captured packets if you want to save them
        wrpcap(filename, [])
        
        return HttpResponse(f'Capturing packets on {interface} and saving to {filename}')



def network_capture(request):
    if request.method == 'POST':
        interface = request.POST.get('interface')
        # Start packet capturing in a separate thread
        t = Thread(target=capture_packets, args=(interface,))
        t.start()
        return render(request, 'idsapp/home.html', {'message': 'IDS activated'})
    
    return render(request, 'idsapp/home.html')


def process_packet(packet):
    if ARP in packet:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc.upper()
        
        try:
            sender_host = socket.gethostbyaddr(sender_ip)[0]
        except socket.herror:
            sender_host = 'Unknown'

        # Save the packet to the database
        Packet.objects.create(
            source_ip=sender_ip,
            protocol='ARP',
            payload=str(packet),
        )
        
        print(f"Device found: {sender_host} ({sender_ip}) - {sender_mac}")


channel_layer = get_channel_layer()

def send_notification(message):
    async_to_sync(channel_layer.group_send)(
        'notifications_group',
        {
            'type': 'send_notification',
            'message': message
        }
    )

async def connect(self):
    await self.channel_layer.group_add(
        'notifications_group',
        self.channel_name
    )
    await self.accept()

async def disconnect(self, close_code):
    await self.channel_layer.group_discard(
        'notifications_group',
        self.channel_name
    )

async def send_notification(self, event):
    message = event['message']
    await self.send(text_data=json.dumps({'message': message}))

async def update_devices_list(self, message):
    devices = message['devices']
    await self.send(text_data=json.dumps({'type': 'update_devices_list', 'devices': devices}))

@login_required
def validate_root_password(request):
    if request.method == 'POST':
        root_password = request.POST.get('password')
        
        try:
            # Use 'sudo' to check if the password is correct
            subprocess.run(['sudo', '-k', '-S', 'whoami'], input=root_password.encode(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # If the command succeeds, perform the root operation
            # Perform your root operation here...
            
            return JsonResponse({'valid': True})
        
        except subprocess.CalledProcessError:
            return JsonResponse({'valid': False})


# Image manipulation
def get_plane_image(img, channel, index=0):
    if channel in img.mode:
        channel_index = img.mode.index(channel)
        new_image = img.copy()

        for x in range(new_image.size[0]):
            for y in range(new_image.size[1]):
                color = new_image.getpixel((x, y))
                channel_value = color[channel_index]
                plane = bin(channel_value)[2:].zfill(8)

                try:
                    new_color = list(color)
                    new_color[channel_index] = 255 * int(plane[abs(index-7)])
                    new_image.putpixel((x, y), tuple(new_color))
                except IndexError:
                    pass

        image_stream = BytesIO()
        new_image.save(image_stream, format='PNG')
        image_stream.seek(0)
        
        return image_stream.getvalue()

def image_steg(request):
    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image_file = request.FILES['image']
            colors = ['R', 'G', 'B']
            images = []

            try:
                img = Image.open(image_file)
                if img.format in ['JPEG', 'PNG']:
                    for channel in colors:
                        for plane in range(8):
                            image_data = get_plane_image(img, channel, plane)
                            image_base64 = b64encode(image_data).decode('utf-8')
                            images.append(f"data:image/png;base64,{image_base64}")

                    return render(request, 
                                  'image_viewer/display_alpha_planes.html',
                                  {'images': images, 
                                   'colors': colors})
                else:
                    error_msg = "Unsupported image format. Please upload a JPEG or PNG image."
            except IOError:
                error_msg = "Invalid image file."
        else:
            error_msg = "Please upload an image file."
        return render(request, 'image_viewer/upload_image.html', {'form': form, 'error_msg': error_msg})
    else:
        form = ImageUploadForm()
        return render(request, 'image_viewer/upload_image.html', {'form': form})


# Malware Files
logger = logging.getLogger(__name__)
language_map = {
    'textplain': 'Plain-text',
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
    'applicationpdf': 'PDF-File',
    'applicationzip': 'ZIP-Compression',
    'applicationx-xz': 'XZ-Compression',
    'applicationgzip': 'GZIP-Compression',
    # Other extensions to research
    # pcap,pcapng,other zip-compressions,  
}

def analyse(request, language_name, signatures):
    return render(request, 'submit_report.html', {'language_name': language_name, 'signatures': signatures})


def detect_file_type(file):
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)  # Reset the file pointer after reading
    return file_type



@login_required
def upload_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']

        # Detect the file type
        file_type = detect_file_type(file)
        cleaned_file_type = re.sub(r'[^\w.-]', '', file_type)
        language_name = language_map.get(cleaned_file_type, 'Unknown')

        if language_name == 'Unknown':
            logger.warning(f"Unknown file type for file: {file.name}")

        # Reset file pointer to the beginning
        file.seek(0)

        # YARA Scanning
        yara_file = os.path.join(settings.BASE_DIR, 'home/YARA/index.yar')
        signatures = run_yara(file, yara_file)

        # Save the uploaded file information
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.uploaded_by = request.user
            uploaded_file.save()

            # Save the analysis results in the Malware model
            malware = Malware(
                uploaded_file=uploaded_file,
                type=language_name,
                name=os.path.basename(file.name),
                language=language_name,
                comments=', '.join(signatures)
            )
            malware.save()

            # Prepare data for redirection
            encoded_language_name = urllib.parse.quote(language_name, safe='').strip("%")
            encoded_signatures = urllib.parse.quote(','.join(signatures), safe='').strip("%")

            logger.info(f"Redirecting to analyse with language_name: {language_name}, signatures: {signatures}")

            # Redirect to the analysis report page
            return redirect(reverse('list_uploaded_files'))
        else:
            logger.error("UploadFileForm is not valid")
            messages.error(request, form.errors)  # Display form errors

    else:
        form = UploadFileForm()

    return render(request, 'malware.html', {'form': form})


def detect_file_type(file):
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)  # Reset the file pointer after reading
    return file_type

def run_yara(file, yara_file):
    try:
        logger.debug("Compiling YARA rules from %s", yara_file)
        compiled_rules = yara.compile(filepath=yara_file)

        logger.debug("Running YARA match")
        file.seek(0)
        matches = compiled_rules.match(data=file.read())

        signatures = [match.rule for match in matches]
        logger.debug("YARA matches found: %s", signatures)
        return signatures

    except yara.Error as e:
        logger.error("YARA error: %s", e)
        return []


def submit_report(request):
    if request.method == 'POST':
        signatures = request.POST.get('signatures')
        language = request.POST.get('language')
        uploaded_file = request.FILES.get('file')

        # Process the submitted data
        # For example, you can create a new Malware instance and save it to the database
        malware = Malware(signatures=signatures, language=language, file=uploaded_file)
        malware.save()

        return redirect('success_page')  # Redirect to a success page

    return render(request, 'submit_report.html')


@login_required
def list_uploaded_files(request):
    query = request.GET.get('q')
    file_type_filter = request.GET.get('file_type')
    files = UploadedFile.objects.all()

    if query:
        files = files.filter(file__icontains=query)
    
    if file_type_filter:
        files = files.filter(file_type=file_type_filter)

    return render(request, 'list_uploaded_files.html', {'files': files})


@login_required
def edit_report(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)
    malware, created = Malware.objects.get_or_create(uploaded_file=uploaded_file)

    if request.method == 'POST':
        form = MalwareForm(request.POST, instance=malware)
        if form.is_valid():
            form.save()
            return redirect('list_uploaded_files')
    else:
        form = MalwareForm(instance=malware)

    return render(request, 'edit_report.html', {'form': form, 'uploaded_file': uploaded_file})

# views.py

@login_required
def view_report(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)
    try:
        malware = Malware.objects.get(uploaded_file=uploaded_file)
    except Malware.DoesNotExist:
        malware = None
    
    return render(request, 'view_report.html', {'uploaded_file': uploaded_file, 'malware': malware})


# PDF Reporting
def generate_pdf_report(file, report_data):
    file_path = f'{settings.MEDIA_ROOT}/{file.name}_report.pdf'
    c = canvas.Canvas(file_path, pagesize=letter)
    c.drawString(100, 750, f"Report for {file.name}")
    c.drawString(100, 730, f"Uploaded By: {report_data['uploaded_by']}")
    c.drawString(100, 710, f"Detected Type: {report_data['type']}")
    c.drawString(100, 690, f"Signatures: {', '.join(report_data['signatures'])}")
    c.save()

    return file_path

