import os
import re
import yara
import json
import magic
import socket
import urllib
import zipfile
import subprocess
from base64 import *
from PIL import Image
from io import BytesIO
from pathlib import Path
from scapy.layers.l2 import ARP
from scapy.all import sniff, get_if_list
from threading import Thread
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from .models import Malware, Packet
from .forms import UserRegistrationForm, ImageUploadForm
    

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


def capture_packets(request):
    if request.method == 'POST':
        interface = request.POST.get('interface')
        
        def process_packet(packet):
            # Process and store the packet as needed
            pass
        
        # Start capturing packets in a separate thread
        t = Thread(target=sniff, kwargs={'iface': interface, 'prn': process_packet})
        t.start()
        
        return HttpResponse('Capturing packets on {}'.format(interface))


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
def analyse(request, language_name, signatures):
    return render(request, 'analyse.html', {'language_name': language_name, 'signatures': signatures})


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


def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        file = request.FILES['file']
        file_type = magic.from_buffer(file.read(1024), mime=True)
        cleaned_file_type = re.sub(r'[^\w.-]', '', file_type) # Clean special characters from file_type using regex
        language_name = language_map.get(cleaned_file_type, 'Unknown') # Look up language name from language_map dictionary
        # Print the file name to the console for debugging
        if language_name == 'Unknown':
            print("Unknown file type for file:", file.name)
        
        # YARA Scanning
        yara_file = 'home/YARA/index.yar'
        signatures = run_yara(file, yara_file)
        

        # return redirect(reverse('analyse', kwargs={'language_name': urllib.parse.quote(language_name), 'signatures': ','.join(signatures)}))

        return redirect(reverse('analyse', kwargs={'language_name': urllib.parse.quote(language_name), 'signatures': signatures}))
    return render(request, 'malware.html')


def run_yara(file, yara_file):
    try:
        # Load YARA rules from the specified YARA file
        compiled_rules = yara.compile(filepath=yara_file)

        # Scan the sample with the loaded rules
        matches = compiled_rules.match(data=file.read())

        # Extract matching rule names or other relevant information from 'matches'
        signatures = [match.rule for match in matches]

        return signatures
    except yara.Error as e:
        print(f"YARA error: {e}")
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
