// Get the modal
const modal = document.getElementById('rootPasswordModal');

// Get the button that opens the modal
const btn = document.getElementById('submitRootPassword');

// Get the <span> element that closes the modal
const span = document.getElementsByClassName('close-btn')[0];

// Function to display the modal
function displayModal() {
    modal.style.display = 'block';
}

// Function to close the modal
function closeModal() {
    modal.style.display = 'none';
}

// Function to send root password to the server
function sendRootPassword() {
    const rootPassword = document.getElementById('rootPasswordInput').value;
    
    // Send root password to the server for validation
    fetch('/validate_root_password/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password: rootPassword }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.valid) {
            // Perform root operation
            // Replace with your root operation code
            alert('Root operation performed successfully');
            
            // Close the modal
            closeModal();
        } else {
            alert('Invalid root password');
        }
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}

// In ids.js

function updateDevicesList(devices) {
    const devicesList = document.getElementById('devices-list');
    devicesList.innerHTML = '';

    devices.forEach(device => {
        const listItem = document.createElement('li');
        listItem.textContent = `${device.hostname} (${device.ip}) - ${device.mac}`;
        devicesList.appendChild(listItem);
    });
}

// Add this to your existing WebSocket listener
if (event.data.type === 'update_devices_list') {
    updateDevicesList(event.data.devices);
}

// Event listeners
btn.addEventListener('click', sendRootPassword);
span.addEventListener('click', closeModal);
