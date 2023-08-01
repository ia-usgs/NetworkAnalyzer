# Real Traffic Visualization and Packet Capture

This repository contains a Python script that provides a graphical user interface (GUI) for visualizing real network traffic and capturing packets. 
The script uses the tkinter library for GUI, scapy for packet sniffing and processing, and matplotlib for visualizing traffic data.

Features
* ** Real Traffic Visualization: ** Capture and visualize real network traffic for a specified duration.
* ** Packet Capture: ** Capture and display detailed packet information including IP address, MAC address, source port, destination port, packet size, and computer name (if available).
* ** Save to CSV: ** Save the captured packets to a CSV file for further analysis.
* ** IP Configuration (ipconfig /all): ** View network adapter configuration details using the ipconfig /all command.
* ** System File Checker Scan (sfc /scannow): ** Run the system file checker (SFC) scan with administrator privileges to check and repair corrupted system files.
* ** Check Disk Scan (chkdsk): ** Run the Check Disk (CHKDSK) scan with administrator privileges to check and repair disk errors.
* ** Deployment Image Servicing and Management (DISM) RestoreHealth: ** Run the DISM RestoreHealth command with administrator privileges to repair the Windows image.

### Requirements
Python 3.x
** tkinter, scapy, matplotlib ** libraries

### Usage
Install the required libraries using the following command:
```
pip install tk scapy matplotlib
```

Clone the repository or copy the script to your local machine.

### Run the script using the following command:
```
python real_traffic_visualization.py

```

The GUI window will appear, and you can interact with the following options:

Enter the Scan Duration in seconds and click the Visualize Real Traffic button to start the packet capture and visualization.
The captured packet information will be displayed in the left text box, and raw packet data will be displayed in the right text box.
Use the Save to CSV button to save the captured packet information to a CSV file named captured_packets.csv in the Downloads folder.
Use the Tools menu to access additional features like ipconfig /all, Show Graph, Show Text Boxes, SFC Scan, CHKDSK Scan, and DISM RestoreHealth.
Please note that certain features (e.g., SFC Scan, CHKDSK Scan, DISM RestoreHealth) may require administrator privileges, and the script will prompt for UAC elevation when necessary.

### Disclaimer
The provided script is intended for educational and informational purposes only. It is not intended for use in any unauthorized or harmful activities. 
The user is responsible for complying with all applicable laws and regulations regarding network traffic monitoring and data capture. 
The authors of this script are not responsible for any misuse or illegal activities conducted using this script.
