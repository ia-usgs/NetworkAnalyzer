import tkinter as tk
from tkinter import scrolledtext, END, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
import socket

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

# Queue to store captured packets
packet_queue = queue.Queue()
computer_name_queue = queue.Queue()

def get_computer_name(ip):
    try:
        computer_name = socket.gethostbyaddr(ip)[0]
        return computer_name
    except socket.herror:
        return None

def process_packet(packet):
    # Extract IP, MAC, and computer name information from the packet
    ip = None
    mac = None

    if 'IP' in packet:
        ip = packet[IP].src
    if 'Ether' in packet:
        mac = packet[Ether].src

    # Format packet information for display in the text box
    packet_info = f"IP: {ip}, MAC: {mac}, Computer Name: Retrieving...\n"
    return packet_info, ip

def dns_lookup_thread():
    while True:
        packet_info, ip = computer_name_queue.get()
        computer_name = get_computer_name(ip)
        if computer_name:
            packet_info = packet_info.replace("Retrieving...", computer_name)
        else:
            packet_info = packet_info.replace("Retrieving...", "Unknown")
        text_box.config(state=tk.NORMAL)  # Enable text box for editing
        text_box.insert(tk.END, packet_info)  # Insert packet info at the end of the text box
        text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing

def packet_capture_thread(completion_event, duration):
    # Capture packets for the specified duration (in seconds)
    captured_packets = sniff(timeout=duration)
    for packet in captured_packets:
        packet_queue.put(packet)

    # Signal completion of packet capture
    completion_event.set()

def visualize_traffic():
    # Get the user input for the scan duration
    duration_str = duration_entry.get()
    try:
        duration = int(duration_str)
        if duration <= 0:
            raise ValueError
    except ValueError:
        # If the user input is not a positive integer, display an error message
        tk.messagebox.showerror("Invalid Input", "Please enter a positive integer for the scan duration.")
        return

    # Create an event to signal the completion of packet capture
    completion_event = threading.Event()

    # Create and start the packet capture thread
    capture_thread = threading.Thread(target=packet_capture_thread, args=(completion_event, duration))
    capture_thread.start()

    # Create and start the DNS lookup thread
    dns_thread = threading.Thread(target=dns_lookup_thread)
    dns_thread.daemon = True
    dns_thread.start()

    # Start updating the visualization
    update_visualization(completion_event)

def update_visualization(completion_event):
    if not completion_event.wait(timeout=0.1):
        # Packet capture is still ongoing, schedule the function to run again
        root.after(1, update_visualization, completion_event)
        return

    # Process the captured packets for visualization and display in the text boxes
    traffic_data = []
    captured_packets = []
    raw_packet_info = ""
    while not packet_queue.empty():
        packet = packet_queue.get()
        captured_packets.append(packet)
        traffic_data.append(len(packet))

        # Process the packet and accumulate packet information
        packet_info, ip = process_packet(packet)
        computer_name_queue.put((packet_info, ip))
        raw_packet_info += packet.show(dump=True) + "\n"

    # Create or update the bar chart
    global fig, ax, canvas  # Declare fig, ax, and canvas as global variables
    if 'fig' not in globals():
        fig, ax = plt.subplots()
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.get_tk_widget().pack(side=tk.RIGHT)  # Place the chart on the right side
    else:
        ax.clear()

    ax.bar(range(len(traffic_data)), traffic_data)
    ax.set_xlabel("Packet Number")
    ax.set_ylabel("Packet Size")

    # Update the chart in the GUI
    canvas.draw()

    # Display the captured packets in the first text box (MAC, IP, and computer name)
    text_box.config(state=tk.NORMAL)  # Enable text box for editing
    text_box.delete(1.0, END)  # Clear previous content
    for packet_info, _ in computer_name_queue.queue:
        text_box.insert(tk.END, packet_info)  # Insert packet info at the end of the text box
    text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing

    # Display the captured packets in the second text box (raw packet data)
    raw_text_box.config(state=tk.NORMAL)  # Enable text box for editing
    raw_text_box.delete(1.0, END)  # Clear previous content
    raw_text_box.insert(tk.END, raw_packet_info)  # Insert raw packet info at the end of the text box
    raw_text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing

# Create the main GUI window
root = tk.Tk()
root.title("Real Traffic Visualization and Packet Capture")

# Create a frame for the GUI elements
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# Create a field box for entering the scan duration
duration_label = tk.Label(frame, text="Scan Duration (seconds):")
duration_label.pack(pady=5)
duration_entry = tk.Entry(frame)
duration_entry.pack(pady=5)

# Create a button to start traffic visualization and packet capture
traffic_button = tk.Button(frame, text="Visualize Real Traffic", command=visualize_traffic)
traffic_button.pack(pady=5)

# Create a larger text box for displaying packet information (MAC, IP, and computer name)
text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=100, height=25)  # Decrease the height to 15
text_box.pack(pady=10, side=tk.LEFT)  # Place the text box on the left side

# Create a second text box to display raw packet data
raw_text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=100, height=25)  # Decrease the height to 10
raw_text_box.pack(pady=10, side=tk.LEFT)  # Place the text box on the left side

# Start the GUI event loop
root.mainloop()
