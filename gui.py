import tkinter as tk
from tkinter import scrolledtext, END, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
import socket

from scapy.layers.dns import DNS, DNSQR
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
    computer_name = None

    if 'IP' in packet:
        ip = packet[IP].src
    if 'Ether' in packet:
        mac = packet[Ether].src

    # Check if it's a DNS packet and extract the server information
    if 'UDP' in packet and 'DNS' in packet:
        if packet[DNS].qr == 0:  # QR = 0 means it's a query (client to server)
            server = packet[DNSQR].qname
            # Perform computer name lookup using the IP address
            computer_name = get_computer_name(ip)
            if computer_name is None:
                computer_name = "Unknown"  # Use a default value if computer name is not found

    # Format packet information for display in the text box
    if computer_name:
        packet_info = f"{ip:<15}  {mac:<18}  {computer_name}\n"
    else:
        packet_info = f"{ip:<15}  {mac:<18}  {'Retrieving...'}\n"

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
    ip_packet_sizes = {}

    while not packet_queue.empty():
        packet = packet_queue.get()
        captured_packets.append(packet)

        # Process the packet and accumulate packet information
        packet_info, ip = process_packet(packet)
        raw_packet_info += packet.show(dump=True) + "\n"

        # Accumulate packet size for each IP address
        if ip:
            if ip not in ip_packet_sizes:
                ip_packet_sizes[ip] = len(packet)
            else:
                ip_packet_sizes[ip] += len(packet)

        # Add packet_info to the computer_name_queue
        computer_name_queue.put((packet_info, ip))

    # Create or update the bar chart
    global fig, ax, canvas  # Declare fig, ax, and canvas as global variables
    if 'fig' not in globals():
        fig, ax = plt.subplots(figsize=(10, 8))  # Increase the figure size
        canvas = FigureCanvasTkAgg(fig, master=frame)
    else:
        ax.clear()

    # Extract IP addresses and packet sizes for graph
    ips = list(ip_packet_sizes.keys())
    packet_sizes = list(ip_packet_sizes.values())

    # Generate x-axis labels (IP addresses)
    x_labels = range(len(ips))

    # Plot the bar chart with packet sizes on the y-axis and IP addresses as labels
    ax.bar(x_labels, packet_sizes, tick_label=ips, color='tab:blue')

    # Rotate x-axis labels to prevent congestion and decrease font size
    plt.xticks(rotation=45, ha='right', fontsize=8)

    ax.set_xlabel("IP Address")
    ax.set_ylabel("Total Packet Size")

    # Update the chart in the GUI
    canvas.draw()

    # Initially hide the graph canvas
    canvas.get_tk_widget().pack_forget()

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

def show_graph():
    canvas.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  # Pack the canvas to fill the frame
    text_box.pack_forget()
    raw_text_box.pack_forget()

def show_text_boxes():
    canvas.get_tk_widget().pack_forget()
    text_box.pack(pady=10, side=tk.LEFT)
    raw_text_box.pack(pady=10, side=tk.LEFT)




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

# Create a larger text box for displaying packet information (MAC, IP, and server)
text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=100, height=25,
                                     font=("Courier New", 10))  # Monospaced font
text_box.pack(pady=10, side=tk.LEFT)  # Place the text box on the left side

# Create a second text box to display raw packet data
raw_text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=100, height=25)  # Decrease the height to 10
raw_text_box.pack(pady=10, side=tk.LEFT)  # Place the text box on the left side

# Create a menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# Create a "View" menu
view_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="View", menu=view_menu)
view_menu.add_command(label="Show Graph", command=show_graph)
view_menu.add_command(label="Show Text Boxes", command=show_text_boxes)

# Start the GUI event loop
root.mainloop()
