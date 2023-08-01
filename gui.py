import ctypes
import os
import textwrap
import tkinter as tk
from tkinter import scrolledtext, END, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
import socket
import csv
import subprocess

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

# Queue to store captured packets
packet_queue = queue.Queue()
computer_name_queue = queue.Queue()

def run_sfc_scan():
    try:
        # Ask for administrator privileges using the UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd", "/c sfc /scannow", None, 1)
        if ret > 32:
            # If the return value is greater than 32, the UAC prompt was successful
            # In this case, the "sfc /scannow" command is running with elevated privileges.
            tk.messagebox.showinfo("SFC Scan Started", "The SFC scan is running with administrator privileges.")
        elif ret == 31:
            # Return value 31 indicates the user canceled the UAC prompt
            raise Exception("SFC scan canceled by user.")
        else:
            # Return value less than 31 indicates an error with UAC prompt
            raise Exception("Failed to obtain administrator privileges.")

    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {str(e)}")
def save_to_csv():
    # Get the user's Downloads folder
    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")

    # Specify the filename and full path for saving the CSV file in the Downloads folder
    filename = os.path.join(downloads_folder, "captured_packets.csv")

    with open(filename, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Write header row
        writer.writerow(["IP Address", "MAC Address", "Source Port", "Dest Port", "Packet Size", "Computer Name"])

        # Write each packet's information to the CSV file
        for packet_info, _, _ in computer_name_queue.queue:
            ip = packet_info.strip().split('  ', 2)[0]
            mac = packet_info.strip().split('  ', 2)[1]
            src_port = packet_info.strip().split('  ', 3)[2]
            dst_port = packet_info.strip().split('  ', 4)[3]
            packet_size = packet_info.strip().split('  ', 4)[4].split()[-1]

            # Handle empty computer name
            computer_name = packet_info.strip().split("  ", 4)[4] if "Retrieving..." not in packet_info else "Unknown"

            # Write the row to the CSV file
            writer.writerow([ip, mac, src_port, dst_port, packet_size, computer_name])

    messagebox.showinfo("CSV Saved", "Captured packets have been saved to 'captured_packets.csv'.")
def update_text_box(output_text_box, process):
    def read_output():
        line = process.stdout.readline()
        if line:
            output_text_box.insert(tk.END, line)
            output_text_box.see(tk.END)
            # Continue reading output after 10 milliseconds
            output_text_box.after(10, read_output)
        else:
            process.stdout.close()
            process.wait()
            # Disable text box to prevent editing when the command is finished
            output_text_box.config(state=tk.DISABLED)

    # Start reading the output
    read_output()


def run_ipconfig_all():
    try:
        # Run the "ipconfig /all" command using subprocess
        process = subprocess.Popen(["ipconfig", "/all"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   universal_newlines=True)

        # Create a new window to display the results
        output_window = tk.Toplevel(root)
        output_window.title("ipconfig /all Results")

        # Create a text box to display the results
        output_text_box = scrolledtext.ScrolledText(output_window, wrap=tk.WORD, width=100, height=25,
                                                   font=("Courier New", 10))  # Monospaced font
        output_text_box.pack(padx=10, pady=10)

        # Start updating the text box with real-time output
        update_thread = threading.Thread(target=update_text_box, args=(output_text_box, process))
        update_thread.start()

    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {str(e)}")

def get_computer_name(ip):
    try:
        computer_name = socket.gethostbyaddr(ip)[0]
        return computer_name
    except socket.herror:
        return None

def process_packet(packet):
    # Initialize variables with default values
    ip = None
    mac = None
    packet_size = 0

    # Check for IP and MAC in the packet
    if 'IP' in packet:
        ip = packet[IP].src
    if 'Ether' in packet:
        mac = packet[Ether].src

    # Calculate the packet size
    packet_size = len(packet)

    # Extract source and destination ports if available
    src_port = None
    dst_port = None
    if 'TCP' in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif 'UDP' in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Format packet information for display in the text box (including ports)
    packet_info = f"{ip or 'Unknown':<15}  {mac or 'Unknown':<18}  {src_port or 'N/A':<6}  {dst_port or 'N/A':<6}  Retrieving...  {packet_size:<10}\n"

    return packet_info, ip, packet_size

def run_chkdsk_scan():
    try:
        # Ask for administrator privileges using the UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd", "/c chkdsk", None, 1)
        if ret > 32:
            # If the return value is greater than 32, the UAC prompt was successful
            # In this case, the "chkdsk" command is running with elevated privileges.
            tk.messagebox.showinfo("CHKDSK Scan Started", "The CHKDSK scan is running with administrator privileges.")
        elif ret == 31:
            # Return value 31 indicates the user canceled the UAC prompt
            raise Exception("CHKDSK scan canceled by user.")
        else:
            # Return value less than 31 indicates an error with UAC prompt
            raise Exception("Failed to obtain administrator privileges.")

    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {str(e)}")
# Updated dns_lookup_thread function
def dns_lookup_thread():
    while True:
        try:
            packet_info, ip, packet_size = computer_name_queue.get()  # Unpack all three values

            # If the IP address is None, set the computer name as "Unknown" and skip the DNS lookup
            if ip is None:
                computer_name = "Unknown"
            else:
                computer_name = get_computer_name(ip)

            # Replace "Retrieving..." with the computer name or "Unknown" if it's None
            packet_info = packet_info.replace("Retrieving...", computer_name or "Unknown")

            text_box.config(state=tk.NORMAL)  # Enable text box for editing
            text_box.insert(tk.END, packet_info)  # Insert packet info at the end of the text box
            text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing
        except Exception as e:
            print("Error in DNS lookup thread:", e)


def run_dism_restorehealth():
    try:
        # Ask for administrator privileges using the UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd", "/c dism /online /cleanup-image /restorehealth", None, 1)
        if ret > 32:
            # If the return value is greater than 32, the UAC prompt was successful
            # In this case, the "dism /online /cleanup-image /restorehealth" command is running with elevated privileges.
            tk.messagebox.showinfo("DISM RestoreHealth Started", "The DISM RestoreHealth process is running with administrator privileges.")
        elif ret == 31:
            # Return value 31 indicates the user canceled the UAC prompt
            raise Exception("DISM RestoreHealth canceled by user.")
        else:
            # Return value less than 31 indicates an error with UAC prompt
            raise Exception("Failed to obtain administrator privileges.")

    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {str(e)}")






def packet_capture_thread(completion_event, duration):
    # Capture packets for the specified duration (in seconds)
    captured_packets = sniff(timeout=duration)
    for packet in captured_packets:
        packet_queue.put(packet)

    # Signal completion of packet capture
    completion_event.set()


def visualize_traffic():
    try:
        # Get the user input for the scan duration
        duration_str = duration_entry.get()
        duration = int(duration_str)
        if duration <= 0:
            raise ValueError("Scan duration must be a positive integer.")

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
    except ValueError:
        tk.messagebox.showerror("Invalid Input", "Please enter a positive integer for the scan duration.")
    except Exception as e:
        tk.messagebox.showerror("Error", str(e))
def update_visualization(completion_event):
    global canvas

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
        if packet is None:
            break  # Stop processing if the packet is None

        captured_packets.append(packet)

        # Process the packet and accumulate packet information
        packet_info, ip, packet_size = process_packet(packet)
        raw_packet_info += packet.show(dump=True) + "\n"

        # Accumulate packet size for each IP address
        if ip:
            if ip not in ip_packet_sizes:
                ip_packet_sizes[ip] = len(packet)
            else:
                ip_packet_sizes[ip] += len(packet)

        # Add packet_info to the computer_name_queue
        computer_name_queue.put((packet_info, ip, packet_size))

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

    # Display the column labels on top of the text box
    column_labels = "IP Address        MAC Address          Source Port    Dest Port    Computer Name    Packet Size\n"
    text_box.config(state=tk.NORMAL)  # Enable text box for editing
    text_box.delete(1.0, END)  # Clear previous content
    text_box.insert(tk.END, column_labels)  # Insert column labels into the text box

    for packet_info, ip, packet_size in computer_name_queue.queue:
        # If the IP address is None, skip formatting and continue to the next packet_info
        if ip is None:
            continue

        # Format the packet information with fixed-width columns
        ip_formatted = f"{ip:<15}"
        max_mac_length = max(
            len(packet_info.strip().split('  ', 2)[1]) for packet_info, _, _ in computer_name_queue.queue)
        mac_formatted = f"{packet_info.strip().split('  ', 2)[1]:<{max_mac_length}}"

        src_port_formatted = f"{packet_info.strip().split('  ', 3)[2]:<6}"
        dst_port_formatted = f"{packet_info.strip().split('  ', 4)[3]:<6}"
        packet_size_formatted = f"{packet_size:>10}"  # Packet size column
        computer_name = packet_info.strip().split("  ", 4)[4]

        # Split the computer name into multiple lines and join them with newlines
        computer_name_lines = textwrap.fill(computer_name, width=30)

        # Concatenate the formatted values and computer name to create a row
        row = f"{ip_formatted}{mac_formatted}{src_port_formatted}{dst_port_formatted}{packet_size_formatted}  {computer_name_lines}\n"

        text_box.insert(tk.END, row)  # Insert row into the text box

    text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing

    # Display the captured packets in the second text box (raw packet data)
    raw_text_box.config(state=tk.NORMAL)  # Enable text box for editing
    raw_text_box.delete(1.0, END)  # Clear previous content

    raw_text_box.insert(tk.END, raw_packet_info)  # Insert raw packet info at the end of the text box

    raw_text_box.config(state=tk.DISABLED)  # Disable text box to prevent editing

    while True:
        try:
            packet = packet_queue.get_nowait()
            if packet is None:
                break  # Stop processing if the packet is None

            # Process the packet and accumulate packet information
            packet_info, ip, packet_size = process_packet(packet)
            raw_packet_info += packet.show(dump=True) + "\n"

            # Accumulate packet size for each IP address
            if ip:
                if ip not in ip_packet_sizes:
                    ip_packet_sizes[ip] = len(packet)
                else:
                    ip_packet_sizes[ip] += len(packet)

            # Add packet_info to the computer_name_queue
            computer_name_queue.put((packet_info, ip, packet_size))
        except queue.Empty:
            break  # Queue is empty, stop processing
        except Exception as e:
            print("Error in packet processing:", e)

    display_packet_info(raw_packet_info)
def show_graph():
    canvas.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  # Pack the canvas to fill the frame
    text_box.pack_forget()
    raw_text_box.pack_forget()

def show_text_boxes():
    canvas.get_tk_widget().pack_forget()
    text_box.pack(pady=10, side=tk.LEFT)
    raw_text_box.pack(pady=10, side=tk.LEFT)


def display_packet_info(raw_packet_info):
    # Display the column labels on top of the text box
    column_labels = "IP Address        MAC Address          Source Port    Dest Port    Packet Size    Computer Name\n"
    text_box.config(state=tk.NORMAL)  # Enable text box for editing
    text_box.delete(1.0, END)  # Clear previous content
    text_box.insert(tk.END, column_labels)  # Insert column labels into the text box

    for packet_info, ip, packet_size in computer_name_queue.queue:
        # If the IP address is None, skip formatting and continue to the next packet_info
        if ip is None:
            continue

        # Format the packet information with fixed-width columns
        ip_formatted = f"{ip:<15}"
        max_mac_length = max(len(packet_info.strip().split('  ', 2)[1]) for packet_info, _, _ in computer_name_queue.queue)
        mac_formatted = f"{packet_info.strip().split('  ', 2)[1]:<{max_mac_length}}"

        src_port_formatted = f"{packet_info.strip().split('  ', 3)[2]:<6}"
        dst_port_formatted = f"{packet_info.strip().split('  ', 4)[3]:<6}"
        packet_size_formatted = f"{packet_size:>10}"  # Packet size column
        computer_name = packet_info.strip().split("  ", 4)[4]

        # Split the computer name into multiple lines and join them with newlines
        computer_name_lines = textwrap.fill(computer_name, width=30)

        # Concatenate the formatted values and computer name to create a row
        row = f"{ip_formatted}{mac_formatted}{src_port_formatted}{dst_port_formatted}{packet_size_formatted}  {computer_name_lines}\n"

        text_box.insert(tk.END, row)  # Insert row into the text box

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
# Create a "Save to CSV" button
save_button = tk.Button(frame, text="Save to CSV", command=save_to_csv)
save_button.pack(pady=5, side=tk.TOP)

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

# Create a "Tools" menu
tools_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Tools", menu=tools_menu)
tools_menu.add_command(label="ipconfig /all", command=run_ipconfig_all)
tools_menu.add_command(label="Show Graph", command=show_graph)
tools_menu.add_command(label="Show Text Boxes", command=show_text_boxes)
tools_menu.add_command(label="SFC Scan", command=run_sfc_scan)
tools_menu.add_command(label="CHKDSK Scan", command=run_chkdsk_scan)
tools_menu.add_command(label="DISM RestoreHealth", command=run_dism_restorehealth)

# Start the GUI event loop
if __name__ == "__main__":
    root.mainloop()