import tkinter as tk
from tkinter import scrolledtext, END
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff
import threading
import queue

# Queue to store captured packets
packet_queue = queue.Queue()

def process_packet(packet):
    # Customize this function to format packet information for display in the text box
    return f"{packet.summary()}\n"

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

    # Start updating the visualization
    update_visualization(completion_event)

def update_visualization(completion_event):
    if not completion_event.wait(timeout=0.1):
        # Packet capture is still ongoing, schedule the function to run again
        root.after(1, update_visualization, completion_event)
        return

    # Process the captured packets for visualization and display in the text box
    traffic_data = []
    captured_packets = []
    while not packet_queue.empty():
        packet = packet_queue.get()
        captured_packets.append(packet)
        traffic_data.append(len(packet))

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

    # Display the captured packets in the text box
    text_box.delete(1.0, END)
    for packet in captured_packets:
        packet_info = process_packet(packet)
        text_box.insert(tk.END, packet_info)

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

# Create a larger text box for displaying packet information
text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=25)  # Increase the height to 25
text_box.pack(pady=10, side=tk.LEFT)  # Place the text box on the left side

# Start the GUI event loop
root.mainloop()
