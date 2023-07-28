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

def packet_capture_thread(completion_event):
    # Capture packets for 10 seconds
    captured_packets = sniff(timeout=10)
    for packet in captured_packets:
        packet_queue.put(packet)

    # Signal completion of packet capture
    completion_event.set()

def visualize_traffic():
    # Create an event to signal the completion of packet capture
    completion_event = threading.Event()

    # Create and start the packet capture thread
    capture_thread = threading.Thread(target=packet_capture_thread, args=(completion_event,))
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

    # Create a bar chart
    fig, ax = plt.subplots()
    ax.bar(range(len(traffic_data)), traffic_data)
    ax.set_xlabel("Packet Number")
    ax.set_ylabel("Packet Size")

    # Display the chart in the GUI
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

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

# Create a button to start traffic visualization and packet capture
traffic_button = tk.Button(frame, text="Visualize Real Traffic", command=visualize_traffic)
traffic_button.pack(pady=5)

# Create a large text box for displaying packet information
text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=15)
text_box.pack(pady=10)

# Start the GUI event loop
root.mainloop()
