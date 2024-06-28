import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import *
import netifaces as nfs
import threading as thr
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP , Raw 
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR

root = ttk.Window(themename="darkly")
buttons = {}
p_labels = {}
labels = {}
threads = {}
stop_events = {}
packets = dict()
running = True  # Flag to check if the main loop is running
current_shown_packet = None
frm = ttk.Frame(root, padding=10)
monitering_frame = ttk.Frame(root, padding=10)
frm.grid(column=0, row=1, columnspan=2)
current_frame = frm

# Populate the main frame with interface buttons
interfaces = nfs.interfaces()
tables = {}

def main():
    line = 0
    for interface in interfaces:
        # Create a label for the interface
        labels[interface] = ttk.Label(frm, text=f"{interface}")
        labels[interface].grid(column=0, row=line)
        # Create a label for the number of packets
        p_labels[interface] = ttk.Label(frm, text="0")
        p_labels[interface].grid(column=1, row=line)
        # Create a monitor button to monitor the interface
        buttons[interface] = ttk.Button(frm, text="Monitor", command=lambda i=interface: sniffer(i))
        buttons[interface].grid(column=2, row=line)
        line += 1
    # Quit button
    ttk.Button(root, text="Quit", command=Quit).grid(column=1, row=line+1)
    start()
    root.mainloop()

def start():
    for interface in interfaces:
        stop_events[interface] = thr.Event()
        threads[interface] = thr.Thread(target=start_sniffing, args=(interface, stop_events[interface]))
        threads[interface].start()

def start_sniffing(interface, stop_event):
    print(f"Starting sniffing on interface {interface} ...\n")
    while not stop_event.is_set():
        sniff(iface=interface, prn=lambda packet: handle_packet(interface, packet), timeout=1)
        # `timeout=1` ensures sniff() returns regularly to check stop_event



# Main window setup


def handle_packet(interface, packet):
    if interface in packets:
        packets[interface].append(packet)
    else:
        packets[interface] = [packet]

    # Update the label in a thread-safe manner
    if running:
        root.after(0, update_label, interface)
        root.after(0, update_table, interface, packet)


def extract_packet_info(packet):
    ether = packet.getlayer(Ether)
    ip = packet.getlayer(IP)
    proto = None
    src_ip = dst_ip = src_mac = dst_mac = ''
    if ether:
        src_mac = ether.src
        dst_mac = ether.dst
    if ip:
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
    return (src_mac, dst_mac, src_ip, dst_ip, proto , packet )

def advanced_details(packet) :
    details = {}

    # Ethernet Layer
    if Ether in packet:
        ether = packet[Ether]
        details['eth'] = {}
        details['eth']['src_mac'] = ether.src
        details['eth']['dst_mac'] = ether.dst
        details['eth']['ethertype'] = ether.type

    # IP Layer
    if IP in packet:
        ip = packet[IP]
        details["ip"] = {}
        details["ip"]['src_ip'] = ip.src
        details["ip"]['dst_ip'] = ip.dst
        details["ip"]['ip_version'] = ip.version
        details["ip"]['ip_header_length'] = ip.ihl
        details["ip"]['tos'] = ip.tos
        details["ip"]['total_length'] = ip.len
        details["ip"]['identification'] = ip.id
        details["ip"]['flags'] = ip.flags
        details["ip"]['fragment_offset'] = ip.frag
        details["ip"]['ttl'] = ip.ttl
        details["ip"]['protocol'] = ip.proto
        details["ip"]['ip_checksum'] = ip.chksum

    # TCP Layer
    if TCP in packet:
        tcp = packet[TCP]
        details['tcp'] = {}
        details['tcp']['src_port'] = tcp.sport
        details['tcp']['dst_port'] = tcp.dport
        details['tcp']['sequence_number'] = tcp.seq
        details['tcp']['acknowledgment_number'] = tcp.ack
        details['tcp']['data_offset'] = tcp.dataofs
        details['tcp']['tcp_reserved'] = tcp.reserved
        details['tcp']['tcp_flags'] = tcp.flags
        details['tcp']['window_size'] = tcp.window
        details['tcp']['tcp_checksum'] = tcp.chksum
        details['tcp']['urgent_pointer'] = tcp.urgptr

    # UDP Layer
    if UDP in packet:
        udp = packet[UDP]
        details['udp'] = {}
        details['udp']['src_port'] = udp.sport
        details['udp']['dst_port'] = udp.dport
        details['udp']['udp_length'] = udp.len
        details['udp']['udp_checksum'] = udp.chksum

    # ICMP Layer
    if ICMP in packet:
        icmp = packet[ICMP]
        details['icmp'] = {}
        details['icmp']['icmp_type'] = icmp.type
        details['icmp']['icmp_code'] = icmp.code
        details['icmp']['icmp_checksum'] = icmp.chksum
        details['icmp']['icmp_id'] = icmp.id
        details['icmp']['icmp_seq'] = icmp.seq

    # HTTP Layer
    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]
        details['httpReq'] = {}
        details['httpReq']['http_method'] = http.Method.decode()
        details['httpReq']['http_host'] = http.Host.decode()
        details['httpReq']['http_path'] = http.Path.decode()

    if packet.haslayer(HTTPResponse):
        http_resp = packet[HTTPResponse]
        details['httpRes'] = {}
        details['httpRes']['http_status_code'] = http_resp.Status_Code.decode()
        details['httpRes']['http_reason_phrase'] = http_resp.Reason_Phrase.decode()

    # DNS Layer
    if packet.haslayer(DNS):
        dns = packet[DNS]
        details['dns'] = {}
        details['dns']['dns_id'] = dns.id
        details['dns']['dns_qr'] = dns.qr
        if dns.qr == 0:  # Query
            if packet.haslayer(DNSQR):
                dnsqr = packet[DNSQR]
                details['dns']['dns_query_name'] = dnsqr.qname.decode()
                details['dns']['dns_query_type'] = dnsqr.qtype
        elif dns.qr == 1:  # Response
            if packet.haslayer(DNSRR):
                dnsrr = packet[DNSRR]
                details['dns']['dns_response_name'] = dnsrr.rrname.decode()
                details['dns']['dns_response_type'] = dnsrr.type
                details['dns']['dns_response_data'] = dnsrr.rdata

    # Timestamp
    timestamp = packet.time

    # Payload
    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else None

    return details , timestamp, payload

# Function to toggle frames
def toggle_frames():
    global current_frame
    
    if current_frame == frm:
        current_frame.grid_forget()
        monitering_frame.grid(column=0, row=1, columnspan=2)
        current_frame = monitering_frame
    else:
        current_frame.grid_forget()
        frm.grid(column=0, row=1, columnspan=2)
        current_frame = frm

def sniffer(interface):
    window = Toplevel(root)
    window.title(f"Packets for {interface}")

    frame = ttk.Frame(window, padding=12)
    frame.grid(column=0, row=0, sticky=(N, S, E, W))

    columns = ('src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'proto' , 'packet')
    table = ttk.Treeview(frame, columns=columns, show='headings')
    table.heading('src_mac', text='Source MAC')
    table.heading('dst_mac', text='Destination MAC')
    table.heading('src_ip', text='Source IP')
    table.heading('dst_ip', text='Destination IP')
    table.heading('proto', text='Protocol')
    table.heading('packet', text='packet')
    table.grid(row=0, column=0, sticky='nsew')

    scrollbar = ttk.Scrollbar(frame, orient=VERTICAL, command=table.yview)
    table.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='ns')

    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    
    def exit_table():
        window.destroy()

    ttk.Button(window, text="Quit", command=exit_table).grid(column=0, row=1, pady=10)

    tables[interface] = table


def show_packet(packet):
    global_window = Toplevel(root)
    global_window.geometry("600x800")
    global_window.resizable(True, True)
    global_window.title(f"Packet Details")

    # Create a frame to contain the canvas and the scrollbar
    container = ttk.Frame(global_window)
    container.grid(row=0, column=0, sticky="nsew")

    # Create a canvas
    canvas = Canvas(container, bg="white")
    canvas.grid(row=0, column=0, sticky="nsew")

    # Add a scrollbar to the canvas
    scrollbar = ttk.Scrollbar(container, orient=VERTICAL, command=canvas.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Create a frame inside the canvas
    scrollable_frame = ttk.Frame(canvas, padding=10)

    # Create a window in the canvas
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    # Configure the scroll region
    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    scrollable_frame.bind("<Configure>", on_frame_configure)

    details, timestamp, payload = advanced_details(packet)
    line = 0

    for layer in details:
        Layer = ttk.Frame(scrollable_frame, padding=15)
        Layer.grid(column=0, row=line+1, sticky='nsew')
        Layer.grid_remove()  # Start with the Layer frame hidden

        ttk.Button(scrollable_frame, text=layer, command=lambda l=Layer: toggle_layer(l)).grid(column=0, row=line)

        header_line = 0
        for header in details[layer]:
            ttk.Label(Layer, text=f"{header} : {details[layer][header]}").grid(column=0, row=header_line, sticky='w')
            header_line += 1

        line += 2

    ttk.Label(scrollable_frame, text=f"payload: {payload}").grid(column=1, row=0)
    ttk.Label(scrollable_frame, text=f"timestamp: {timestamp}").grid(column=1, row=1)

    def Exit():
        global_window.destroy()

    ttk.Button(scrollable_frame, text="Exit", command=Exit).grid(column=0, row=line, pady=10)

    # Make the container expandable
    global_window.grid_rowconfigure(0, weight=1)
    global_window.grid_columnconfigure(0, weight=1)
    container.grid_rowconfigure(0, weight=1)
    container.grid_columnconfigure(0, weight=1)
    canvas.grid_rowconfigure(0, weight=1)
    canvas.grid_columnconfigure(0, weight=1)

def toggle_layer(layer):
    if layer.winfo_ismapped():
        layer.grid_remove()
    else:
        layer.grid()

        
def update_label(interface):
    if interface in p_labels:
        p_labels[interface].config(text=len(packets[interface]))

def update_table(interface, packet):
    if interface in tables and tables[interface].winfo_exists():
        packet_info = extract_packet_info(packet)
        row_id = tables[interface].insert('', 'end', values=packet_info)
        tables[interface].item(row_id, tags=(row_id,))
        tables[interface].tag_bind(row_id, '<Double-1>', lambda e, pkt=packet: show_packet(pkt))


def Quit():
    global running
    running = False
    for interface in stop_events:
        stop_events[interface].set()
    for thread in threads:
        threads[thread].join()
    root.destroy()




if __name__ == '__main__':
    main()