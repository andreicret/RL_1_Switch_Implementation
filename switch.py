#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import utils as util
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Structure-like class used for sending BPDU packets
class bdpu_packet:
    def __init__(
        self,
        dst_mac,
        src_mac,
        llc_length,
        llc_header,
        bdpu_header,
        flags,
        root_bridge_id,
        root_path_cost,
        bridge_id,
        port_id,
        message_age,
        max_age,
        hello_time,
        forward_delay
    ):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.llc_length = llc_length
        self.llc_header = llc_header
        self.bdpu_header = bdpu_header
        self.flags = int.to_bytes(flags, 1, byteorder='big')

        self.root_bridge_id = int.to_bytes(root_bridge_id, 2, byteorder='big')
        self.root_path_cost = int.to_bytes(root_path_cost, 4, byteorder='big')
        self.bridge_id =  int.to_bytes(bridge_id, 2, byteorder='big')
        self.port_id = int.to_bytes(port_id, 2, byteorder='big')
        self.message_age = int.to_bytes(message_age, 2, byteorder='big')
        self.max_age = int.to_bytes(max_age, 2, byteorder='big')
        self.hello_time = int.to_bytes(hello_time, 2, byteorder='big')
        self.forward_delay = int.to_bytes(forward_delay, 2, byteorder='big')


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# Function used by the second thread to establish STP convergence
def send_bdpu_every_sec(port_modes, interfaces):
    while True:
        # If switch is also root
        if util.bridge_id == util.root_id:
            for port in interfaces:
                # Do not send BPDU packets via access ports
                if util.port_modes[get_interface_name(port)] == 'T':
                    bdpu = bdpu_packet(
                        dst_mac = util.ALL_BRIDGES_BYTE,
                        src_mac = get_switch_mac(),
                        llc_length = util.LLC_LENGTH,
                        llc_header = util.LLC_HEADER,

                        # BPDU header
                        bdpu_header = util.BDPU_HEADER,

                        # BPDU config (default values)
                        flags = 0,
                        root_bridge_id = int(util.bridge_id),
                        root_path_cost = 0,
                        bridge_id = int(util.bridge_id),
                        port_id = int(port),
                        message_age = 1,
                        max_age = 20,
                        hello_time = 2,
                        forward_delay = 15)
                    # Assemble the binary packet
                    data = bdpu.dst_mac + bdpu.src_mac + bdpu.llc_length + bdpu.llc_header +bdpu.flags + bdpu.root_bridge_id + bdpu.root_path_cost + bdpu.bridge_id + bdpu.port_id + bdpu.message_age + bdpu.max_age + bdpu.hello_time + bdpu.forward_delay
                    send_to_link(port, len(data), data)   
        time.sleep(1)

#Check if a MAC address is unicast or broadcast
def is_unicast(mac_address):
    return int(mac_address[1], 16) % 2 == 0

def main():
    # Retreive the switch ID
    switch_id = sys.argv[1]

    # Generate the interface array
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # Parse the switch configuration from external file
    with open (util.SWITCH_FILES[switch_id], 'r') as config:
        line = config.readline().strip()
        util.priority = line.split()[0]
        
        # Is the current interface TRUNK or ACCESS?
        for line in config:
            words = line.split()
            util.port_modes[words[0]] = words[1]

    config.close()

    # Set all trunk ports to blocking
    for interface in interfaces:
        if util.port_modes[get_interface_name(interface)] == 'T':
            util.port_states[interface] = 'BLOCKING'
            util.port_result[interface] = 'BLOCKING'
        
    # Only the priorities are considered for BID
    util.bridge_id = int(util.priority)
    util.root_id = int(util.priority)
    
    root_path_cost = 0
   

    # As initially all switches are root, set interfaces as designated
    for interface in interfaces:
        util.port_result[interface] = 'DESIGNATED'

     # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(util.port_modes, interfaces))
    t.start()

    while True:
        interface, data, length = recv_from_any_link() 
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Populate the CAM table with source addresses
        util.cam_table[src_mac] = interface
        curr_port_type = util.port_modes[get_interface_name(interface)]

        # BPDU packet       
        if dest_mac == util.ALL_BRIDGES:
            bdpu_root_bridge_id = int.from_bytes(data[18:20], byteorder='big')
            bdpu_sender_bridge_id = int.from_bytes(data[24:26], byteorder='big')
            bdpu_root_path_cost = int.from_bytes(data[20:24], byteorder='big')

            # Oops, a better root was found?
            if int(bdpu_root_bridge_id) < int(util.root_id):
                # Update info for the new root
                util.root_id = bdpu_root_bridge_id

                # Increase the path cost 
                root_path_cost = bdpu_root_path_cost + 10
                aux = data[:20] + root_path_cost.to_bytes(4, byteorder='big') + data[24:]
                data = aux
                root_port = interface

                # Set all other ports on BLOCKING
                if bdpu_root_bridge_id == util.bridge_id:
                    for port in interfaces:
                        if util.port_modes[get_interface_name(port)] == 'T' and port != root_port:
                            util.port_states[port] = 'BLOCKING'

                # Unblock the root port if necessary
                if util.port_states[root_port] == 'BLOCKING':
                    util.port_states[root_port] = 'LISTENING'

                # Update sender_bridge_id
                aux = data[:24] + int.to_bytes(util.bridge_id, 2, byteorder='big') + data[26:]
                data = aux
                aux = data[:18] + int.to_bytes(util.root_id, 2, byteorder='big') + data[20:]
                data = aux

                for port in interfaces:
                    if util.port_modes[get_interface_name(port)] == 'T' and port != root_port:
                        send_to_link(port, len(data), data)

            # Root was not changed
            elif bdpu_root_bridge_id == util.root_id:

                # If the current interface is the best, just add the link cost
                if interface == root_port and bdpu_root_path_cost + 10 < root_path_cost:
                    root_path_cost = bdpu_root_path_cost + 10

                # Change the route
                elif interface != root_port:
                    if bdpu_root_path_cost > root_path_cost:
                        if util.port_result[interface] != 'DESIGNATED':
                            util.port_result[interface] = 'DESIGNATED'
                            util.port_states[interface] = 'LISTENING'

            # Found a loop, received the packet that switch has already sent         
            elif bdpu_sender_bridge_id == util.bridge_id:
                util.port_states[interface] = 'BLOCKING'
                util.port_result[interface] = 'BLOCKING'

            # What if the current switch is the root? - open its interfaces:)
            if (util.bridge_id == util.root_id):
                for port in interfaces:
                    if util.port_modes[get_interface_name(port)] == 'T':
                        util.port_result[port] = 'DESIGNATED'
                        util.port_states[port] = 'LISTENING'

            continue
        
        # Parse other packets
        if is_unicast(dest_mac):
            # Was this destination already memorised?
            if dest_mac in util.cam_table:
                new_interface = util.cam_table[dest_mac]
                dest_port_type = util.port_modes[get_interface_name(new_interface)]

                # Trunk - Trunk link
                if curr_port_type == 'T' and  dest_port_type == 'T':
                    # Send the data only if STP topology permits it
                    if util.port_states[new_interface] == 'LISTENING':
                        send_to_link(new_interface, len(data), data)

                # Access - Trunk link
                elif curr_port_type != 'T' and dest_port_type == 'T':
                    # Add the VLAN tag
                    tagged_frame = data[0:12] + create_vlan_tag(int(util.port_modes[get_interface_name(interface)])) + data[12:]
                    if util.port_states[new_interface] == 'LISTENING':
                        send_to_link(new_interface, len(tagged_frame), tagged_frame)

                # Trunk - Access link
                elif curr_port_type == 'T' and dest_port_type != 'T':
                    # No need for VLAN tag 
                    shrinked_frame = data[0:12] + data[16:]
                    if (int(dest_port_type) == vlan_id): 
                        send_to_link(new_interface, len(shrinked_frame), shrinked_frame)
                
                # Access - Access link
                else:
                    # Send the same data that was received, no need for further parsing
                    if (curr_port_type == dest_port_type):
                        send_to_link(new_interface, len(data), data)

            # Unicast unknown address, perform a broadcast
            else: 
                for new_interface in interfaces:
                    if new_interface != interface:
                        dest_port_type = util.port_modes[get_interface_name(new_interface)]

                        # Trunk- Trunk
                        if curr_port_type == 'T' and  dest_port_type == 'T':
                            if util.port_states[new_interface] == 'LISTENING':
                                send_to_link(new_interface, len(data), data)

                        # Access - Access
                        elif curr_port_type != 'T' and dest_port_type == 'T':
                            tagged_frame = data[:12] + create_vlan_tag(int(util.port_modes[get_interface_name(interface)])) + data[12:]
                            if util.port_states[new_interface] == 'LISTENING':
                                send_to_link(new_interface, len(tagged_frame), tagged_frame)

                        # Trunk - Access
                        elif curr_port_type == 'T' and dest_port_type != 'T':
                            shrinked_frame = data[0:12] + data[16:]
                            if (int(dest_port_type) == vlan_id): 
                                send_to_link(new_interface, len(shrinked_frame), shrinked_frame)

                        # Access - Access
                        else: 
                            if (curr_port_type == dest_port_type):
                                send_to_link(new_interface, len(data), data)

        else: # Multicast address => broadcast
            for new_interface in interfaces:
                if new_interface != interface:
                    dest_port_type = util.port_modes[get_interface_name(new_interface)]

                    # Trunk - Trunk
                    if curr_port_type == 'T' and  dest_port_type == 'T':
                       # print("INTERFACE" + str(new_interface))
                        if util.port_states[new_interface] == 'LISTENING':
                          #  print("YES")
                            send_to_link(new_interface, len(data), data)
                        
                    # Access - Trunk
                    elif curr_port_type != 'T' and dest_port_type == 'T':
                        tagged_frame = data[:12] + create_vlan_tag(int(util.port_modes[get_interface_name(interface)])) + data[12:]
                        if util.port_states[new_interface] == 'LISTENING':
                            send_to_link(new_interface, len(tagged_frame), tagged_frame)

                    # Trunk - Access
                    elif curr_port_type == 'T' and dest_port_type != 'T':
                        shrinked_frame = data[0:12] + data[16:]
                        if (int(dest_port_type) == vlan_id): 
                            send_to_link(new_interface, len(shrinked_frame), shrinked_frame)
                    
                    # Access - Access
                    else:
                        if (curr_port_type == dest_port_type):
                            send_to_link(new_interface, len(data), data)
            
if __name__ == "__main__":
    main()
