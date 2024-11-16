1 2 3

##### Copyright 2024 Alexandru-Andrei CRET - 335CA (**alexandru.cret@stud.acs.upb.ro**)

# Homework #1 - Switch Implementation

The purpose of this project is to implement the basic functionality of a switch, responsible for forwarding layer-2 frames in a LAN. It offers support for VLAN and STP. The relevant code was written in **Python**.

## Project Structure

+ **switch.py**: main functionality of a switch
+ **utils.py**: constants and variables intended to work as globals
+ **wrapper.py**: wrappers over C functions for networking
+ **configs/***: hardcoded configurations of the three switches


## Switch Configuration
Every switch has its own hardcoded information about its priority and interfaces. This part of the code is responsible for populating the **port_modes** hashmap, which stores the interfaces' type: **trunk** or **access** (in that case the VLAN id is saved).


## Content Addressable Memory (CAM Table)

The first step of this project was the simple forwarding of frames sent from one host to another without anyrestrictions. An initial implementation looked like this:
```Python
    # Save source in CAM Table
    cam_table[src_mac] = interface
    curr_port_type = port_modes[get_interface_name(interface)]

    # Simple compare function
    if is_unicast(dest_mac): 
        if dest_mac in cam_table:
            new_interface = cam_table.get(dest_mac)
            send_to_link(new_interface, len(data), data)
        # Address not in the table? => broadcast
        else:
            for new_interface in interfaces:
                if new_interface != interface:
                    send_to_link(new_interface, len(data), data)

    # Multicast and Broadcast addresses
    else:
        for new_interface in interfaces:
            if new_interface != interface:
                send_to_link(new_interface, len(data), data)

```

The other tasks used this code as a starting point, as the forwarding process remains largely the same. The main loop contains **recv_from_any_link** blocking function which retrieves data from any open interface. The frame is then parsed by the already given function, **parse_ethernet_header**.

# VLAN

Things got complicated pretty easily as more logic had to be implemented. As the 802.1q Ethernet format is not present by default on a frame sent from a host, I identified four possible cases of data forwarding:

+ **Trunk - Trunk**: the VLAN header is present and frame integrity should not be affected
+ **Trunk - Access**: no need for the VLAN header, send a shrinked frame instead, only if the VLAN id of the packet corresponds to the link's VLAN id
+ **Access - Trunk**: add the VLAN header and send a tagged frame instead, only if the VLAN of the packet corresponds to the link's VLAN id
+ **Access - Access**: 802.1q not present, just send the packet if the VLAN IDs correspond

**port_modes** hashmap was relevant for a valid implementation.


## Spanning Tree Protocol

An extensive description of the algorithm that i used can be found in the [homework's description](https://ocw.cs.pub.ro/courses/rl/teme/tema1_sw).

**port_result** stores if the current port is DESIGNATED or BLOCKING and **port_states** saves the current state of each trunk port. In order to send a BPDU packet correctly on the second thread, **bdpu_packet** class was used to simulate a structure, similar to the ones in C. **BPDU CONFIG** values are the [default](https://youtu.be/japdEY1UKe4?t=975) ones.
The constructor saves the correct amount of bytes so that the packet could be sent correctly. Once a BPDU packet was received on an interface, I identified each field thanks to **Wireshark**. After the topology convergence, a packet could be sent on a specific interface only if it was not in a BLOCKING state.

