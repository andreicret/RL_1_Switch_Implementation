SWITCH_FILES = {
    '0' : 'configs/switch0.cfg',
    '1' : 'configs/switch1.cfg',
    '2' : 'configs/switch2.cfg'
}

cam_table = {}
port_modes = {}
port_states = {}
port_result = {}

priority = 1
bridge_id = 0
root_id = 0
ALL_BRIDGES = "01:80:c2:00:00:00"
ALL_BRIDGES_BYTE = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
LLC_HEADER = bytes([0x42, 0x42, 0x03]) 
LLC_LENGTH = int.to_bytes(38, 2, byteorder='big')
BDPU_HEADER = bytes([0x00, 0x00])