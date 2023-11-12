import struct
import numpy as np
import sys

# Define the file paths
input_file_path = sys.argv[1]

packets = {}
times = {}
start_times = {}
finish_times = {}
end_times = {}
src_ip_all = {}
dest_ip_all = {}
src_ip = {}
dest_ip = {}
src_port_all = {}
dest_port_all ={}
src_ports ={}
dest_ports = {}
src_packets_sent = {}
dest_packets_sent = {}
total_packets_sent = {}
src_bytes_sent = {}
dest_bytes_sent = {}
original_lengths = {}
time_durations = {}
rtt_times = {}

flags = {}
complete_connections = {}

seq_numbers = {}
ack_numbers = {}
offset_numbers = {}
win_sizes = {}
payload_sizes = {}

syn_count ={}
fin_count = {}
ack_count = {}
rst_count = {}

flags_all = {}

num_connections = {}

def connection_availability(src_ip_loc, dest_ip_loc, length, src_port, dest_port, win_size, ind):
    
    for j in src_ip.keys():
        
        if (src_ip[j] == src_ip_loc and dest_ip[j] == dest_ip_loc and \
            src_ports[j] == src_port and dest_ports[j] == dest_port):
            
            total_packets_sent[j] += 1
            src_packets_sent[j] += 1 
            src_bytes_sent[j] += length
            
            win_sizes[ind] = win_size
                
            return True
            
        elif (src_ip[j] == dest_ip_loc and dest_ip[j] == src_ip_loc and \
              src_ports[j] == dest_port and dest_ports[j] == src_port):
            
            total_packets_sent[j] += 1
            dest_packets_sent[j] += 1
            dest_bytes_sent[j] += length

            win_sizes[ind] = win_size
                
            return True

        
    return False
            
               
def set_flags(src_ip_temp, dest_ip_temp, src_port, dest_port, syn, ack, rst, fin):
    
    ind = 0
    
    for i in src_ip.keys():
        if (src_ip_all[i] == src_ip_temp and dest_ip_all[i] == dest_ip_temp and src_ports[i] == src_port and dest_ports[i] == dest_port) or\
           (src_ip[i] == dest_ip_temp and dest_ip[i] == src_ip_temp and src_ports[i] == dest_port and dest_ports[i] == src_port):
            
            ind = i
            break
               
    if syn == 1:
        syn_count[ind]+=1
        flags[ind] = f"S{syn_count[ind]}F{fin_count[ind]}R{rst_count[ind]}"

    if fin == 1:
        fin_count[ind]+=1
        flags[ind] = f"S{syn_count[ind]}F{fin_count[ind]}R{rst_count[ind]}"

    if rst == 1:
        rst_count[ind]+=1
        flags[ind] = f"S{syn_count[ind]}F{fin_count[ind]}R{rst_count[ind]}"
            
    return None


def check_complete(src_ip_temp, dest_ip_temp, src_port, dest_port):
    
    ind = -1
    
    for i in src_ip.keys():
        
        if (src_ip[i] == src_ip_temp and dest_ip[i] == dest_ip_temp and src_ports[i] == src_port and dest_ports[i] == dest_port) or\
           (src_ip[i] == dest_ip_temp and dest_ip[i] == src_ip_temp and src_ports[i] == dest_port and dest_ports[i] == src_port):
            
            ind = i
            break
        
            
    if ind >= 0 and syn_count[ind] >= 1 and fin_count[ind] >= 1:
        complete_connections[ind] = True
        return True
    
    else:
        
        return False
    
    return False

def calculate_RTT():
    
    picked_indexes = {}
    counter = 0
         
    for i in range(len(seq_numbers)):
        
        if i not in picked_indexes.values():
        
            for j in range(i+1, len(ack_numbers)):

                if j not in picked_indexes.values():

                    if (src_ip_all[i] == dest_ip_all[j] \
                       and dest_ip_all[i] == src_ip_all[j] \
                       and src_port_all[i] == dest_port_all[j] \
                       and dest_port_all[i] == src_port_all[j]) \
                       and check_complete(src_ip_all[i], dest_ip_all[i],  src_port_all[i],  dest_port_all[i]) == True:

                        if flags_all[i][0] == "0" and \
                           flags_all[j][0] == "0" and \
                           flags_all[j][1] == "1" and \
                           flags_all[i][1] == "1" and \
                           any(ei == "1" for ei in flags_all[i][2:]) and  \
                           all(ej == "0" for ej in flags_all[j][2:]) and \
                           ack_numbers[j] == (seq_numbers[i] + payload_sizes[i]):
                            
                            rtt_times[i] = times[j] - times[i]
                            picked_indexes[counter] = i
                            picked_indexes[counter + 1] = j
                            counter += 2
                            break
                            
                        elif flags_all[i][0] == "0" and \
                             flags_all[j][0] == "0" and \
                             flags_all[i][1] == "0" and \
                             flags_all[j][1] == "1" and \
                             flags_all[j][2] == "1" and \
                             flags_all[i][2] == "1" and \
                             ack_numbers[j] == (seq_numbers[i] + 1):
                            
                            
                            rtt_times[i] = times[j] - times[i]
                            picked_indexes[counter] = i
                            picked_indexes[counter + 1] = j
                            counter += 2
                            break
                            
   
                        elif flags_all[i][0] == "0" and \
                             flags_all[j][0] == "0" and \
                             flags_all[i][1] == "1" and \
                             flags_all[j][1] == "1" and \
                             flags_all[i][4] == "1" and \
                             (flags_all[j][4] == "1" or flags_all[j][4] == "0") and \
                             ack_numbers[j] == (seq_numbers[i] + 1):
                            

                            rtt_times[i] = times[j] - times[i]
                            picked_indexes[counter] = i
                            picked_indexes[counter + 1] = j
                            counter += 2
                            break
                        
                                                                             
    return None


def output_data_AB():
    
    prev_st = start_times[0]

    
    print(f"A) Total number of connections: {len(src_ip)}")
    print("________________________________________________")
    print()
    j = 1
    
    print("B) Connections Details")
    print()
    
    for i in src_ip.keys():
        
        print(f"Connection {j}: ")
        print(f"Source address: {src_ip[i]}" )
        print(f"Destination address: {dest_ip[i]}")
        print(f"Source port: {src_ports[i]}")
        print(f"Destination port: {dest_ports[i]}")

        
        if check_complete(src_ip[i], dest_ip[i], src_ports[i], dest_ports[i]) == True:
            
            print(f"Status: {flags[i]}")
            print(f"Start time: {round(abs(start_times[i] - prev_st), 6)}" + " seconds")
           
            
            if i in finish_times.keys():
                
                duration = round(finish_times[i] - start_times[i], 4)
                
                print(f"End time: {round(abs(start_times[i] - prev_st) + duration, 6)}" + " seconds")
                print(f"Duration: {duration} seconds")
                
                time_durations[i] = duration
                
            else:
                
                duration = round(finish_times[i] - start_times[i], 4)
                
                print(f"End time: {round(abs(start_times[i] - prev_st) + duration, 6)}" + " seconds")
                print(f"Duration: {round(duration, 6)} seconds")
                time_durations[i] = duration
            
            prev_st = start_times[i]
            
            print(f"Number of packets sent from Source to Destination: {src_packets_sent[i]}")
            print(f"Number of packets sent from Destination to Source: {dest_packets_sent[i]}")
            print(f"Total number of packets: {total_packets_sent[i]}")
            print(f"Number of bytes sent from Source to Destination: {src_bytes_sent[i]}")
            print(f"Number of bytes sent from Destination to Source: {dest_bytes_sent[i]}")
            print(f"Total number of bytes: {src_bytes_sent[i] + dest_bytes_sent[i] }")
            

        j += 1
        print("END")
        print("++++++++++++++++++++++++++++++++")
        
        
    return None

def output_data_C():
    
    print("________________________________________________")
    print()
    print("C) General")
    print()
    print(f"Total number of complete TCP connections: {len([c for c in complete_connections.values() if c == True])} connections")
    print(f"Number of reset TCP connections: {len([r for r in rst_count.values() if r >= 1])} connections")
    print(f"Number of TCP connections that were still open when the trace capture ended: {len([f for f in fin_count.values() if f == 0])} connections")
    
    return None
    
def output_data_D():
    print("________________________________________________")
    print()
    print("D) Complete TCP connections: ")
    print()
    print(f"Minimum time duration: {round(min(time_durations.values()), 6)} seconds")
    print(f"Mean time duration: {round(np.average(list(time_durations.values())), 6)} seconds")
    print(f"Maximum time duration: {round(max(time_durations.values()), 6)} seconds")
    
    
    #RTT output for later

    complete_connections_packets = {}
    complete_connections_win_sizes = {}
    
    for i in complete_connections.keys():
        if complete_connections[i] == True:
            complete_connections_packets[i] = total_packets_sent[i]
            
    
    for j in src_ip_all.keys():
        if check_complete(src_ip_all[j], dest_ip_all[j],  src_port_all[j],  dest_port_all[j]) == True :
            complete_connections_win_sizes[j] = win_sizes[j]

    print()
    
    if(len(complete_connections_packets.values()) > 0):
        
        print("Minimum number of packets including both send/received: ", round(min(complete_connections_packets.values()), 6), " packets")
        print("Mean number of packets including both send/received: ", round(np.average(list(complete_connections_packets.values())), 6), " packets")
        print("Maximum number of packets including both send/received: ", round(max(complete_connections_packets.values()), 6), " packets")
    
    print()
    
    if(len(rtt_times.values()) > 0):
        
        print("Minimum RTT value: ", round(min(rtt_times.values()), 6), " seconds")
        print("Mean RTT value: ", round(np.average(list(rtt_times.values())), 6), " senonds")
        print("Maximum RTT value: ", round(max(rtt_times.values()), 6), " seconds")
    
    print()
    
    if(len(complete_connections_win_sizes.values()) > 0): 
        
        print("Minimum recieve window size including both send/received: ", min(complete_connections_win_sizes.values()), " bytes")
        print("Mean recieve window size including both send/received: ", round(np.average(list(complete_connections_win_sizes.values())), 6), " bytes")
        print("Maximum recieve window size including both send/received: ", max(complete_connections_win_sizes.values()), " bytes")

    return None
    


def get_start_end_time():
    
    cap2_file = open(input_file_path, "rb")
    
    
    global_header= cap2_file.read(24)
    
    magic_num = str(global_header[0:4].hex())
    read_ident = ">"
    
    if magic_num == "d4c3b2a1":
        
        read_ident = ">"
        
    else:
        
        read_ident = "<"
        
    check_first = 0

    
    for j in src_ip.keys():
                   
                   
        for i in packets.keys():

            
            src_ip_temp = ".".join(tuple(str(x) for x in struct.unpack("<4B", packets[i][26:30])))
            dest_ip_temp = ".".join(tuple(str(x) for x in struct.unpack("<4B", packets[i][30:34])))

            
            ip_length = (int(packets[i][14:15].hex(), 16)) & 0xF
            ip_length = int((ip_length * 32) / 8)
            
            tcp_header_start = ip_length + 14
            result = struct.unpack(f"{read_ident}B", packets[i][tcp_header_start + 13: tcp_header_start + 14])[0]
            binary_flag = bin(result)[2:].zfill(8)
            syn = binary_flag[6]
            fin = binary_flag[7]
        
            src_port_temp = struct.unpack(f"{read_ident}H", packets[i][tcp_header_start: tcp_header_start + 2])[0]
            dest_port_temp = struct.unpack(f"{read_ident}H", packets[i][tcp_header_start + 2: tcp_header_start + 4])[0]
            
            if (src_ip[j] == src_ip_temp and dest_ip[j] == dest_ip_temp and src_ports[j] == src_port_temp  and dest_ports[j] == dest_port_temp ) or \
               (src_ip[j] == dest_ip_temp and dest_ip[j] == src_ip_temp and src_ports[j] == dest_port_temp  and dest_ports[j] == src_port_temp):
                
                if syn == "1" and check_first == 0:
                    
                    check_first = 1
                    start_times[j] = times[i]
                   
                elif fin == "1":
                   
                   finish_times[j] = times[i]
                
                            
        check_first = 0
        
                
    return None


def extract_data():
    
    cap_file = open(input_file_path, "rb")
    
    global_header= cap_file.read(24)
    
    magic_num = str(global_header[0:4].hex())
    read_ident = ">"
    
    if magic_num == "d4c3b2a1":
        
        read_ident = ">"
        
    else:
        
        read_ident = "<"
        
    
    i = 0

    while True:

        packet_header = cap_file.read(16)

        if(len(packet_header) == 0):
            break

        times[i] = struct.unpack(f"{read_ident}L", packet_header[0:4][::-1]) 
        times[i] = round(times[i][0] + struct.unpack(f"{read_ident}L", packet_header[4:8][::-1])[0] * 0.000001, 5)

        packet_data_length = packet_header[8:12]
        packet_data_length = struct.unpack(f"{read_ident}L",packet_data_length[::-1])
        original_lengths[i] = struct.unpack(f"{read_ident}L",packet_header[12:16][::-1])

        packet_data = cap_file.read(packet_data_length[0])
        packets[i] = packet_data

        i += 1



    i = 0
  
    ip_length = (int(packets[i][14:15].hex()[1:]))

    ip_length = int((ip_length * 32) / 8)
    
    
    while True:

        if i >= len(packets) or len(packets[i]) == 0:
            break
            

            
        src_ip_temp = ".".join(tuple(str(x) for x in struct.unpack("<4B", packets[i][26:30])))
        dest_ip_temp = ".".join(tuple(str(x) for x in struct.unpack("<4B", packets[i][30:34])))
            
     
               
        src_ip_all[i] =  src_ip_temp
        dest_ip_all[i] =  dest_ip_temp
        
        tcp_header_start = ip_length + 14

        result = struct.unpack(f"{read_ident}B", packets[i][tcp_header_start + 13: tcp_header_start + 14])[0]
        binary_flag = bin(result)[2:].zfill(8)

        src_port_temp = struct.unpack(f"{read_ident}H", packets[i][tcp_header_start: tcp_header_start + 2])[0]
        dest_port_temp = struct.unpack(f"{read_ident}H", packets[i][tcp_header_start + 2: tcp_header_start + 4])[0]
        
        src_port_all[i] = src_port_temp
        dest_port_all[i] = dest_port_temp
        
        seq_numbers[i] = struct.unpack(f"{read_ident}I", packets[i][tcp_header_start + 4: tcp_header_start + 8])[0]
        ack_numbers[i] = struct.unpack(f"{read_ident}I", packets[i][tcp_header_start + 8: tcp_header_start + 12])[0]

        offset_numbers[i] = struct.unpack(f"{read_ident}B", packets[i][tcp_header_start + 12: tcp_header_start + 13])[0]
        win_size = struct.unpack(f"{read_ident}H", packets[i][tcp_header_start + 14: tcp_header_start + 16])[0]

        payload_start_loc = (offset_numbers[i] >> 4) * 4
        
        payload_size = len(packets[i]) - payload_start_loc - tcp_header_start
        payload_sizes[i] = payload_size


        if connection_availability(src_ip_temp, dest_ip_temp, payload_sizes[i], src_port_temp, dest_port_temp, win_size, i) == False:
            
            win_sizes[i] = win_size
            src_ip[i] = src_ip_temp
            dest_ip[i] = dest_ip_temp
            src_ports[i] = src_port_temp
            dest_ports[i] = dest_port_temp
            total_packets_sent[i] = 0
            src_packets_sent[i] = 1
            dest_packets_sent[i] = 0
            src_bytes_sent[i] =  payload_sizes[i]
            dest_bytes_sent[i] = 0
            syn_count[i] = 0
            ack_count[i] = 0
            rst_count[i] = 0
            fin_count[i] = 0
            complete_connections[i] = False

        
        flags_all[i] = binary_flag[5] + binary_flag[3] + binary_flag[6] + binary_flag[4] + binary_flag[7]
        
        syn = int(binary_flag[6])  
        ack = int(binary_flag[3])
        
        psh = int(binary_flag[4])
        ece = int(binary_flag[1])
        urg = int(binary_flag[2])
        cwr = int(binary_flag[0])
        
        rst = int(binary_flag[5]) 
        fin = int(binary_flag[7])

        i += 1

        set_flags(src_ip_temp, dest_ip_temp, src_port_temp, dest_port_temp, syn, ack, rst, fin)
        
        


def main():
    
    try:
        
        extract_data()
        get_start_end_time()

        calculate_RTT()

        output_data_AB()
        output_data_C()
        output_data_D()
        
    except Exception as e:
        
        print("Error Occured: Unexpected Behaviour!!")
        print(e)

main()
