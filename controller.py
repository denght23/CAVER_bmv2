#!/usr/bin/env python2
import argparse, re, grpc, os, sys, json, subprocess
import networkx as nx
from collections import deque, defaultdict

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import p4runtime_lib.helper

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.convert import decodeMac, decodeIPv4
from switch_utils import printGrpcError,load_topology,run_ssc_cmd

# Turn on dry run mode
debug = True
max_port = 2 
max_hop = 4

# Generate a simple UID for dst_id of each host
def host_to_dst_id(hosts):
    return dict(list(zip(hosts, list(range(1, len(hosts) + 1)))))

def mcast_grp_command(mcast_id, port_ids, handle_id):
    port_seq = " ".join(str(e) for e in port_ids)
    create = "mc_mgrp_create " + str(mcast_id) 
    node = "mc_node_create 0 " + port_seq
    assoc = "mc_node_associate " + str(mcast_id) + " " + str(handle_id)
    return create + "\n" + node + "\n" + assoc

def generate_ECMP_choose_table(mn_topo, p4info_helper, switches):
    for sw in mn_topo.switches():
        for i in range(max_port):
            ECMP_entry = p4info_helper.buildTableEntry(
                table_name=f"MyIngress.ECMP_choose_table",
                match_fields = {
                    "meta.hash_result": i
                },
                action_name = f"MyIngress.ECMP_choose_Port_{i}",
                action_params = {}
            )
            switches[sw].WriteTableEntry(ECMP_entry, debug)

def generate_SrcRoute_Table(mn_topo, p4info_helper, switches):
    for sw in mn_topo.switches():
        for i in range(max_hop):
            SrcRoute_entry = p4info_helper.buildTableEntry(
                table_name=f"MyIngress.SrcRoute_Table",
                match_fields = {
                    "hdr.caver_data.hopCountt": i
                },
                action_name = f"MyIngress.SrcRoute_choose_Port_{i}",
                action_params = {}
            )
            switches[sw].WriteTableEntry(SrcRoute_entry, debug)
        
def generate_ToR_host_Table(mn_topo, p4info_helper, switches):
    ToR_host_dict = {}
    for (x, y) in mn_topo.links():
        switch = None
        host= None
        if x.startswith("h") and y.startswith("s"):
            switch = y
            host = x
        elif y.startswith("h") and x.startswith("s"):
            switch = x
            host = y
        else:
            continue
        if switch not in ToR_host_dict:
            ToR_host_dict[switch] = []
        host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0]   
        if host_ip not in ToR_host_dict[switch]:
            ToR_host_dict[switch].append(host_ip)
        
    for sw in ToR_host_dict:
        for host_ip in ToR_host_dict[sw]:
            ToR_host_entry = p4info_helper.buildTableEntry(
                table_name=f"MyIngress.ToR_host_Table",
                match_fields = {
                    "hdr.ipv4.dstAddr": host_ip
                },
                action_name = f"MyIngress.set_dstToR",
                action_params = {}
            )
            switches[sw].WriteTableEntry(ToR_host_entry, debug)

def generate_Host_ip_2_id(mn_topo, p4info_helper, switches, host_list):
    for switch in mn_topo.switches():
        for host in host_list:
            host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0] 
            Host_entry = p4info_helper.buildTableEntry(
                table_name=f"MyIngress.Host_ip_2_id",
                match_fields = {
                    "meta.host_addr": host_ip
                },
                action_name = f"MyIngress.get_host_id",
                action_params = {
                    "host_id": int(host[1:])
                }
            )
            switches[switch].WriteTableEntry(Host_entry, debug)

def generate_Routing_Table(mn_topo, host_list, p4info_helper, switches):
    G = nx.Graph()
    G.add_edges_from(mn_topo.links())
    nextHop = {}# 数据结构，next[node][host] = [n1, n2, n3] 
    outPort_table = {}# 数据结构，outPort_table[node][host] = [p1, p2, p3] 
    for switch in mn_topo.switches():
        nextHop[switch] = {}
    for switch in mn_topo.switches():
        outPort_table[switch] = {}
    #BFS
    for host in host_list:
        host_next_hop = CalculateRoute(host, mn_topo)
        for switch in mn_topo.switches():
            nextHop[switch][host] = host_next_hop[switch]
    ######将下一跳转化为对应的出端口
    for host in host_list:
        for switch in mn_topo.switches():
            outPort_table[switch][host] = []
            for next_hop in nextHop[switch][host]:
                outPort_table[switch][host].append(mn_topo.port(switch, next_hop)[0])
                
    for switch in mn_topo.switches():
        print("switch: ", switch)
        for host in host_list:
            host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0]
            action_params = {}
            for i in range(len(outPort_table[switch][host])):
                action_params["port" + str(i)] = outPort_table[switch][host][i]
            Port_entry = p4info_helper.buildTableEntry(
                table_name=f"MyIngress.Routing_Table",
                match_fields = {
                    "hdr.ipv4.dstAddr": host_ip
                },
                action_name = f"MyIngress.get_{len(outPort_table[switch][host])}_port",
                action_params = action_params
            )
            switches[switch].WriteTableEntry(Port_entry, debug)
    return outPort_table
    
    

def CalculateRoute(host, mn_topo):
    host_next_hop = {}
    for switch in mn_topo.switches():
        host_next_hop[switch] = []
    queue = [(host, 0)]
    shortest_distance = {}
    shortest_distance[host] = 0
    G = nx.Graph()
    G.add_edges_from(mn_topo.links())
    while queue:
        current, dist = queue.pop(0)
        adjacents = [a[1] for a in G.edges(current)]
        for neighbor in adjacents:
            if "s" in neighbor:
                if neighbor not in shortest_distance or dist + 1 < shortest_distance[neighbor]:
                    shortest_distance[neighbor] = dist + 1
                    queue.append((neighbor, dist + 1))
                    host_next_hop[neighbor].append(current)
                elif dist + 1 == shortest_distance[neighbor]:
                    host_next_hop[neighbor].append(current)
    return host_next_hop
                        
def install_smart_mcast(mn_topo, switches, p4info_helper):
    # Note(rachit): Hosts are always considered downstream.
    def is_upstream(x, y):
        return x[0] == y[0] and int(x[1]) < int(y[1])

    G = nx.Graph()
    G.add_edges_from(mn_topo.links())
    # Generate mcast commands and store them in config/<switch>
    for switch in mn_topo.switches():
        command = ""
        adjacents = [__a[1] for __a in G.edges(switch)]
        for adj in adjacents:
            mcast_adjs = None
            # If the packet came from an upstream link, cast it to only downstream links
            if is_upstream(switch, adj):
                mcast_adjs = [a for a in adjacents if not is_upstream(switch, a)]
            # If the packet came from a downstream link, cast it at all other links.
            else:
                mcast_adjs = [a for a in adjacents if a != adj]

            mcast_ports = [mn_topo.port(switch, a)[0] for a in mcast_adjs]
            ingress_port = mn_topo.port(switch, adj)[0]
            cmd = mcast_grp_command(ingress_port, mcast_ports,
                                    switches[switch].getAndUpdateHandleId())
            command += (cmd + "\n")
        # Execute mcast setup
        print(run_ssc_cmd(switch, command))

def install_hula_logic(mn_topo, switches, p4info_helper):
    for sw in mn_topo.switches():
        add_hula_handle_probe = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x42
            },
            action_name = "MyIngress.hula_handle_probe",
            action_params = {
        })
        add_hula_handle_data_packet = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x06
            },
            action_name = "MyIngress.hula_handle_data_packet",
            action_params = {
        })
        add_hula_handle_data_packet_icmp = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x01
            },
            action_name = "MyIngress.hula_handle_data_packet_icmp",
            action_params = {
        })
        add_hula_handle_data_packet_udp = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x11
            },
            action_name = "MyIngress.hula_handle_data_packet_udp",
            action_params = {
        })
        switches[sw].WriteTableEntry(add_hula_handle_probe, debug)
        switches[sw].WriteTableEntry(add_hula_handle_data_packet, debug)
        switches[sw].WriteTableEntry(add_hula_handle_data_packet_icmp, debug)
        switches[sw].WriteTableEntry(add_hula_handle_data_packet_udp, debug)

def install_tables(mn_topo, switches, p4info_helper):
    # Install entries for hula_logic
    install_hula_logic(mn_topo, switches, p4info_helper)
    # Install rule to map each host to dst_tor
    for (x, y) in mn_topo.links():
        switch = None
        host= None
        if x.startswith("h") and y.startswith("s"):
            switch = y
            host = x
        elif y.startswith("h") and x.startswith("s"):
            switch = x
            host = y
        else:
            continue
        host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0]
        host_mac = mn_topo.nodeInfo(host)['mac']
        dst_tor_num = int(switch[1:])
        port = mn_topo.port(switch, host)[0]

        # Install entries for edge forwarding.
        add_edge_forward = p4info_helper.buildTableEntry(
            table_name="MyIngress.edge_forward",
            match_fields = {
                "hdr.ipv4.dstAddr": host_ip
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": port,
                "dstAddr": host_mac # should be MAC address of the host
            })
        switches[switch].WriteTableEntry(add_edge_forward, debug)

        for sw in mn_topo.switches():
            self_id = int(sw[1:])
            # Install entries to calculate get_dst_tor
            add_host_dst_tor = p4info_helper.buildTableEntry(
                table_name="MyIngress.get_dst_tor",
                match_fields = {
                    "hdr.ipv4.dstAddr": host_ip
                },
                action_name="MyIngress.set_dst_tor",
                action_params={
                    "dst_tor": dst_tor_num,
                    "self_id": self_id
                })
            switches[sw].WriteTableEntry(add_host_dst_tor, debug)

def generate_host_id_2_ip_file(mn_topo, host_list):
    host_id_2_ip = {}
    for host in host_list:
        host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0]
        host_id_2_ip[host] = host_ip
    with open('host_id_2_ip.json', 'w') as f:
        json.dump(host_id_2_ip, f)

def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Load the topology from the JSON file
        switches, mn_topo = load_topology(topo_file_path)
        
        ####获取服务器的列表
        with open(topo_file_path) as topo_data:
            j = json.load(topo_data)
        host_list = j['hosts']

        # Establish a P4 Runtime connection to each switch
        for bmv2_switch in list(switches.values()):
            bmv2_switch.MasterArbitrationUpdate()
            print("Established as controller for %s" % bmv2_switch.name)

        # Load the P4 program onto each switch
        for bmv2_switch in list(switches.values()):
            bmv2_switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                    bmv2_json_file_path=bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on %s" % bmv2_switch.name)


        generate_Routing_Table(mn_topo, host_list, p4info_helper, switches)
        generate_Host_ip_2_id(mn_topo, p4info_helper, switches, host_list)
        generate_ToR_host_Table(mn_topo, p4info_helper, switches)
        generate_SrcRoute_Table(mn_topo, p4info_helper, switches)
        generate_ECMP_choose_table(mn_topo, p4info_helper, switches)
        generate_host_id_2_ip_file(mn_topo, host_list)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/CAVER.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/CAVER.json')
    parser.add_argument('--topo', help='Topology file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    if not os.path.exists(args.topo):
        parser.print_help()
        print("\nTopology file not found: %s" % args.topo)
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo)
