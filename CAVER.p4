/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> port_id_t;
typedef bit<8> util_t;
typedef bit<24> tor_id_t;
typedef bit<48> time_t;
typedef bit<32> port_num;
typedef bit<4> CE_t;
typedef bit<32> Dre_t;
typedef bit<32> host_id_t;
typedef bit<8> shift_t;
/* Constants about the topology and switches. */
const port_id_t NUM_PORTS = 255;
const tor_id_t NUM_TORS = 512;
const bit<32> EGDE_HOSTS = 4; 
const bit<32> NUM_FLOWS= 4096;
const bit<32> NUM_HOSTS= 128;
/* Declaration for the various packet types. */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_TCP = 0x06;
const bit<8> PROTO_UDP = 0x11;

const bit<8> PROTO_ACK = 0x43;
const bit<8> PROTO_CAVER_ACK = 0x44;
const bit<8> PROTO_CAVER_DATA = 0x42;

/* Tracking things for flowlets */
// const time_t FLOWLET_TOUT = 48w1 << 3;
const time_t FLOWLET_TOUT = 48100000;
const util_t PROBE_FREQ_FACTOR = 6;
const time_t KEEP_ALIVE_THRESH = 48w1 << PROBE_FREQ_FACTOR;

const time_t PROBE_FREQ = 48w1 << PROBE_FREQ_FACTOR; // Here for documentation. Unused.


const time_t CE_reduce_gap = 256; //微秒
const shift_t CE_reduce_gap_math = 8;
//CE_reduce_gap = 2 ** CE_reduce_gap_math
const shift_t CE_reduce_alpha = 2;
const Dre_t alpha_con = 3; 
//alpha = 0.25
//x *(1-alpha) = (x >> CE_reduce_alpha) * alpha_con
const shift_t link_rate = 3; 
const shift_t m_quantizeBit = 3;
// 2**link_rate  (Mbps)
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
// 这里的包头使用了一个简单的，与真实协议不同的版本，后续需要修改；
header hula_t {
    bit<24> dst_tor;
    bit<8> path_util;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seq;
  bit<32> ack;
  bit<4> dataofs;
  bit<3> reserved;
  bit<9> flags;
  bit<32> window;
  bit<16> chksum;
  bit<16> urgptr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}
header ACK_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
    bit<8> seq;
}
header CAVER_data_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;

    port_id_t hop_0;
    port_id_t hop_1;
    port_id_t hop_2;
    port_id_t hop_3;
    bit<7> hopCount;
    bit<1> SrcRoute;
}
header CAVER_ack_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
    bit<8> seq; 
    
    port_id_t hop_0;
    port_id_t hop_1;
    port_id_t hop_2;
    port_id_t hop_3;
    bit<8> pathCE;
}

struct metadata {
    bit<1> m_isSrcToR;
    bit<1> m_isDstToR;
    bit<8> hash_result;
    port_id_t ECMP_port;
    // 转发表中可能的下一跳；
    port_id_t port_0;
    port_id_t port_1;
    port_id_t SrcRoute_port;
    ip4Addr_t host_addr;//ACK的源host，数据包的dstHost
    host_id_t host_id;//ACK的源host，数据包的dstHost

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t       udp;
    ACK_t       ack;
    CAVER_data_t caver_data;
    CAVER_ack_t caver_ack;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
// TODO: PARSER需要修改
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ACK: parse_ack;
            PROTO_CAVER_DATA: parse_caver_data;
            PROTO_CAVER_ACK: parse_caver_ack;
            default: accept;
        }
    }
    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp{
        meta.host_addr = hdr.ipv4.dstAddr;
        meta.m_isSrcToR = 1;
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_ack{
        meta.host_addr = hdr.ipv4.srcAddr;
        meta.m_isSrcToR = 1;
        packet.extract(hdr.ack);
        transition accept;
    }
    state parse_caver_data{
        meta.host_addr = hdr.ipv4.dstAddr;
        meta.m_isSrcToR = 0;
        packet.extract(hdr.caver_data);
        transition accept;
    }
    state parse_caver_ack{
        meta.host_addr = hdr.ipv4.srcAddr;
        meta.m_isSrcToR = 0;
        packet.extract(hdr.caver_ack);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /****** Registers for flowlet related *******/
    register<time_t>((bit<32>) NUM_FLOWS) flowlet_time;
    register<bit<1>>((bit<32>) NUM_FLOWS) flowlet_SrcRoute;
    register<port_id_t>((bit<32>) NUM_FLOWS) flowlet_SrcRoute_hop_0;
    register<port_id_t>((bit<32>) NUM_FLOWS) flowlet_SrcRoute_hop_1;
    register<port_id_t>((bit<32>) NUM_FLOWS) flowlet_SrcRoute_hop_2;
    register<port_id_t>((bit<32>) NUM_FLOWS) flowlet_SrcRoute_hop_3;
    /****** Registers for pathCE related and SrcRoute related *******/

    register<port_id_t>((host_id_t) NUM_HOSTS) SrcRoute_hop_0_reg;
    register<port_id_t>((host_id_t) NUM_HOSTS) SrcRoute_hop_1_reg;
    register<port_id_t>((host_id_t) NUM_HOSTS) SrcRoute_hop_2_reg;
    register<port_id_t>((host_id_t) NUM_HOSTS) SrcRoute_hop_3_reg;

    register<CE_t>((host_id_t) NUM_HOSTS)pathCE_egress;//储存路径的CE值(量化后)
    register<bit<1>>((host_id_t) NUM_HOSTS)SrcRoute_valid;//1：记录了到达该host的路径，0：未记录
    /****** Registers for portCE related *******/

    register<Dre_t>((bit<32>) NUM_PORTS) portCE_egress; //记录每端口的未量化的CE值
    register<time_t>((bit<32>) NUM_PORTS) portCE_reduce_time_egress;//portCE定期reduce使用；

    action drop() {
        mark_to_drop(standard_metadata);
    }
    //根据目的ip地址，确定目的的host id； 
    action get_host_id(host_id_t host_id){
        meta.host_id = (host_id_t)host_id;
    }
    action host_not_found(){
        meta.host_id = 128;//apply时丢弃
        drop();
    }
    table Host_ip_2_id {
        key= {
          meta.host_addr: exact;
        }
        actions = {
          get_host_id;
          host_not_found;
        }
        default_action = host_not_found;
    }

    // 判断本交换机是否是dstToR
    action  set_dstToR(){
        meta.m_isDstToR = 1;
    }
    action set_non_dstToR(){
        meta.m_isDstToR = 0;
    }
    table ToR_host_Table{
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_dstToR;
            set_non_dstToR;
        }
        default_action = set_non_dstToR;
    }

    //路由表相关，获取如果采用ECMP时的出端口；
    // usage:Routing_Table.apply + ECMP_choose_table.apply
    action get_1_port(port_id_t port_0){
        meta.port_0 = port_0;
        meta.port_1 = 255;
        meta.hash_result = 0;
    }
    action get_2_port(port_id_t port_0, port_id_t port_1){
        meta.port_0 = port_0;
        meta.port_1 = port_1;
        hash(meta.hash_result,
            HashAlgorithm.crc16,
            32w0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
            32w2);
    }
    action get_0_port(){
        meta.port_0 = 255;
        meta.port_1 = 255;
        meta.hash_result = 255;
        
    }
    table Routing_Table{
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            get_1_port;
            get_2_port;
            get_0_port;
        }
        default_action = get_0_port;
    }
    action ECMP_choose_Port_0(){
        meta.ECMP_port = meta.port_0;
    }
    action ECMP_choose_Port_1(){
        meta.ECMP_port = meta.port_1;
    }
    action non_ECMP_Port(){
        meta.ECMP_port = 255;
    }
    table ECMP_choose_table{
        key = {
            meta.hash_result: exact;
        }
        actions = {
            ECMP_choose_Port_0;
            ECMP_choose_Port_1;
            non_ECMP_Port;
        }
        default_action = non_ECMP_Port;
    }
    action SrcRoute_choose_Port_0(){
        meta.SrcRoute_port = (port_id_t) hdr.caver_data.hop_0;
    }
    action SrcRoute_choose_Port_1(){
        meta.SrcRoute_port = (port_id_t) hdr.caver_data.hop_1;
    }
    action SrcRoute_choose_Port_2(){
        meta.SrcRoute_port = (port_id_t) hdr.caver_data.hop_2;
    }
    action SrcRoute_choose_Port_3(){
        meta.SrcRoute_port = (port_id_t) hdr.caver_data.hop_3;
    }
    action non_SrcRoute_Port(){
        meta.SrcRoute_port = (port_id_t) 255;
    }

    table SrcRoute_Table{
        key = {
            hdr.caver_data.hopCount: exact;
        }
        actions = {
            SrcRoute_choose_Port_0;
            SrcRoute_choose_Port_1;
            SrcRoute_choose_Port_2;
            SrcRoute_choose_Port_3;
            non_SrcRoute_Port;
        }
        default_action = non_SrcRoute_Port;
    }

    apply {
        drop(); 
        // 获得ECMP的出端口；
        Routing_Table.apply();
        ECMP_choose_table.apply();
        // 判断本交换机是否是DstToR，若是则直接转发
        ToR_host_Table.apply();
        // 读取host_id
        Host_ip_2_id.apply();
        if (((bool) meta.m_isDstToR) && ((bool) meta.m_isSrcToR)){
            standard_metadata.egress_spec = (bit<9>)meta.ECMP_port;
            if ((hdr.caver_data.isValid() || hdr.udp.isValid()) && meta.host_id != 128){
                                    // 更新PortCE;
                Dre_t ori_port_CE;
                portCE_egress.read(ori_port_CE, (bit<32>)standard_metadata.egress_spec);
                ori_port_CE = ori_port_CE + standard_metadata.packet_length;
                time_t curr_time = standard_metadata.ingress_global_timestamp;
                time_t last_reduc_time;
                portCE_reduce_time_egress.read(last_reduc_time, (bit<32>)standard_metadata.egress_spec);
                if (curr_time - last_reduc_time > CE_reduce_gap){
                    ori_port_CE = (bit<32>)ori_port_CE >> CE_reduce_alpha;
                    ori_port_CE = (bit<32>)ori_port_CE * alpha_con;
                    portCE_reduce_time_egress.write((bit<32>)standard_metadata.egress_spec, curr_time);
                }
                portCE_egress.write((bit<32>)standard_metadata.egress_spec, ori_port_CE);
            }
        }
        else{
             /****** 数据包处理 *******/
            //  TODO: 这里的判断逻辑会随着Parser的修改而改变；
            if (hdr.caver_data.isValid() || hdr.udp.isValid()){
                if (meta.host_id == 128){
                    drop();
                }
                else{
                    // SrcToR转发
                    if ((bool) meta.m_isSrcToR){
                        // 修改包头
                        hdr.caver_data.setValid();
                        // hdr.caver_data.len = (bit<16>) (hdr.udp.len - sizeof(hdr.udp) + sizeof(hdr.caver_data));
                        hdr.caver_data.srcPort = hdr.udp.srcPort;
                        hdr.caver_data.dstPort = hdr.udp.dstPort;
                        hdr.ipv4.protocol = PROTO_CAVER_DATA;
                        hdr.udp.setInvalid();

                        port_id_t SrcRoute_hop_0;
                        port_id_t SrcRoute_hop_1;
                        port_id_t SrcRoute_hop_2;
                        port_id_t SrcRoute_hop_3;
                        bit<1> hasSrcRoute;

                        bit<1> cur_flowlet_isSrcRoute;
                        time_t flowlet_last_time;
                        port_id_t cur_flowlet_SrcRoute_hop_0;
                        port_id_t cur_flowlet_SrcRoute_hop_1;
                        port_id_t cur_flowlet_SrcRoute_hop_2;
                        port_id_t cur_flowlet_SrcRoute_hop_3;
                        time_t curr_time = standard_metadata.ingress_global_timestamp;
                        


                        //确定路由方式；
                        // 查询PathCE表；
                        SrcRoute_valid.read(hasSrcRoute, meta.host_id);
                        SrcRoute_hop_0_reg.read(SrcRoute_hop_0, meta.host_id);
                        SrcRoute_hop_1_reg.read(SrcRoute_hop_1, meta.host_id);
                        SrcRoute_hop_2_reg.read(SrcRoute_hop_2, meta.host_id);
                        SrcRoute_hop_3_reg.read(SrcRoute_hop_3, meta.host_id);
                        // 查询flowlet表；
                        bit<32> flow_hash;
                        hash(flow_hash, HashAlgorithm.csum16, 32w0, {
                            hdr.ipv4.srcAddr,
                            hdr.ipv4.dstAddr,
                            hdr.ipv4.protocol,
                            hdr.caver_data.srcPort,
                            hdr.caver_data.dstPort
                        }, 32w1 << 10 - 1);

                        flowlet_time.read(flowlet_last_time, flow_hash);
                        flowlet_SrcRoute.read(cur_flowlet_isSrcRoute, flow_hash);
                        flowlet_SrcRoute_hop_0.read(cur_flowlet_SrcRoute_hop_0, flow_hash);
                        flowlet_SrcRoute_hop_1.read(cur_flowlet_SrcRoute_hop_1, flow_hash);
                        flowlet_SrcRoute_hop_2.read(cur_flowlet_SrcRoute_hop_2, flow_hash);
                        flowlet_SrcRoute_hop_3.read(cur_flowlet_SrcRoute_hop_3, flow_hash);
                        flowlet_time.write(flow_hash, curr_time);
                        if (curr_time - flowlet_last_time > FLOWLET_TOUT){
                            flowlet_SrcRoute.write(flow_hash, hasSrcRoute);
                            flowlet_SrcRoute_hop_0.write(flow_hash, SrcRoute_hop_0);
                            flowlet_SrcRoute_hop_1.write(flow_hash, SrcRoute_hop_1);
                            flowlet_SrcRoute_hop_2.write(flow_hash, SrcRoute_hop_2);
                            flowlet_SrcRoute_hop_3.write(flow_hash, SrcRoute_hop_3);

                            hdr.caver_data.hop_0 = SrcRoute_hop_0;
                            hdr.caver_data.hop_1 = SrcRoute_hop_1;
                            hdr.caver_data.hop_2 = SrcRoute_hop_2;
                            hdr.caver_data.hop_3 = SrcRoute_hop_3;
                            hdr.caver_data.hopCount = 1;
                            hdr.caver_data.SrcRoute = hasSrcRoute;

                            // 选择出端口
                            if  (hasSrcRoute == 1){
                                standard_metadata.egress_spec = (bit<9>) SrcRoute_hop_0;
                            }
                            else{
                                standard_metadata.egress_spec = (bit<9>) meta.ECMP_port;
                            }
                        }
                        else{
                            hdr.caver_data.hop_0 = cur_flowlet_SrcRoute_hop_0;
                            hdr.caver_data.hop_1 = cur_flowlet_SrcRoute_hop_1;
                            hdr.caver_data.hop_2 = cur_flowlet_SrcRoute_hop_2;
                            hdr.caver_data.hop_3 = cur_flowlet_SrcRoute_hop_3;
                            hdr.caver_data.hopCount = 1;
                            hdr.caver_data.SrcRoute = cur_flowlet_isSrcRoute;
                            // 选择出端口
                            if  (cur_flowlet_isSrcRoute == 1){
                                standard_metadata.egress_spec = (bit<9>) cur_flowlet_SrcRoute_hop_0;
                            }
                            else{
                                standard_metadata.egress_spec = (bit<9>) meta.ECMP_port;
                            }
                        }
                    }
                    // DstToR转发
                    else if ((bool) meta.m_isDstToR){
                        standard_metadata.egress_spec = (bit<9>) meta.ECMP_port;
                        // TODO: 包头改成UDP的包头；目前还没有写len和checksum，同时逻辑也会随包头变化而变化
                        hdr.udp.setValid();
                        // hdr.udp.len = (bit<16>) (hdr.caver_data.len - sizeof(hdr.caver_data) + sizeof (hdr.udp));
                        hdr.udp.srcPort = hdr.caver_data.srcPort;
                        hdr.udp.dstPort = hdr.caver_data.dstPort;
                        hdr.ipv4.protocol = PROTO_UDP;
                        hdr.caver_data.setInvalid();
                    }   
                    //midToR转发;
                    else{
                        if ((bool) hdr.caver_data.SrcRoute){
                            SrcRoute_Table.apply();
                            standard_metadata.egress_spec = (bit<9>) meta.SrcRoute_port;
                            hdr.caver_data.hopCount = hdr.caver_data.hopCount + 1;
                        }
                        else{
                            standard_metadata.egress_spec = (bit<9>) meta.ECMP_port;
                        }
                    }
                    // 更新PortCE;
                    Dre_t ori_port_CE;
                    portCE_egress.read(ori_port_CE, (bit<32>)standard_metadata.egress_spec);
                    ori_port_CE = ori_port_CE + standard_metadata.packet_length;
                    time_t curr_time = standard_metadata.ingress_global_timestamp;
                    time_t last_reduc_time;
                    portCE_reduce_time_egress.read(last_reduc_time, (bit<32>)standard_metadata.egress_spec);
                    if (curr_time - last_reduc_time > CE_reduce_gap){
                        ori_port_CE = (bit<32>)ori_port_CE >> CE_reduce_alpha;
                        ori_port_CE = (bit<32>)ori_port_CE * alpha_con;
                        portCE_reduce_time_egress.write((bit<32>)standard_metadata.egress_spec, curr_time);
                    }
                    portCE_egress.write((bit<32>)standard_metadata.egress_spec, ori_port_CE);
                }
            }
            /****** ACK包处理 *******/
            //  TODO: 这里的判断逻辑会随着Parser的修改而改变；
            if (hdr.caver_ack.isValid() || hdr.ack.isValid()){
                Dre_t port_CE;
                portCE_egress.read(port_CE, (bit<32>) standard_metadata.ingress_port);
                CE_t localCE;
                bit<64>temp;
                temp = ((bit<64>) port_CE)<< 3;
                temp = temp << m_quantizeBit;
                temp = temp >> (CE_reduce_alpha + CE_reduce_gap_math + link_rate);
                localCE = (CE_t) temp;
                standard_metadata.egress_spec = (bit<9>) meta.ECMP_port;
                if ((bool) meta.m_isSrcToR){
                    // ACK的源ToR
                    // 修改包头类型，计算tag内容（pathid:全0即可，因为这一跳无需源路由， CE端口对应的CE）；
                    hdr.caver_ack.setValid();
                    // hdr.caver_ack.len = (bit<16>)(hdr.ack.len - sizeof(hdr.ack) + sizeof(hdr.caver_ack));
                    hdr.ipv4.protocol = PROTO_CAVER_ACK;
                    hdr.caver_ack.srcPort = hdr.ack.srcPort;
                    hdr.caver_ack.dstPort = hdr.ack.dstPort;
                    hdr.caver_ack.seq = hdr.ack.seq;
                    hdr.caver_ack.hop_0 = 0;
                    hdr.caver_ack.hop_1 = 0;
                    hdr.caver_ack.hop_2 = 0;
                    hdr.caver_ack.hop_3 = 0;
                    hdr.caver_ack.pathCE = (bit<8>) localCE;
                    hdr.ack.setInvalid();
                }
                else if ((bool) meta.m_isDstToR){
                    // ACK的目的ToR
                    // 修改包头类型，更新pathCE表
                    hdr.ack.setValid();
                    // hdr.ack.len = (bit<16>)(hdr.caver_ack.len - sizeof(hdr.caver_ack) + sizeof(hdr.ack));
                    hdr.ipv4.protocol = PROTO_ACK;
                    hdr.ack.srcPort = hdr.caver_ack.srcPort;
                    hdr.ack.dstPort = hdr.caver_ack.dstPort;
                    hdr.ack.seq = hdr.caver_ack.seq;
                    
                    port_id_t SrcRoute_hop_0;
                    port_id_t SrcRoute_hop_1;
                    port_id_t SrcRoute_hop_2;
                    port_id_t SrcRoute_hop_3;
                    bit<1> hasSrcRoute;
                    CE_t pathCE;
                    CE_t new_pathCE;
                    bit<1> update_PathCE_egress;

                    SrcRoute_valid.read(hasSrcRoute, meta.host_id);
                    SrcRoute_hop_0_reg.read(SrcRoute_hop_0, meta.host_id);
                    SrcRoute_hop_1_reg.read(SrcRoute_hop_1, meta.host_id);
                    SrcRoute_hop_2_reg.read(SrcRoute_hop_2, meta.host_id);
                    SrcRoute_hop_3_reg.read(SrcRoute_hop_3, meta.host_id);
                    pathCE_egress.read(pathCE,  meta.host_id);
                    new_pathCE = (localCE > (CE_t)hdr.caver_ack.pathCE) ? localCE :(CE_t) hdr.caver_ack.pathCE;
                    
                    if (hasSrcRoute ==0 || SrcRoute_hop_0 == (port_id_t)standard_metadata.ingress_port || new_pathCE < pathCE){
                        SrcRoute_valid.write(meta.host_id, 1);
                        pathCE = new_pathCE;
                        // 用包头中的路径更新表格里的路径
                        SrcRoute_hop_3 = hdr.caver_ack.hop_2;
                        SrcRoute_hop_2 = hdr.caver_ack.hop_1;
                        SrcRoute_hop_1 = hdr.caver_ack.hop_0;
                        SrcRoute_hop_0 = (port_id_t)standard_metadata.ingress_port;

                        pathCE_egress.write(meta.host_id, new_pathCE);
                        SrcRoute_hop_3_reg.write(meta.host_id, SrcRoute_hop_3);
                        SrcRoute_hop_2_reg.write(meta.host_id, SrcRoute_hop_2);
                        SrcRoute_hop_1_reg.write(meta.host_id, SrcRoute_hop_1);
                        SrcRoute_hop_0_reg.write(meta.host_id, SrcRoute_hop_0);
                    }
                    hdr.caver_ack.setInvalid();
                }
                else{
                    // ACK的中间ToR
                    // 计算tag内容， 更新pathCE表；
                    port_id_t SrcRoute_hop_0;
                    port_id_t SrcRoute_hop_1;
                    port_id_t SrcRoute_hop_2;
                    port_id_t SrcRoute_hop_3;
                    bit<1> hasSrcRoute;
                    CE_t pathCE;
                    CE_t new_pathCE;
                    bit<1> update_PathCE_egress;

                    SrcRoute_valid.read(hasSrcRoute, meta.host_id);
                    SrcRoute_hop_0_reg.read(SrcRoute_hop_0, meta.host_id);
                    SrcRoute_hop_1_reg.read(SrcRoute_hop_1, meta.host_id);
                    SrcRoute_hop_2_reg.read(SrcRoute_hop_2, meta.host_id);
                    SrcRoute_hop_3_reg.read(SrcRoute_hop_3, meta.host_id);
                    pathCE_egress.read(pathCE, meta.host_id);
                    new_pathCE = (localCE > (CE_t)hdr.caver_ack.pathCE) ? localCE : (CE_t)hdr.caver_ack.pathCE;
                    
                    if (hasSrcRoute ==0 || SrcRoute_hop_0 == (port_id_t)standard_metadata.ingress_port || new_pathCE < pathCE){
                        SrcRoute_valid.write(meta.host_id, 1);
                        pathCE = new_pathCE;
                        // 用包头路径的更新表项的数据以及包头的数据
                        SrcRoute_hop_3 = hdr.caver_ack.hop_2;
                        SrcRoute_hop_2 = hdr.caver_ack.hop_1;
                        SrcRoute_hop_1 = hdr.caver_ack.hop_0;
                        SrcRoute_hop_0 = (port_id_t)standard_metadata.ingress_port;

                        pathCE_egress.write(meta.host_id, new_pathCE);
                        SrcRoute_hop_3_reg.write(meta.host_id, SrcRoute_hop_3);
                        SrcRoute_hop_2_reg.write(meta.host_id, SrcRoute_hop_2);
                        SrcRoute_hop_1_reg.write(meta.host_id, SrcRoute_hop_1);
                        SrcRoute_hop_0_reg.write(meta.host_id, SrcRoute_hop_0);
                    }
                    hdr.caver_ack.hop_0 = SrcRoute_hop_0;
                    hdr.caver_ack.hop_1 = SrcRoute_hop_1;
                    hdr.caver_ack.hop_2 = SrcRoute_hop_2;
                    hdr.caver_ack.hop_3 = SrcRoute_hop_3;
                    hdr.caver_ack.pathCE = (bit<8>)pathCE;
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.ack);
        packet.emit(hdr.caver_data);
        packet.emit(hdr.caver_ack);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
