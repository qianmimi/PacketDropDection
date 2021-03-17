/**
 *
 * header.p4
 * 
 */

/*===========================================
=            Forwarding Headers.            =
===========================================*/
header ethernet_t {
    bit<48>  dstAddr;
    bit<48>  srcAddr;
    bit<16>  etherType;
}

header ipv4_t {
        bit<4>  version;
        bit<4>  ihl;
        bit<8>  diffserv;
        bit<16>  totalLen;
        bit<16>  identification;
        bit<3>   flags;
        bit<13>  fragOffset;
        bit<8>   ttl;
        bit<8>   protocol;
        bit<16>  hdrChecksum;
        bit<32>  srcAddr;
        bit<32>  dstAddr;
}

header ipv4_option_t {
        bit<16>   packetID;  // a private sequence number
}

header l4_ports_t {
        bit<32>  ports;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_option_t   ipv4_option;
    l4_ports_t   l4_ports;
}

/*===========================================
=            Metadata            =
===========================================*/
struct metadata {
    bit<32>  startPId;
    bit<32>  endPId;
    bit<16>  downPortHashVal;///???not sure
    bit<16>  upPortHashVal;///???not sure
    bit<32>  upPortPos;
    bit<1>  dflag;
}


/*===========================================
=            Notice Headers.            =
===========================================*/
header sfNotice_t {
      bit<32>  startPId;
      bit<32>  endPId;
      bit<16>  realEtherType;
}
