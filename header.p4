/**
 *
 * header.p4
 * 
 */

/*===========================================
=            Forwarding Headers.            =
===========================================*/
header_type ethernet_t {
        fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16; // here
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;

header_type ipv4_option_t {
    fields {
        packetID : 16;   // a private sequence number
    }
}
header ipv4_option_t ipv4_option;

header_type l4_ports_t {
    fields {
        ports : 32;
    }
}
header l4_ports_t l4_ports;

header_type sfInfoKey_t {
    fields {
        startPId : 32;
        endPId : 32;
        downPortHashVal: 16;///???not sure
        upPortHashVal: 16;///???not sure
        upPortPos : 32;
        dflag : 1;
        qfstart : 32;
        qfend : 32;
    }
}
metadata sfInfoKey_t sfInfoKey;

header_type sfNotice_t {
    fields {
        startPId : 32;
        endPId : 32;
        realEtherType : 16;
    }
}
header sfNotice_t sfNotice;

header_type cpu_header_t {
    fields {
        srcAddr : 32;
        dstAddr : 32;
        ports : 32;
        protocol : 8
    }
}
header cpu_header_t cpu_header;
