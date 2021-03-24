/**
 *
 * Headers, metadata, and parser.
 *
 */
 metadata sfInfoKey_t sfInfoKey;
 header sfNotice_t sfNotice;
  
 header_type sfInfoKey_t {
    fields {
        startPId : 32;
        endPId : 32;
        downPortHashVal: 16;///???not sure
        upPortHashVal: 16;///???not sure
        upPortPos : 32;
        dflag : 1;
        normal : 1;
    }
}

header_type sfNotice_t {
    fields {
        startPId : 32;
        endPId : 32;
        realEtherType : 16;
    }
}

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

header ipv4_option_t {
    packetID : 16;   // a private sequence number
}
header ipv4_option_t ipv4_option;

header_type l4_ports_t {
    fields {
        ports : 32;
    }
}
header l4_ports_t l4_ports;


/*=====  End of Forwarding Headers.  ======*/

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_DROP_NF: parse_drop_nf; // notification packet，This should report event???
        ETHERTYPE_IPV4 : parse_ipv4; 
        default : ingress;
    }
}

// IP.
parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.ihl) {
        5: parse_l4; //no options
        default : parse_ipv4_option;  //have options
    }
}
parser parse_ipv4_option {
    extract(ipv4_option);
    return parse_l4;
}

// TCP / UDP ports.
parser parse_l4 {
    extract(l4_ports);
    return ingress;
}


// looks up its ring buffer for the packets whose sequence
//numbers fall into the missing interval and reports them as dropped
//packets.
parser parse_drop_no {

}
