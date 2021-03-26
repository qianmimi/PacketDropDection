/**
 *
 * mainDropDetect.p4
 * 
 */
#include "headers.p4"
#include "parsers.p4"

header_type port_pktIds_t {
    fields {
        index: 16;
	index_1 : 16;
    }
}
metadata port_pktIds_t port_pktIds;

header_type pointer_t {
    fields {
        qfront: 16;        
        qrear: 16;
    }
}
metadata pointer_t pointer;

control ingress {
}
control egress {
}

field_list inPortFields {	
    ig_intr_md.ingress_port;
}
field_list_calculation inPortHashCalc {
    input { inPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}

action aipointer() {
    register_read(pointer.qfront, rfront, 0);
    register_read(pointer.qrear, rrear, 0);
}
table tipointer {
    actions {aipointer;}
}
action aisaveqf() {
    register_read(sfInfoKey.qfstart, rstartId, pointer.qfront);
    register_read(sfInfoKey.qfend, rendId, pointer.qfront);
}
table tisaveqf {
    actions {aisaveqf;}
}
action movestart() {
    register_write(rstartId, pointer.qfront, sfInfoKey.qfstart + 1);
}
table timovestart {
    actions {movestart;}
}
action movefront() {
    register_write(rfront, 0, pointer.qfront + 1);
}
table timovefront {
    actions {movefront;}
}
#define CPU_MIRROR_SESSION_ID                  250

field_list copy_to_cpu_fields {
    standard_metadata;
}
action do_copy_to_cpu() {
    add_header(cpu_header);
    register_read(cpu_header.srcAddr, rSrcAddr, sfInfoKey.qfstart);
    register_read(cpu_header.dstAddr, rtDstAddr, sfInfoKey.qfstart);
    register_read(cpu_header.ports,  rPort, sfInfoKey.qfstart);
    register_read(cpu_header.protocol, rProtocol, sfInfoKey.qfstart);
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);
}
table copy_to_cpu {
    actions {do_copy_to_cpu;}
}

#define sf_MIRROR_SESSION_ID                  251
action clone_to_inport() {   //怎么发到上游接口呢，而且要发三次？？
    add_header(sfNotice);
    modify_field(ethernet.etherType, ETHERTYPE_DROP_NF);
    clone_ingress_pkt_to_egress(sf_MIRROR_SESSION_ID, copy_to_cpu_fields);
}
table ticlone_to_inport {
    actions {clone_to_inport;}
}

field_list outPortFields {
    standard_metadata.egress_port;
}
field_list_calculation upPortHashCalc {
    input { outPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}
action aioutpktid() {   //获取出口的packet id
    modify_field_with_hash_based_offset(port_pktIds.index_1, 0, upPortHashCalc, SF_SHORT_BIT_WIDTH);
    register_read(sfInfoKey.outpktid, routPortPktId, port_pktIds.index_1);
    register_write(routPortPktId, port_pktIds.index_1, sfInfoKey.outpktid + 1);
}
table tioutpktid {
    actions {aioutpktid;}
}
//a out-port Array
register routPortPktId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
action aisaveflow() {   //保存flow信息、insert id 到ipv4的option
    register_write(rSrcAddr, sfInfoKey.outpktid, ipv4.srcAddr);
    register_write(rtDstAddr, sfInfoKey.outpktid, ipv4.dstAddr);
    register_write(rPort, sfInfoKey.outpktid, l4_ports.ports);
    register_write(rProtocol, sfInfoKey.outpktid, ipv4.protocol);
    modify_field(ipv4_option.packetID, sfInfoKey.outpktid);
}
table tisaveflow {
    actions {aisaveflow;}
}

action set_egr(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}
table forward {
    reads {
		standard_metadata.ingress_port: exact;
    }
    actions {
        set_egr;
    }
}
control process_1 {
    apply(tipointer);  //保存队首队尾指针,front和rear
    if (valid(sfNotice)){	//如果是通知包，记录star和end id，接着检测丢包并发送到cpu
    	apply (tiRecord);
    }
    else{
    	apply (tiDetectDrop);//普通包
	if(sfInfoKey.startPId != sfInfoKey.endPId+1){  //有丢包
	      	apply(ticlone_to_ingress); //添加通知头，发送给ingress port
	}
	apply (tioutpktid); //获得出口的packet id
	apply (tisaveflow);  //cache flow info
	apply (forward); //转发
    }
    if(pointer.qfront!=pointer.qrear){
   	apply(tisaveqf);   //保存front位置的start和end
    	apply(copy_to_cpu);  //检测队列中的丢包，发送CPU
	if(sfInfoKey.qfstart!=sfInfoKey.qfend){  //如果队首位置的start和end不相等，front位置的start+1
	 	apply(timovestart);  
	}
	else{    //相等，front+1
		apply(timovefront); 
	}
    }
}

action aeDoNothing() {
    no_op();
}

table tiDetectDrop{
    actions {ainPortPktId;}
    default_action : ainPortPktId;
}
action ainPortPktId() {  
    modify_field(sfInfoKey.endPId, ipv4_option.packetID-1);
    modify_field_with_hash_based_offset(port_pktIds.index, 0, inPortHashCalc, SF_SHORT_BIT_WIDTH);
    register_read(sfInfoKey.startPId, rinPortPktId, port_pktIds.index);
    register_write(rinPortPktId, port_pktIds.index, ipv4_option.packetID + 1);
}
//a in-port Array
register rinPortPktId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
table tiRecord{
    actions {aiRecordDropId;}
    default_action : aiRecordDropId;
}
action aiRecordDropId(){
    register_write(rstartId, pointer.qrear, sfNotice.startPId);
    register_write(rendId, pointer.qrear, sfNotice.endPId);
    register_write(rrear, 0, pointer.qrear+1);
}
//a Queue: record start and end drop id
register rfront{
    width : 32;
    instance_count : 1;
}
register rrear{
    width : 32;
    instance_count : 1;
}
register rstartId{
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
register rendId{
    width : 32;
    instance_count : SF_SHORT_SIZE;
}

register rSrcAddr {
    width : 32;
    instance_count : SF_SHORT_BIT_WIDTH;
}
register rtDstAddr {
    width : 32;
    instance_count : SF_SHORT_BIT_WIDTH;
}
register rPort {
    width :32;
    instance_count : SF_SHORT_BIT_WIDTH;
}
register rProtocol {
    width :8;
    instance_count : SF_SHORT_BIT_WIDTH;
}



table teProcessSfHeader { 
    reads {
        //eg_intr_md.egress_port : exact;
	sfInfoKey.dflag : exact;
    }
    actions { aeDoNothing; aeRemoveSfHeader;}
    default_action : aeRemoveSfHeader();
}
