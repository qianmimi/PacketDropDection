/**
 *
 * mainDropDetect.p4
 * 
 */
#include "includes/headers.p4"
#include "includes/parser.p4"

#define SF_SHORT_BIT_WIDTH 12
#define SF_SHORT_SIZE 5

header_type port_pktIds_t {
    fields {
        index: 12;
	index_1 : 12;
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

header_type sfInfoKey_t {
    fields {
        startPId : 12;
        endPId : 12;
        downPortHashVal: 12;///???not sure
        upPortHashVal: 12;///???not sure
        outpktid : 12;
        dflag : 1;
        qfstart : 12;
        qfend : 12;
    }
}
metadata sfInfoKey_t sfInfoKey;

field_list inPortFields {	
    standard_metadata.ingress_port;
}
field_list_calculation inPortHashCalc {
    input { inPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}
field_list outPortFields {
    standard_metadata.egress_port;
}
field_list_calculation upPortHashCalc {
    input { outPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}

control ingress {
	process_1();
}
control egress {
	process_2();
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
    width : 12;
    instance_count : SF_SHORT_SIZE;
}
action aisaveflow() {   //保存flow信息、insert id 到ipv4的option
    register_write(rSrcAddr, sfInfoKey.outpktid, ipv4.srcAddr);
    register_write(rtDstAddr, sfInfoKey.outpktid, ipv4.dstAddr);
    register_write(rPort, sfInfoKey.outpktid, l4_ports.ports);
    register_write(rProtocol, sfInfoKey.outpktid, ipv4.protocol);
    add_header(ipv4_option);
    modify_field(ipv4_option.packetID, sfInfoKey.outpktid);
}
table tisaveflow {
    actions {aisaveflow;}
}

#define INPORT_MIRROR_SESSION_ID                  3

field_list clone_fields {
    standard_metadata;
}
action aiclone_to_e2e() {
    clone_egress_pkt_to_egress(INPORT_MIRROR_SESSION_ID, clone_fields);
}
table ticlone_to_e2e {
    actions {aiclone_to_e2e;}
}
#define CPU_MIRROR_SESSION_ID                  250
action do_copy_to_cpu() {
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, clone_fields);
}
table copy_to_cpu {
    actions {do_copy_to_cpu;}
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
        apply (forward); //转发
    	apply (tiDetectDrop);//普通包
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

action do_cpu_encap() {
    remove_header(sfNotice);
    add_header(cpu_header);
    register_read(cpu_header.srcAddr, rSrcAddr, sfInfoKey.qfstart);
    register_read(cpu_header.dstAddr, rtDstAddr, sfInfoKey.qfstart);
    register_read(cpu_header.ports,  rPort, sfInfoKey.qfstart);
    register_read(cpu_header.protocol, rProtocol, sfInfoKey.qfstart);
}

table redirect_1 {
    reads { standard_metadata.instance_type : exact; }
    actions {do_cpu_encap;}
}

action do_inport_encap() {
    remove_header(cpu_header);
    add_header(sfNotice);
    modify_field(sfNotice.startPId, sfInfoKey.endPId);
    modify_field(sfNotice.endPId, sfInfoKey.startPId);
}

table redirect_2 {
    reads { standard_metadata.instance_type : exact; }
    actions {do_inport_encap;}
}
control process_2 {
     if(standard_metadata.instance_type == 0){
     	  if(sfInfoKey.startPId != sfInfoKey.endPId+1){  //有丢包
	      	apply(ticlone_to_e2e); //添加通知头，发送给ingress port
	  }
          apply (tioutpktid); //获得出口的packet id
	  apply (tisaveflow);  //cache flow info
      }
     apply(redirect_1);
     apply(redirect_2);
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
    width : 12;
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
    width : 16;
    instance_count : 1;
}
register rrear{
    width : 16;
    instance_count : 1;
}
register rstartId{
    width : 12;
    instance_count : SF_SHORT_BIT_WIDTH;
}
register rendId{
    width : 12;
    instance_count : SF_SHORT_BIT_WIDTH;
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
