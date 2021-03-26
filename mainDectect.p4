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
    process_cache();
    process_value();
    
    apply (ipv4_route);
}

control egress {
    if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_exist != 1) {
        heavy_hitter();
    }
    apply (ethernet_set_mac);
}

field_list inPortFields {	
    ig_intr_md.ingress_port;
}
field_list_calculation inPortHashCalc {
    input { inPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}


field_list outPortFields {
    eg_intr_md.egress_port;
}
field_list_calculation upPortHashCalc {
    input { outPortFields; }
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

control process_1 {
    apply(tipointer);  //保存队首队尾指针,front和rear
    if (valid(sfNotice)){	//如果是通知包，记录star和end id，接着检测丢包并发送到cpu
    	apply (tiRecord);
    }
    else{
    	apply (tiDetectDrop);//普通包
	if(sfInfoKey.startPId!=sfInfoKey.endPId+1){  //有丢包
		
	}
	else{    //没有丢包
	
	
	}
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

control egress {
        //1，发送通知包  2，根据port，记录packetId和flow信息
	if (valid(sfNotice)) {
        apply(teProcessSfHeader);//还有问题？？？对于通知包，应该怎么发送给原端口，并且删除通知包的包头后，发送给本来应该发送的端口,后面再看看
	
    }
    
}
table teProcessSfHeader { 
    reads {
        //eg_intr_md.egress_port : exact;
	sfInfoKey.dflag : exact;
    }
    actions { aeDoNothing; aeRemoveSfHeader;}
    default_action : aeRemoveSfHeader();
}

action aeDoNothing() {
    no_op();
}

action aeRemoveSfHeader() {
    modify_field(ethernet.etherType, sfNotice.realEtherType);
    remove_header(sfNotice);
    modify_field(ipv4_option.packetID,sfInfoKey.endPId+1);
}

@pragma stage 0
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



//if sfInfoKey.dflag==1,constructs a packet
@pragma stage 0
@pragma ignore_table_dependency tiVerifyfarward
table tiNotice {
    reads {sfInfoKey.dflag : exact;}
    actions {ainotice; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
action ainotice() {
   //TODO: constructs a packet
   add_header(sfNotice);
   modify_field(sfNotice.realEtherType, ethernet.etherType);
   modify_field(sfNotice.startPId, sfInfoKey.startPId);
   modify_field(sfNotice.endPId, sfInfoKey.endPId);
   modify_field(ethernet.etherType, ETHERTYPE_DROP_NF);
   aiMcToup();//发送到入端口
}

action aiMcToup() {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, ig_intr_md.ingress_port);  //从入口发送通知包
}
action aiforward(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}
