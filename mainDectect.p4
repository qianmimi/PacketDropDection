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
        packetId: 32;
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
control process_1 {
    if (valid(sfNotice)){
    	apply (tiRecord);
	apply (tiTocpu);
    }
    else{
    	apply (tiDetectDrop);
	if(sfInfoKey.endPId==port_pktIds.packetId){
	     apply (tiTocpu);
	}
    }

    //TO DO
    /*1, forward packet always,
      2, if sfInfoKey.dflag==1 constructs a packet which contains the starting and ending of missing sequence numbers and sends it to upstreamswitch
    produce three copies of it in order to avoid drop again */
    if(sfInfoKey.dflag==1){
        apply(tiNotice);//
    }

}

control egress {
        //1，发送通知包  2，根据port，记录packetId和flow信息
	if (valid(sfNotice)) {
        apply(teProcessSfHeader);//还有问题？？？对于通知包，应该怎么发送给原端口，并且删除通知包的包头后，发送给本来应该发送的端口,后面再看看
	
    }
    apply(teBufferFlow);//save pkt number and flow
    
}
table teBufferFlow { 
    actions { aeBufferFlow;}
    default_action : aeBufferFlow();
}
action aeBufferFlow() {

      // increase packet number in one port == pos
      modify_field_with_hash_based_offset(sfInfoKey.upPortHashVal, 0, upPortHashCalc, SF_SHORT_BIT_WIDTH);
      rPortBuffPosUpdate.execute_stateful_alu(sfInfoKey.upPortHashVal);
      
      //save pkt number and flow(5-tuple)
      rPortBuffPktId.execute_stateful_alu(sfInfoKey.upPortPos);
      rPortBuffSrcAddr.execute_stateful_alu(sfInfoKey.upPortPos);
      rPortBuffDstAddr.execute_stateful_alu(sfInfoKey.upPortPos);
      rPortBuffSrcPort.execute_stateful_alu(sfInfoKey.upPortPos);
      rPortBuffDstPort.execute_stateful_alu(sfInfoKey.upPortPos);
      rPortBuffProtocol.execute_stateful_alu(sfInfoKey.upPortPos);

      
}

//sfInfoKey.dflag==1 removeHeader,然后发送
//else do nothing,发送
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
table tiRecord{
    actions {aiRecordDropId;}
    default_action : aiRecordDropId;
}
table tiDetectDrop{
    actions {ainPortPktId;}
    default_action : ainPortPktId;
}
action ainPortPktId() {  
    modify_field(sfInfoKey.endPId, ipv4_option.packetID-1);
    modify_field_with_hash_based_offset(port_pktIds.index, 0, inPortHashCalc, SF_SHORT_BIT_WIDTH);
    register_read(port_pktIds.packetId, rinPortPktId, port_pktIds.index);
    register_write(rinPortPktId, port_pktIds.index, port_pktIds.packetId + 1);   
}
//a in-port Array
register rinPortPktId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
action aiRecordDropId(){
    register_read(pointer.qfront, rfront, 0);
    register_read(pointer.qrear, rrear, 0);
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
table tiTocpu{
    actions {aiTocpu;}
    default_action : aiTocpu;
}
action aiTocpu(){
    
}





//ring buffer pos == pkt numbers
blackbox stateful_alu rPortBuffPosUpdate{
    reg : rUpPortBuffPos;
    update_lo_1_value : register_lo+1;
    output_dst : sfInfoKey.upPortPos;
    output_value : register_lo;
}
register rUpPortBuffPos {
    width : 8;
    instance_count : SF_SHORT_BIT_WIDTH;
}
//save pkt number
blackbox stateful_alu rPortBuffPktId{
    reg : rUpPortpacketId;
    update_lo_1_value : sfInfoKey.upPortPos
}
register rUpPortpacketId {
    width : 32;
    instance_count : SF_SHORT_BIT_WIDTH;
}
//save pkt srcAddr
blackbox stateful_alu rPortBuffSrcAddr{
    reg : rUpPortSrcAddr;
    update_lo_1_value : ipv4.srcAddr;
}
register rUpPortSrcAddr {
    width : 32;
    instance_count : SF_SHORT_BIT_WIDTH;
}

//save pkt DstAddr
blackbox stateful_alu rPortBuffDstAddr{
    reg : rUpPortDstAddr;
    update_lo_1_value : ipv4.dstAddr;
}
register rUpPortDstAddr {
    width : 32;
    instance_count : SF_SHORT_BIT_WIDTH;
}

//save pkt src port
blackbox stateful_alu rPortBuffSrcPort{
    reg : rUpPortSrcPort;
    update_lo_1_value : tcp.srcPort;
}
register rUpPortSrcPort {
    width :32;
    instance_count : SF_SHORT_BIT_WIDTH;
}

//save pkt dst port
blackbox stateful_alu rPortBuffDstPort{
    reg : rUpPortDstPort;
    update_lo_1_value : tcp.dstPort;
}
register rUpPortDstPort {
    width :32;
    instance_count : SF_SHORT_BIT_WIDTH;
}

//save pkt protocol
blackbox stateful_alu rPortBuffProtocol{
    reg : rUpPortProtocol;
    update_lo_1_value : ipv4.protocol;
}
register rUpPortProtocol {
    width :32;
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
