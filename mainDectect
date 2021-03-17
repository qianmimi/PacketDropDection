/**
 *
 * mainDropDetect.p4
 * 
 */
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/primitives.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_DROP_NF 0x081A
#define SF_SHORT_BIT_WIDTH 32
#include "parser.p4"

field_list downPortFields {
    ig_intr_md.ingress_port;
}
field_list_calculation downPortHashCalc {
    input { downPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}

field_list upPortFields {
    eg_intr_md.egress_port;
}
field_list_calculation upPortHashCalc {
    input { upPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}
control ingress {
    apply(tiDectectDrop);//verify whether packet drop,TO DO：need to modify
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
table tiDectectDrop{
    reads {ethernet.etherType : exact;}//verify normal packet or notice packet
    actions {aiDownPortPktId; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
//if normal packet
action aiDownPortPktId() {  
    modify_field(sfInfoKey.endPId, ipv4_option.packetID);
    modify_field_with_hash_based_offset(sfInfoKey.downPortHashVal, 0, downPortHashCalc, SF_SHORT_BIT_WIDTH);
    sDownPortPktId.execute_stateful_alu(sfInfoKey.downPortHashVal);
    if(sfInfoKey.endPId==sfInfoKey.startPId+1){
    	modify_field(sfInfoKey.dflag,1);
    }   
}

//if packetId==register+1,no drop
/* else inconsecutive sequence numbers as a sign of packet drops;*/
/*dflag==0 no drop ; dflag==1 drop*/
blackbox stateful_alu sDownPortPktId{
    reg : rDownPortPktId;
    condition_lo : ipv4_option.packetID== register_lo+1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo+1;

    output_dst : sfInfoKey.startPId;
    output_value : register_lo;
}

register rDownPortPktId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
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
