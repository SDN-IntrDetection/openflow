#include <LearningSwitch.h>
#include "Switch_Info.h"

Define_Module(LearningSwitch);

LearningSwitch::LearningSwitch(){

}

LearningSwitch::~LearningSwitch(){

}

void LearningSwitch::initialize(){
    AbstractControllerApp::initialize();
    idleTimeout = par("flowModIdleTimeOut");
    hardTimeout = par("flowModHardTimeOut");
}

void LearningSwitch::receiveSignal(cComponent *src, simsignal_t id, cObject *obj) {
    AbstractControllerApp::receiveSignal(src,id,obj);

    if(id == PacketInSignalId){
        EV << "LearningSwitch::PacketIn" << endl;
        if (dynamic_cast<OFP_Packet_In *>(obj) != NULL) {
            OFP_Packet_In *packet_in = (OFP_Packet_In *) obj;
            doSwitching(packet_in);
        }
    }
}


void LearningSwitch::doSwitching(OFP_Packet_In *packet_in_msg){

    CommonHeaderFields headerFields = extractCommonHeaderFields(packet_in_msg);

    //search map for source mac address and enter
    if(lookupTable.count(headerFields.swInfo)<=0){
        lookupTable[headerFields.swInfo]= std::map<MACAddress,uint32_t>();
        lookupTable[headerFields.swInfo][headerFields.src_mac] = headerFields.inport;
    } else {
        if(lookupTable[headerFields.swInfo].count(headerFields.src_mac)<=0){
            lookupTable[headerFields.swInfo][headerFields.src_mac] = headerFields.inport;
        }
    }


    if(lookupTable.count(headerFields.swInfo)<=0){
        floodPacket(packet_in_msg);
    } else {
        if(lookupTable[headerFields.swInfo].count(headerFields.dst_mac)<=0){
            floodPacket(packet_in_msg);
        } else {
            if (packet_in_msg->getReason() == OFPR_THRESHOLD_REACHED){
                EV << "Flow entry with packet drop because of threshold is made!" << '\n';
                outport = OFPP_ANY;
                dropPacket(packet_in_msg);

                oxm_basic_match match = oxm_basic_match();


               match.OFB_ETH_DST = headerFields.dst_mac;
               match.OFB_ETH_TYPE = headerFields.eth_type;
               match.OFB_ETH_SRC = headerFields.src_mac;
               match.OFB_IN_PORT = headerFields.inport;
               match.OFB_SYN_FLAG = headerFields.syn_flag;
               match.OFB_ACK_FLAG = headerFields.ack_flag;
               match.OFB_IPV4_SRC = headerFields.src_adr;
               match.OFB_IPV4_DST = headerFields.dst_adr;



               match.wildcards= 0;
               match.wildcards |= OFPFW_IN_PORT;
               match.wildcards |=  OFPFW_DL_SRC;
               match.wildcards |= OFPFW_DL_TYPE;
               if((headerFields.ack_flag == 1) || (headerFields.syn_flag = 0)){
                   match.wildcards |= OFPFW_IP_SRC;
                   match.wildcards |= OFPFW_IP_DST;
               }
               if(headerFields.syn_flag == 0){
                       match.wildcards |= OFPFW_ACK_FLAG;
                   }



               TCPSocket * socket = controller->findSocketFor(packet_in_msg);
               sendFlowModMessage(OFPFC_ADD, match, outport, socket,idleTimeout,hardTimeout);
               sendPacket(packet_in_msg, outport);
            }
            else{
                outport = lookupTable[headerFields.swInfo][headerFields.dst_mac];


                oxm_basic_match match = oxm_basic_match();


                match.OFB_ETH_DST = headerFields.dst_mac;
                match.OFB_ETH_TYPE = headerFields.eth_type;
                match.OFB_ETH_SRC = headerFields.src_mac;
                match.OFB_IN_PORT = headerFields.inport;
                match.OFB_SYN_FLAG = headerFields.syn_flag;
                match.OFB_ACK_FLAG = headerFields.ack_flag;
                match.OFB_IPV4_SRC = headerFields.src_adr;
                match.OFB_IPV4_DST = headerFields.dst_adr;



                match.wildcards= 0;
                match.wildcards |= OFPFW_IN_PORT;
                match.wildcards |=  OFPFW_DL_SRC;
                match.wildcards |= OFPFW_DL_TYPE;
                if((headerFields.ack_flag == 1) || (headerFields.syn_flag = 0)){
                    match.wildcards |= OFPFW_IP_SRC;
                    match.wildcards |= OFPFW_IP_DST;
                }
                if(headerFields.syn_flag == 0){
                        match.wildcards |= OFPFW_ACK_FLAG;
                    }



                TCPSocket * socket = controller->findSocketFor(packet_in_msg);
                sendFlowModMessage(OFPFC_ADD, match, outport, socket,idleTimeout,hardTimeout);
                sendPacket(packet_in_msg, outport);
                EV << "EGVILHJEEEEEEEEEEEEEEEEEEEEM!";
            }
        }
    }
}







