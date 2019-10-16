#include <omnetpp.h>
#include <EtherFrame_m.h>
#include <MACAddress.h>
#include <ARPPacket_m.h>
#include <Flow_Table.h>

using namespace std;


Flow_Table::Flow_Table() {

}


static inline int flow_fields_match(const oxm_basic_match &m1, const oxm_basic_match &m2, const uint32_t w){
    return (((w & OFPFW_IN_PORT) || m1.OFB_IN_PORT == m2.OFB_IN_PORT)
            && ((w & OFPFW_DL_TYPE) || m1.OFB_ETH_TYPE == m2.OFB_ETH_TYPE )
            && ((w & OFPFW_DL_SRC) || !m1.OFB_ETH_SRC.compareTo(m2.OFB_ETH_SRC))
            && ((w & OFPFW_DL_DST) || !m1.OFB_ETH_DST.compareTo(m2.OFB_ETH_DST))
            && (m1.OFB_SYN_FLAG == m2.OFB_SYN_FLAG)
            && ((w & OFPFW_ACK_FLAG) || m1.OFB_ACK_FLAG == m2.OFB_ACK_FLAG)
            && ((w & OFPFW_IP_SRC) || m1.OFB_IPV4_SRC == m2.OFB_IPV4_SRC)
            && ((w & OFPFW_IP_DST) || m1.OFB_IPV4_DST == m2.OFB_IPV4_DST));
}

void Flow_Table::addEntry(Flow_Table_Entry entry) {
    entryList.push_front(entry);
    countList.push_front(1);
    EV << "Entry was added to the front of the list: ";
    for(list<int>::iterator i=countList.begin(); i!=countList.end(); i++){
        EV <<  *i << ' ';
    }
    EV << '\n';

}


Flow_Table_Entry* Flow_Table::lookup(oxm_basic_match &match) {
    EV << "Looking through " << entryList.size() << " Flow Entries!" << '\n';
    EV << "This is the match fields we try to match with a table:" << '\n';
    EV << "Packet in port: " << match.OFB_IN_PORT << '\n';
    EV << "Packet eth type: " << match.OFB_ETH_TYPE << '\n';
    EV << "Packet eth src: " << match.OFB_ETH_SRC << '\n';
    EV << "Packet eth dst: " << match.OFB_ETH_DST << '\n';
    EV << "Packet syn flag: " << match.OFB_SYN_FLAG << '\n';
    EV << "Packet ack flag: " << match.OFB_ACK_FLAG << '\n';
    EV << "Packet ipv4 src: " << match.OFB_IPV4_SRC << '\n';
    EV << "Packet ipv4 dst: " << match.OFB_IPV4_DST << '\n';

    int i = 0;
    for(auto iter =entryList.begin();iter != entryList.end();++iter){
        EV << "Flow table entry in port: " << (*iter).getMatch().OFB_IN_PORT << '\n';
        EV << "Flow table entry eth type: " << (*iter).getMatch().OFB_ETH_TYPE << '\n';
        EV << "Flow table entry eth src: " << (*iter).getMatch().OFB_ETH_SRC << '\n';
        EV << "Flow table entry eth dst: " << (*iter).getMatch().OFB_ETH_DST << '\n';
        EV << "Flow table entry syn flag: " << (*iter).getMatch().OFB_SYN_FLAG << '\n';
        EV << "Flow table entry ack flag: " << (*iter).getMatch().OFB_ACK_FLAG << '\n';
        EV << "Flow table entry ipv4 src: " << (*iter).getMatch().OFB_IPV4_SRC << '\n';
        EV << "Flow table entry ipv4 dst: " << (*iter).getMatch().OFB_IPV4_DST << '\n';
        EV << "Flow table entry outport action: " << (*iter).getInstructions().port << '\n';
        EV << '\n';
    //    EV << "Flow table counter is: " << (*iter).getCounter() << '\n';
        //check if flow has expired
        if ((*iter).getExpiresAt() < simTime()){
            iter = entryList.erase(iter);

            list<int>::iterator itr = countList.begin();
            advance(itr,i);
            countList.erase(itr);
            erasedCount = erasedCount+1;
            EV << "A flow table was erased!"  << '\n';
            continue;
        }


        if (flow_fields_match(match, (*iter).getMatch(), (*iter).getMatch().wildcards)){
            //adapt idle timer filed if neccessary
            if ((*iter).getIdleTimeout() != 0){
                (*iter).setExpiresAt((*iter).getIdleTimeout()+simTime());
                EV << "Idle Timeout is: " << (*iter).getIdleTimeout() << '\n';
                EV << "Erase count is now: "<< erasedCount  << '\n';
            }

            list<int>::iterator it = countList.begin();
            advance(it,i);
            *it = *it +1;
            EV <<"Number of matches for flow table number " << i << ": " << *it << '\n';
            for(list<int>::iterator itera=countList.begin(); itera!=countList.end(); itera++){
                EV <<  *itera << ' ';
            }
            EV << '\n';

            if((*it >= 5) && ((*iter).getMatch().OFB_SYN_FLAG == 1) && ((*iter).getMatch().OFB_ACK_FLAG == 0) && ((*iter).getInstructions().port != OFPP_ANY)){
                (*iter).setExpiresAt(simTime());
            }



            return &(*iter);
        }
        i++;
    }
    return NULL;
}


