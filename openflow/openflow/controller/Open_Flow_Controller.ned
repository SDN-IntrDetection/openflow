

package openflow.openflow.controller;
import inet.base.NotificationBoard;
import inet.linklayer.ethernet.EthernetInterface;
import inet.networklayer.common.InterfaceTable;
import inet.networklayer.ipv4.RoutingTable;
import inet.nodes.inet.NetworkLayer;
import inet.transport.ITCP;
import inet.applications.ITCPApp;

import openflow.controllerApps.*;
//
// TODO documentation
//
module Open_Flow_Controller
{
    parameters:
        @node();
        @labels(node,ethernet-node);
        @display("i=device/server;bgb=795,381;i2=openflow/OpenFlow-Logo-small");
        int numControllerApps = default(0);
        int numTcpControllerApps = default(0);

		//submodules
        string tcpType = default("TCP");  // tcp implementation (e.g. TCP, TCP_old, TCP_NSC)
        bool IPForward = default(false);
        string routingFile = default("");
        int numExtInterfaces = default(0);
        double serviceTime @unit("s") = default(0s);



    gates:
        inout ethg[] @labels(EtherFrame-conn);
    submodules:

        controllerApps[numControllerApps]: <> like AbstractControllerApp {
            parameters:
                @display("p=514,102,row,60");
        }

        tcpControllerApps[numTcpControllerApps]: <> like ITCPApp {
            parameters:
                @display("p=195,102,row,60");
        }

        notificationBoard: NotificationBoard {
            parameters:
                @display("p=728,268");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=728,187");
        }
        routingTable: RoutingTable {
            parameters:
                IPForward = IPForward;
                routerId = "";
                routingFile = routingFile;
                @display("p=728,102");
        }
        tcp: <tcpType> like ITCP {
            parameters:
                @display("p=195,239");
        }
        networkLayer: NetworkLayer {
            parameters:
                proxyARP = false;
                @display("p=350,239;q=queue");
            gates:
                ifIn[sizeof(pppg)+sizeof(ethg)+numExtInterfaces];
                ifOut[sizeof(pppg)+sizeof(ethg)+numExtInterfaces];
        }
        eth[sizeof(ethg)]: EthernetInterface {
            parameters:
                @display("p=514,239,row,90;q=txQueue");
        }
        OF_Controller: OF_Controller {
            @display("p=51,239");
            serviceTime = serviceTime;
        }
    connections allowunconnected:
        tcp.ipOut --> networkLayer.transportIn++;
        tcp.ipIn <-- networkLayer.transportOut++;

        for i=0..sizeof(ethg)-1 {
            ethg[i] <--> eth[i].phys;
            eth[i].upperLayerOut --> networkLayer.ifIn[i];
            eth[i].upperLayerIn <-- networkLayer.ifOut[i];
        }

        for i=0..numTcpControllerApps-1 {
            tcpControllerApps[i].tcpOut --> tcp.appIn++;
            tcpControllerApps[i].tcpIn <-- tcp.appOut++;
        }

        tcp.appOut++ --> OF_Controller.tcpIn;
        OF_Controller.tcpOut --> tcp.appIn++;
}


