

package openflow.networks;

import inet.networklayer.ipv4.RoutingTableRecorder;
import inet.nodes.ethernet.EtherSwitch;
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import inet.networklayer.autorouting.ipv4.*;
import inet.nodes.rip.RIPRouter;
import inet.util.ThruputMeteringChannel;
import inet.world.radio.ChannelControl;
import lte.corenetwork.binder.LteBinder;
import lte.corenetwork.nodes.Ue;
import lte.corenetwork.nodes.eNodeB;
import lte.epc.PgwStandardSimplified;
import openflow.utility.*;

import openflow.nodes.*;
import openflow.openflow.controller.*;
import openflow.openflow.switch.*;
import openflow.hyperflow.*;


network Scenario_TestCaseAltered
{
    parameters:
        int numClients @display("bgb=768,465") = default(1);
        int numControllers @display("bgb=768,465") = default(1);
        int numUe @display("bgb=768,465") = default(1);
        int numMal @display("bgb=768,465") = default(1);

        @display("bgb=925,638");
    types:
        channel ethernetline extends ThruputMeteringChannel
        {
            delay = 1us;
            datarate = 100Mbps;
            thruputDisplayFormat = "u";
        }

    submodules:
        spanningTree: StaticSpanningTree {
            @display("p=97,108");
        }
        openflowGraphAnalyzer: OpenFlowGraphAnalyzer {
            @display("p=97,39");
        }

        server: StandardHost {
            @display("p=321,229");
        }
        configurator: IPv4NetworkConfigurator {
            parameters:
                @display("p=97,172");
        }

        open_flow_switch1: Open_Flow_Switch {
            @display("p=516,228");
        }
        open_flow_controller1: Open_Flow_Controller if numControllers >=1 {
            @display("p=516,70");
        }
        channelControl: ChannelControl {
            @display("p=97,307");
        }
        binder: LteBinder {
            @display("p=97,383");
        }
        routingRecorder: RoutingTableRecorder {
            @display("p=97,440");
        }
        pgw: PgwStandardSimplified {
            nodeType = "PGW";
            @display("p=516,397");
        }
        eNodeB: eNodeB {
            @display("p=379,397");
        }
        ue[numUe]: Ue {
            @display("p=307,422");
        }
        ueMal[numMal]: Ue {
            @display("p=379,484");
        }

        clientG1[numClients]: StandardHost {
            @display("p=745,229");
        }
        router: Router {
            @display("p=649,397");
        }
    connections:
        open_flow_switch1.gateControlPlane++ <--> ethernetline <--> open_flow_controller1.ethg++;
        server.ethg++ <--> ethernetline <--> open_flow_switch1.gateDataPlane++;
        pgw.pppg++ <--> ethernetline <--> eNodeB.ppp;
        clientG1[0].ethg++ <--> ethernetline <--> open_flow_switch1.gateDataPlane++;
        pgw.filterGate <--> ethernetline <--> router.pppg++;
        router.ethg++ <--> ethernetline <--> open_flow_switch1.gateDataPlane++;
}
