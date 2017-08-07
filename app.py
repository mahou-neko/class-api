#!/usr/bin/env python

from __future__ import print_function
from future.standard_library import install_aliases
install_aliases()

from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError

import json
import os

from flask import Flask
from flask import request
from flask import make_response

# Flask app should start in global layout
app = Flask(__name__)


@app.route('/webhook', methods=['POST'])
def webhook():
    req = request.get_json(silent=True, force=True)

    print("Request:")
    print(json.dumps(req, indent=4))

    res = processRequest(req)

    res = json.dumps(res, indent=4)
    # print(res)
    r = make_response(res)
    r.headers['Content-Type'] = 'application/json'
    return r


def processRequest(req):
    if req.get("result").get("action")=="yahooWeatherForecast":
        baseurl = "https://query.yahooapis.com/v1/public/yql?"
        yql_query = makeYqlQuery(req)
        if yql_query is None:
           return {}
        yql_url = baseurl + urlencode({'q': yql_query}) + "&format=json"
        result = urlopen(yql_url).read()
        data = json.loads(result)
        res = makeWebhookResult(data)

    elif req.get("result").get("action")=="getjoke":
        baseurl = "http://api.icndb.com/jokes/random"
        result = urlopen(baseurl).read()
        data = json.loads(result)
        res = makeWebhookResultForGetJoke(data)

    elif req.get("result").get("action")=="layerabout":
        result = req.get("result")
        parameters = result.get("parameters")
        layer = parameters.get("layer")
        res = makeWebhookResultLayerAbout(layer)

    elif req.get("result").get("action")=="layer4_congestion":
        result = req.get("result")
        parameters = result.get("parameters")
        congestion4 = parameters.get("congestion_control")
        res = congestion_control_layer4(congestion4)

    elif req.get("result").get("action")=="layer2_congestion":
        result = req.get("result")
        parameters = result.get("parameters")
        congestion2 = parameters.get("congestion_control")
        res = congestion_control_layer2(congestion2)

    elif req.get("result").get("action")=="get_protocol_spec":
        result = req.get("result")
        parameters = result.get("parameters")
        prot = parameters.get("protocols")
        res = prot_info(prot)

    elif req.get("result").get("action")=="get_protocol_spec_info":
        result = req.get("result")
        parameters = result.get("parameters")
        prot = parameters.get("protocols")
        res = prot_more_info(prot)

    elif req.get("result").get("action")=="get_protocol_info_more":
        result = req.get("result")
        parameters = result.get("parameters")
        prot = parameters.get("protocols")
        infor = parameters.get("Information")
        res = prot_more_info_more(prot, infor)

    elif req.get("result").get("action")=="get_ipvdiff":
        result = req.get("result")
        parameters = result.get("parameters")
        prot = parameters.get("protocols")
        res = prot_more_info_more("IP", "advantages")

    elif req.get("result").get("action")=="get_layer_info_general":
        result = req.get("result")
        parameters = result.get("parameters")
        res = layer_general_event()

    elif req.get("result").get("action")=="trigger_peer_event":
        result = req.get("result")
        parameters = result.get("parameters")
        res = peer_event()

    elif req.get("result").get("action")=="p2p_info":
        result = req.get("result")
        parameters = result.get("parameters")
        topo = parameters.get("Topologies")
        res = p2p_inf(topo)

    elif req.get("result").get("action")=="layer_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        layer = parameters.get("layer")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        model = parameters.get("Models")
        res = layerintent(layer,info,addinfo,model)

    elif req.get("result").get("action")=="model_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        model = parameters.get("Models")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        res = modelintent(model,info,addinfo)

    elif req.get("result").get("action")=="congestion_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        cong = parameters.get("congestion_control")
        info = parameters.get("Information")
        layer = parameters.get("layer")
        addinfo = parameters.get("addInfo")
        res = congestionintent(cong,info,layer,addinfo)

    elif req.get("result").get("action")=="protocol_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        prot = parameters.get("protocols")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        service = parameters.get("Service")
        res = protocolintent(prot,info,addinfo,service)

    elif req.get("result").get("action")=="service_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        service = parameters.get("Service")
        res = serviceintent(service,addinfo,info)

    elif req.get("result").get("action")=="network_arch_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        netarch = parameters.get("Network-Architectures")
        netcomp = parameters.get("Network-Components")
        topo = parameters.get("Topologies")
        res = netarchintent(netarch,netcomp,topo,addinfo,info)

    elif req.get("result").get("action")=="acronym_intent":
        result = req.get("result")
        parameters = result.get("parameters")
        info = parameters.get("Information")
        addinfo = parameters.get("addInfo")
        netarch = parameters.get("Network-Architectures")
        netcomp = parameters.get("Network-Components")
        topo = parameters.get("Topologies")
        prot = parameters.get("protocols")
        model = parameters.get("Models")
        cong = parameters.get("congestion_control")
        service = parameters.get("Service")
        layer = parameters.get("layer")
        res = acronymintent(info,addinfo,netarch,netcomp,topo,prot,model,cong,service,layer)

    #elif req.get("result").get("action")=="greeting":
        #result = req.get("result")
        #parameters = result.get("parameters")
        #eve = parameters.get("eve")
        #res = makeWebhookResultTriggerEvent()
    else:
        return {}
 
    return res

def makeYqlQuery(req):
    result = req.get("result")
    parameters = result.get("parameters")
    city = parameters.get("geo-city")
    if city is None:
        return None

    return "select * from weather.forecast where woeid in (select woeid from geo.places(1) where text='" + city + "')"

def acronymintent(info,addinfo,netarch,netcomp,topo,prot,model,cong):
    protocols = ['TCP','HTTP','SMTP','IMAP','DNS','SIP','RTP','HTML','IP','UDP','protocol','RPC']
    networkarchs = ['SOA','cloud','SAAS','IAAS','PAAS','client-server','distributed system']
    models = ['OSI','TCP/IP','model']
    congestioncontrols = ['s-aloha','CSMA','CSMA/CD','CSMA/CA','RED']

    if topo == "peer-to-peer" or topo == "dht":
        return netarchintent(netarch,netcomp,topo,addinfo,info) #add contextname to params and change context accordingly 
    if cong in congestioncontrols:
        return congestionintent(cong,info,layer,addinfo)
    if model in models:
        return modelintent(model,info,addinfo)
    if netarch in networkarchs:
        return netarchintent(netarch,netcomp,topo,addinfo,info)
    if prot in protocols:
        return protocolintent(prot,info,addinfo,service)

    speech = "I am sorry, but I do not know the meaning of this acronym... However, I can ask someone and get back to you, if thats okay 😊"


    contextname = "acronym_intent" #add reset context for no follow up

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Network-Architectures":netarch,"Network-Components":netcomp,"Topologies":topo,"protocols":prot,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def acronymintent_first_try(info,addinfo,netarch,netcomp,topo,prot,model):
    net_arch_acro = {'SOA':'SOA = Service Oriented Architectures',
                        'SAAS':'SAAS = Software AS A Service',
                        'IAAS':'IAAS = Infrastructure As A Service',
                        'PAAS':'PAAS = Platform AS A Service'}
    prot_acro = {'TCP':'TCP = Transmission Control Protocol',
                'HTTP':'HTTP = Hyper Text Transfer Protocol',
                'SMTP':'SMTP = Simple Mail Transport Protocol',
                'IMAP':'IMAP = Internet Message Access Protocol',
                'DNS':'DNS = Domain Name System',
                'SIP':'SIP = Session Initiation Protocol',
                'RTP':'RTP = Real-time Transport Protocol',
                'HTML':'HTML = Hypertext Markup Language',
                'IP':'IP = Internet Protocol',
                'UDP':'UDP = User Datagram Protocol',
                'protocol':'Protocols are sets of rules which give structure and meaning to exchanged messages. They are deployed for implementing Services and are usually not distinguishable for users. Would you like to know something about services?',
                'RPC':'RPC = Remote Procedure Call',
                'RED':'RED = Random Early Detection',
                }
    model_acro = {'OSI':'OSI model = Open Systems Interconnection model',
                    'TCP/IP':'TCP/IP = Internet protocol suite named after the originally used protocols Transmission Control Protocol (TCP) and the Internet Protocol (IP)'}
    #congestion could be added here as well as models
    if netarch in net_arch_acro:
        speech = net_arch_acro[netarch]
    elif prot in prot_acro:
        speech = prot_acro[prot]
    elif model in model_acro:
        speech = model_acro[model]

    if model == "model":
        speech = "There are two types of conceptual models which are used on the Internet and similar comupter networks to facilitate communication and offer services. One would be the TCP/IP model and the other would be the OSI model. 😊 Which model would you like to know more about?"
        addinfo = "moreM"
    if prot == "protocols":
        speech = "Protocols are sets of rules which give structure and meaning to exchanged messages. They are deployed for implementing Services and are usually not distinguishable for users. Would you like to know something about services?"
        addinfo = "moreP"
    contextname = "acronym_conversation"
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Network-Architectures":netarch,"Network-Components":netcomp,"Topologies":topo,"protocols":prot,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }


def netarchintent(netarch,netcomp,topo,addinfo,info):
    net_arch_def = {'cloud':'Well clouds are means to deploy massive and mostly transparent distributed networks. The common use resources increases the workload and hence reduces costs. Would you like to hear more about the different types of cloud services?',
                    'SOA':'Alright! SOA - service oriented architectures- envision to combine reusable services (which could be obtained from different providers) in order to compose a (commercial) application.',
                    'moreC':'Awesome! 😎 The greatest distinction would be between public and private clouds. Public clouds are mutually used by many users while private ones are just used by one cooperation or even just one person!',
                    'networktopology':'Network topology is the arrangement of the various elements (links, nodes, etc.) of a computer network. Essentially, it is the topological structure of a network and may be depicted physically or logically. Physical topology is the placement of the various components of a network, including device location and cable installation, while logical topology illustrates how data flows within a network, regardless of its physical design. Distances between nodes, physical interconnections, transmission rates, or signal types may differ between two networks, yet their topologies may be identical.',
                    'distributed system':'A distributed system is a model in which components located on networked computers communicate and coordinate their actions by passing messages. The components interact with each other in order to achieve a common goal. Three significant characteristics of distributed systems are: concurrency of components, lack of a global clock, and independent failure of components. Examples of distributed systems vary from SOA-based systems to massively multiplayer online games to peer-to-peer applications.',
                    'moreCD':'Public clouds are mutually used by many users while private ones are just used by one cooperation or even just one person!',
                    'SAAS':'In the software as a service (SaaS) model, users gain access to application software and databases. Cloud providers manage the infrastructure and platforms that run the applications. SaaS is sometimes referred to as "on-demand software" and is usually priced on a pay-per-use basis or using a subscription fee.[86] In the SaaS model, cloud providers install and operate application software in the cloud and cloud users access the software from cloud clients. Cloud users do not manage the cloud infrastructure and platform where the application runs. This eliminates the need to install and run the application on the cloud users own computers, which simplifies maintenance and support. Cloud applications differ from other applications in their scalability—which can be achieved by cloning tasks onto multiple virtual machines at run-time to meet changing work demand. Load balancers distribute the work over the set of virtual machines. This process is transparent to the cloud user, who sees only a single access-point. To accommodate a large number of cloud users, cloud applications can be multitenant, meaning that any machine may serve more than one cloud-user organization.',
                    'IAAS':'According to the Internet Engineering Task Force (IETF), the most basic cloud-service model is that of providers offering computing infrastructure – virtual machines and other resources – as a service to subscribers. Infrastructure as a service (IaaS) refers to online services that provide high-level APIs used to dereference various low-level details of underlying network infrastructure like physical computing resources, location, data partitioning, scaling, security, backup etc. A hypervisor, such as Xen, Oracle VirtualBox, Oracle VM, KVM, VMware ESX/ESXi, or Hyper-V, LXD, runs the virtual machines as guests. Pools of hypervisors within the cloud operational system can support large numbers of virtual machines and the ability to scale services up and down according to customers varying requirements.',
                    'PAAS':'PaaS vendors offer a development environment to application developers. The provider typically develops toolkit and standards for development and channels for distribution and payment. In the PaaS models, cloud providers deliver a computing platform, typically including operating system, programming-language execution environment, database, and web server. Application developers can develop and run their software solutions on a cloud platform without the cost and complexity of buying and managing the underlying hardware and software layers. With some PaaS offers like Microsoft Azure and Google App Engine, the underlying computer and storage resources scale automatically to match application demand so that the cloud user does not have to allocate resources manually. The latter has also been proposed by an architecture aiming to facilitate real-time in cloud environments.',
                    'peer-to-peer':'Peer-to-peer (P2P) computing or networking is a distributed application architecture that partitions tasks or workloads between peers. Peers are equally privileged, equipotent participants in the application. They are said to form a peer-to-peer network of nodes. Would you like to hear more?',
                    'client-server-d':'For distributed systems with centralised control there are a few network designs which rank between two extremes: thin clients with fat servers (meaning that the client side is less computationally and storage wise exerted) and the exact contrary with a fat client (which does all the heavy lifting) and a thin server.',
                    'types':'There are centralised, federal and decentralised topologies for distributed systems. Centralised ones are on the end of the asymmetric scale while decentralised ones are more prone to be symmetric.',
                    'overlay':'So overlays are basically logic networks which reside on top of already existing networks (in those cases called underlays). I could tell you a bit more about them, but only if you want to 😊',
                    'moreO':'Good choice! 😁 Their topology can differ a lot from the underlays since overlay networks are pretty independent and have their own addresses and routing paths.',
                    'p2pv1':'Every node of the overlay knows k > 2 other nodes. Data gets flooded over the edges and every node contains every information.',
                    'network':'A computer network or data network is a digital telecommunications network which allows nodes to share resources. In computer networks, networked computing devices exchange data with each other using a data link. The connections between nodes are established using either cable media or wireless media.',
                    'client-server':'The client–server model is a distributed application structure that partitions tasks or workloads between the providers of a resource or service, called servers, and service requesters, called clients. Often clients and servers communicate over a computer network on separate hardware, but both client and server may reside in the same system. A server host runs one or more server programs which share their resources with clients. A client does not share any of its resources, but requests a servers content or service function. Clients therefore initiate communication sessions with servers which await incoming requests. Examples of computer applications that use the client–server model are Email, network printing, and the World Wide Web.',
                    'client':'A client is a piece of computer hardware or software that accesses a service made available by a server. The server is often (but not always) on another computer system, in which case the client accesses the service by way of a network. The term applies to the role that programs or devices play in the client–server model.',
                    'nodes':'Network computer devices that originate, route and terminate the data are called network nodes. Nodes can include hosts such as personal computers, phones, servers as well as networking hardware. Two such devices can be said to be networked together when one device is able to exchange information with the other device, whether or not they have a direct connection to each other. In most cases, application-specific communications protocols are layered (i.e. carried as payload) over other more general communications protocols. This formidable collection of information technology requires skilled network management to keep it all running reliably.',
                    'server':'In computing, a server is a computer program or a device that provides functionality for other programs or devices, called "clients". This architecture is called the client–server model, and a single overall computation is distributed across multiple processes or devices. Servers can provide various functionalities, often called "services", such as sharing data or resources among multiple clients, or performing computation for a client. A single server can serve multiple clients, and a single client can use multiple servers. A client process may run on the same device or may connect over a network to a server on a different device. Typical servers are database servers, file servers, mail servers, print servers, web servers, game servers, and application servers.',
                    'p2pv2':'Every node contains only a small fraction of the data. Hence rare content is hard to find. This type of p2p is usually deployed via directory servers or flooding with backtracking.',
                    'dht':'Distributed Hash-Tables are a structured p2p overlay and utilizes a dynamic number of nodes. I realizes a cyclic data space and since every node knows the address of its logical successor, the complexity of searches is reduced to O(n).',
                    'unstructured peer':'Unstructured peer-to-peer networks do not impose a particular structure on the overlay network by design, but rather are formed by nodes that randomly form connections to each other.',
                    'structured peer':'In structured peer-to-peer networks the overlay is organized into a specific topology, and the protocol ensures that any node can efficiently search the network for a file/resource, even if the resource is extremely rare.'}
    #define SOA, cloud, SAAS, IAAS, PAAS, client-server, distributed system - network arch
    #define network, client, server, thin client, thin server, fat server, fat client - network components
    #define topology, centralised, decentralised, federal, overlay, networktopology, symmetric, asymmetric, peer-to-peer, p2pv1, p2pv2
    #structured peer, unstructured peer - topologies
    #and further
    net_arch_acro = {'SOA':'SOA = Service Oriented Architectures',
                        'SAAS':'SAAS = Software AS A Service',
                        'IAAS':'IAAS = Infrastructure As A Service',
                        'PAAS':'PAAS = Platform AS A Service'}
    synonyms_client_server = ["fat server","thin server","thin client","fat client"]
    synonyms_topo = {"federal","symmetric","Asymmetric","centralised","decentralised"}
    net_arch_coll = ["SAAS","IAAS","SOA","PAAS"]

    if topo == "topology":
        topo = "networktopology"
    if netcomp in synonyms_client_server or (netarch == "client-server" and info == "types"): #find better solution
        netcomp = "client-server-d"
    if topo in synonyms_topo:
        info = "types"
    if topo == "p2p":
        topo = "peer-to-peer"

    if netarch in net_arch_def:
        speech = net_arch_def[netarch]
    if addinfo == "moreC":
        speech = net_arch_def[addinfo]
    if netcomp in net_arch_def:
        speech = net_arch_def[netcomp]
    if topo in net_arch_def:
        speech = net_arch_def[topo]

    if addinfo == "moreA" and netarch in net_arch_def:
        speech = net_arch_def[netarch]
        contextname = "netarch_conversation"
        return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Network-Architectures":netarch,"Network-Components":netcomp,"Topologies":topo,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"}
    if addinfo == "moreO" or addinfo == "moreC":
        speech = net_arch_def[addinfo]
        addinfo = "more"
        contextname = "netarch_conversation"
        return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Network-Architectures":netarch,"Network-Components":netcomp,"Topologies":topo,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"}

    if info == "types" and netarch != "client-server": #more sophisticated
        speech = net_arch_def[info]
    if info == "acronym" and netarch in net_arch_coll:
        speech = net_arch_acro[netarch] + " Would you like to know more about " + netarch + " ?😊"
        info = "more"
        addinfo = "moreA"
    #check for more in order to get full explanation
    if info == "difference" or info == "types" and netarch == "cloud":
        speech = net_arch_def['moreCD']

    if netarch == "cloud":
        addinfo = "moreC"
    if topo == "overlay":
        addinfo = "moreO"
    if topo == "peer-to-peer" and addinfo == "moreP":
        speech = "Cool! 😎 Would you like to hear about structured or unstructured peer-to-peer networks?"
    if topo == "peer-to-peer":
        addinfo = "moreP"

    contextname = "netarch_conversation"
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Network-Architectures":netarch,"Network-Components":netcomp,"Topologies":topo,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def protocolintent(prot,info,addinfo,service):
    protocol_defs = {'protocol':'Protocols are sets of rules which give structure and meaning to exchanged messages. They are deployed for implementing Services and are usually not distinguishable for users. Would you like to know something about services?',
                    'TCP':'The Transmission Control Protocol (TCP) is one of the main protocols of the Internet protocol suite. It originated in the initial network implementation in which it complemented the Internet Protocol (IP). Therefore, the entire suite is commonly referred to as TCP/IP. TCP provides reliable, ordered, and error-checked delivery of a stream of octets between applications running on hosts communicating by an IP network. Major Internet applications such as the World Wide Web, email, remote administration, and file transfer rely on TCP.',
                    'HTTP':'The Hypertext Transfer Protocol (HTTP) is an application protocol for distributed, collaborative, and hypermedia information systems. HTTP is the foundation of data communication for the World Wide Web. Hypertext is structured text that uses logical links (hyperlinks) between nodes containing text. HTTP is the protocol to exchange or transfer hypertext.',
                    'SMTP':'Simple Mail Transfer Protocol (SMTP) is an Internet standard for electronic mail (email) transmission. Although electronic mail servers and other mail transfer agents use SMTP to send and receive mail messages, user-level client mail applications typically use SMTP only for sending messages to a mail server for relaying. For retrieving messages, client applications usually use either IMAP or POP3.',
                    'IMAP':'In computing, the Internet Message Access Protocol (IMAP) is an Internet standard protocol used by e-mail clients to retrieve e-mail messages from a mail server over a TCP/IP connection. IMAP was designed with the goal of permitting complete management of an email box by multiple email clients, therefore clients generally leave messages on the server until the user explicitly deletes them.',
                    'DNS':'The Domain Name System (DNS) is a hierarchical decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols. By providing a worldwide, distributed directory service, the Domain Name System is an essential component of the functionality on the Internet, that has been in use since 1985.',
                    'SIP':'The Session Initiation Protocol (SIP) is a communications protocol for signaling and controlling multimedia communication sessions in applications of Internet telephony for voice and video calls, in private IP telephone systems, as well as in instant messaging over Internet Protocol (IP) networks. SIP works in conjunction with several other protocols that specify and carry the session media. Media type and parameter negotiation and media setup is performed with the Session Description Protocol (SDP), which is carried as payload in SIP messages. For the transmission of media streams (voice, video) SIP typically employs the Real-time Transport Protocol (RTP) or the Secure Real-time Transport Protocol (SRTP).',
                    'RTP':'The Real-time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks. RTP is used extensively in communication and entertainment systems that involve streaming media, such as telephony, video teleconference applications, television services and web-based push-to-talk features. RTP typically runs over User Datagram Protocol (UDP). RTP is used in conjunction with the RTP Control Protocol (RTCP). While RTP carries the media streams (e.g., audio and video), RTCP is used to monitor transmission statistics and quality of service (QoS) and aids synchronization of multiple streams. RTP is one of the technical foundations of Voice over IP and in this context is often used in conjunction with a signaling protocol such as the Session Initiation Protocol (SIP) which establishes connections across the network.',
                    'HTML':'Hypertext Markup Language (HTML) is the standard markup language for creating web pages and web applications. With Cascading Style Sheets (CSS) and JavaScript it forms a triad of cornerstone technologies for the World Wide Web. Web browsers receive HTML documents from a webserver or from local storage and render them into multimedia web pages. HTML describes the structure of a web page semantically and originally included cues for the appearance of the document.',
                    'IP':'The Internet Protocol (IP) is the principal communications protocol in the Internet protocol suite for relaying datagrams across network boundaries. Its routing function enables internetworking, and essentially establishes the Internet. IP has the task of delivering packets from the source host to the destination host solely based on the IP addresses in the packet headers. For this purpose, IP defines packet structures that encapsulate the data to be delivered. It also defines addressing methods that are used to label the datagram with source and destination information.',
                    'UDP':'In electronic communication, the User Datagram Protocol (UDP) is one of the core members of the Internet protocol suite. With UDP, computer applications can send messages, in this case referred to as datagrams, to other hosts on an Internet Protocol (IP) network. Prior communications are not required in order to set up transmission channels or data paths. UDP uses a simple connectionless transmission model with a minimum of protocol mechanism. UDP provides checksums for data integrity, and port numbers for addressing different functions at the source and destination of the datagram. It has no handshaking dialogues, and thus exposes the users program to any unreliability of the underlying network: there is no guarantee of delivery, ordering, or duplicate protection',
                    'RPC':'n distributed computing, a remote procedure call (RPC) is when a computer program causes a procedure (subroutine) to execute in a different address space (commonly on another computer on a shared network), which is coded as if it were a normal (local) procedure call, without the programmer explicitly coding the details for the remote interaction. That is, the programmer writes essentially the same code whether the subroutine is local to the executing program, or remote. This is a form of client–server interaction (caller is client, executor is server), typically implemented via a request–response message-passing system.'
                    }
    prot_acro = {'TCP':'TCP = Transmission Control Protocol',
                'HTTP':'HTTP = Hyper Text Transfer Protocol',
                'SMTP':'SMTP = Simple Mail Transport Protocol',
                'IMAP':'IMAP = Internet Message Access Protocol',
                'DNS':'DNS = Domain Name System',
                'SIP':'SIP = Session Initiation Protocol',
                'RTP':'RTP = Real-time Transport Protocol',
                'HTML':'HTML = Hypertext Markup Language',
                'IP':'IP = Internet Protocol',
                'UDP':'UDP = User Datagram Protocol',
                'protocol':'Protocols are sets of rules which give structure and meaning to exchanged messages. They are deployed for implementing Services and are usually not distinguishable for users. Would you like to know something about services?',
                'RPC':'RPC = Remote Procedure Call'
                }
    prot_diff = {'IP':'The main differences between IPv4 and IPv6 consist of the checksum, the header length, fragmentation handeling and no header options for IPv6.',
                'TCP':'There are two types of Internet Protocol (IP) traffic. They are TCP or Transmission Control Protocol and UDP or User Datagram Protocol. TCP is connection oriented – once a connection is established, data can be sent bidirectional. UDP is a simpler, connectionless Internet protocol.',
                'UDP':'There are two types of Internet Protocol (IP) traffic. They are TCP or Transmission Control Protocol and UDP or User Datagram Protocol. TCP is connection oriented – once a connection is established, data can be sent bidirectional. UDP is a simpler, connectionless Internet protocol.'}

    contextname = "protocol_conversation"
    #info = "more"
    if service == "service":
        return serviceintent(service, addinfo, info)
    if addinfo == "moreAcro":
        speech = protocol_defs[prot]
        addinfo = "moreSpecific"
        return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"protocols":prot,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
        }
    if addinfo == "moreSpecific":
        speech = "I can tell you about advantages, issues, alternatives and differences of protocols. What would you like to know more about?"
        if prot == "protocol":
            speech = "Which protocol would you like to hear more about?"
        addinfo = "more"
        return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"protocols":prot,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
        }
    if info == "acronym":
        if prot in prot_acro:
            speech = prot_acro[prot] + " Would you like to hear more? 😊"
            addinfo = "moreAcro" #reset info maybe
        else:
            speech = "That's ebarassing... I am not sure about this acronym... But I can ask someone who'll know and get back to you if you'd like!"
    elif prot in protocol_defs:
        speech = protocol_defs[prot] + " Would you like to know something specific about " + prot + " ? 😊"
        addinfo = "moreSpecific"
    else:
        speech = "I am terribly sorry, but I am not sure about this protocol... I could ask someone about it and get back to you - if that's okay 😊"

    #change advantages, issues, alternatives to dic. here
    if info == "advantages" and prot in prot_acro:
        speech = prot_advantages(prot)
    if info == "issues" and prot in prot_acro:
        speech = prot_disadvantages(prot)
    if info == "alternatives" and prot in prot_acro:
        speech = prot_alternatives(prot)
    if info == "difference" and prot in prot_diff:
        speech = prot_diff[prot]

    #addinfo = "more" 
    #handle even furhter information etc

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"protocols":prot,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def trigger_service():
    return{"followupEvent":{"name":"service_event","data":{" ":" "}}}


def serviceintent(service, addinfo, info):
    service_def = {'service':'Alright 😊 Services are a set of available functions. The details of those function, however, is hidden from higher layers. Would you like to hear more about layers or a specific service?',
                    'SOA':'Alright! SOA - service oriented architectures- envision to combine reusable services (which could be obtained from different providers) in order to compose a (commercial) application.'}
    #could add case for layers and specific services and expand with hear more

    if service in service_def and addinfo != "more":
        speech = service_def[service]

    if addinfo == "more" and service == "service":
        speech = "Which service or which layer would you like to know more about? 😊"
        contextname = "service_conversation"
        addinfo = ""
        info = "more"
        return {
            "speech": speech,
            "displayText": speech,
            # "data": data,
            "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"service":service,"info":info,"addInfo":addinfo}}],
            "source": "apiai-weather-webhook-sample"
        }
    #for specific information as well

    info = "more"
    addinfo = "more"
    contextname = "service_conversation"
    
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"service":service,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def congestionintent(cong,info,layer,addinfo):
    #more elaborate on methods
    cong_defs = {'congestion control general':'Congestion Control is handled by layer 2 and 4 of the OSI model. Which layer are you interested in the most?',
                    'data link layer':'Alright! Layer 2 - the data link layer -  it is! 😊 Congestion Control on the second layer deals with media access control by avoiding, detecting and resolving collisions. Would you like to know more about that?',
                    'more2':'Got it! 😎 On the data link layer congestion control is deployed via ALOHA, S-ALOHA and CSMA/CD as well as CSMA/CA. Would you like to hear more?',
                    'more22':'Great! Which access method would you like to learn more about?',
                    'more44':'Cool! 😎 Would like to hear more about Reno or Tahoe or rather something about tcp congestion control?',
                    'moreCG':'Awesome! 😊 Would you like to hear more about layer 2 or layer 4 congestion control?',
                    'types' : 'On the data link layer congestion control is deployed via ALOHA, S-ALOHA and CSMA/CD as well as CSMA/CA. Methods for congestion avoidance rank from slower (preventive) to fast (reactive) approaches. From preventive to reactive those approaches would be: expanding -  redirecting - access control - choking - rejecting. The  most commonly used congestion control methods are Reno and Tahoe in combination with TCP.',
                    'moreRed':'In the conventional tail drop algorithm, a router or other network component buffers as many packets as it can, and simply drops the ones it cannot buffer. If buffers are constantly full, the network is congested. Tail drop distributes buffer space unfairly among traffic flows. Tail drop can also lead to TCP global synchronization as all TCP connections "hold back" simultaneously, and then step forward simultaneously. Networks become under-utilized and flooded by turns. RED addresses these issues.',
                    'transport layer':'Okay, Congestion control for the transport layer! 😎 Congestion control on the transport layer handels end-to-end congestion control. Would you like to hear more about it?',
                    'more4':'Methods for congestion avoidance rank from slower (preventive) to fast (reactive) approaches. From preventive to reactive those approaches would be: expanding -  redirecting - access control - choking - rejecting. The  most commonly used congestion control methods are Reno and Tahoe in combination with TCP. Would you be interested to hear more?'}
    con_methods = {'aloha':'The first version of the protocol was quite simple: If you have data to send, send the data - If, while you are transmitting data, you receive any data from another station, there has been a message collision. All transmitting stations will need to try resending "later". Note that the first step implies that Pure ALOHA does not check whether the channel is busy before transmitting. Since collisions can occur and data may have to be sent again, ALOHA cannot use 100 percent of the capacity of the communications channel. How long a station waits until it transmits, and the likelihood a collision occurs are interrelated, and both affect how efficiently the channel can be used.',
                    's-aloha':'An improvement to the original ALOHA protocol was "Slotted ALOHA", which introduced discrete timeslots and increased the maximum throughput. A station can start a transmission only at the beginning of a timeslot, and thus collisions are reduced. In this case, only transmission-attempts within 1 frame-time and not 2 consecutive frame-times need to be considered, since collisions can only occur during each timeslot.',
                    'CSMA':'Carrier-sense multiple access (CSMA) is a media access control (MAC) protocol in which a node verifies the absence of other traffic before transmitting on a shared transmission medium. A transmitter attempts to determine whether another transmission is in progress before initiating a transmission using a carrier-sense mechanism. That is, it tries to detect the presence of a carrier signal from another node before attempting to transmit.',
                    'CSMA/CD':'CSMA/CD is used to improve CSMA performance by terminating transmission as soon as a collision is detected, thus shortening the time required before a retry can be attempted.',
                    'CSMA/CA':'In CSMA/CA collision avoidance is used to improve the performance of CSMA. If the transmission medium is sensed busy before transmission, then the transmission is deferred for a random interval. This random interval reduces the likelihood that two or more nodes waiting to transmit will simultaneously begin transmission upon termination of the detected transmission, thus reducing the incidence of collision.',
                    'reno':'If three duplicate ACKs are received, Reno will perform a fast retransmit and skip the slow start phase (which is part of Tahoe s procedure) by instead halving the congestion window (instead of setting it to 1 MSS like Tahoe), setting the slow start threshold equal to the new congestion window, and enter a phase called Fast Recovery.',
                    'tahoe':'If three duplicate ACKs are received, Tahoe performs a fast retransmit, sets the slow start threshold to half of the current congestion window, reduces the congestion window to 1 MSS, and resets to slow start state',
                    'TCP congestion control':'Congestion control via TCP is deployed either with Reno or Tahoe. Whenever duplicate ACKs are received either a slow start or a fast recovery is performed',
                    'RED':'Random Early Detection is a queueing discipline for a network scheduler suited for congestion avoidance. Do you want to know more?',
                    'congestion control general':'Alright 😎 Network Congestion is the reduced quality of service that occurs when a network node is carrying more data than it can handle. Typical effects include queueing delay, packet loss or the blocking of new connections. A consequence of congestion is that an incremental increase in offered load leads either only to a small increase or even a decrease in network throughput. Congestion control tries to combat this issue. Layer 2 and 4 of the OSI model are concerned with congestion control. Would you like to know more?'}
    if addinfo in cong_defs:
        speech = cong_defs[addinfo]
        if addinfo == "more2":
            addinfo = "more22"
        if addinfo == "more4":
            addinfo = "more44"
    if cong in con_methods:
        speech = con_methods[cong]
        if cong == "congestion control general":
            addinfo = "moreCG"
        if cong == "RED":
            addinfo = "moreRed"
    if info in cong_defs:
        speech = cong_defs[info]
    if layer in cong_defs:
        speech = cong_defs[layer]
        if layer == "data link layer":
            addinfo = "more2"
        if layer == "transport layer":
            addinfo = "more4"
    #else:
        #speech = "Sorry... I guess this topic slipped my mind... I can ask someone who'll know more if you'd like me too!"

    contextname = "congestion_conversation"
    #addinfo = "moreRed" expand to other answers

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"congestion_control":cong,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def congestion_addInfo(cong,info,layer,addinfo):
    cong_defs = {'congestion control general':'Congestion Control is handled by layer 2 and 4 of the OSI model. Which layer are you interested in the most?',
                    'data link layer':'Alright! Layer 2 - the data link layer -  it is! 😊 Congestion Control on the second layer deals with media access control by avoiding, detecting and resolving collisions. Would you like to know more about that?',
                    'more2':'Got it! 😎 On the data link layer congestion control is deployed via ALOHA, S-ALOHA and CSMA/CD as well as CSMA/CA. Would you like to hear more?',
                    'more22':'Great! Which access method would you like to learn more about?',
                    'moreCG':'Awesome! 😊 Would you like to hear more about layer 2 or layer 4 congestion control?',
                    'types' : 'On the data link layer congestion control is deployed via ALOHA, S-ALOHA and CSMA/CD as well as CSMA/CA. Methods for congestion avoidance rank from slower (preventive) to fast (reactive) approaches. From preventive to reactive those approaches would be: expanding -  redirecting - access control - choking - rejecting. The  most commonly used congestion control methods are Reno and Tahoe in combination with TCP.',
                    'moreRed':'In the conventional tail drop algorithm, a router or other network component buffers as many packets as it can, and simply drops the ones it cannot buffer. If buffers are constantly full, the network is congested. Tail drop distributes buffer space unfairly among traffic flows. Tail drop can also lead to TCP global synchronization as all TCP connections "hold back" simultaneously, and then step forward simultaneously. Networks become under-utilized and flooded by turns. RED addresses these issues.',
                    'transport layer':'Okay, Congestion control for the transport layer! 😎 Congestion control on the transport layer handels end-to-end congestion control. Would you like to hear more about it?',
                    'more4':'Methods for congestion avoidance rank from slower (preventive) to fast (reactive) approaches. From preventive to reactive those approaches would be: expanding -  redirecting - access control - choking - rejecting. The  most commonly used congestion control methods are Reno and Tahoe in combination with TCP. Would you be interested to hear more?'}
    if addinfo in cong_defs:
        speech = cong_defs[addinfo]
        if addinfo == "more2":
            addinfo = "more22"
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"congestion_control":cong,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }


def modelintent(model,info,addinfo):
    model_defs = {'TCP/IP':'Alright 😊 The Internet protocol suite provides end-to-end data communication specifying how data should be packetized, addressed, transmitted, routed and received. This functionality is organized into four abstraction layers which are used to sort all related protocols according to the scope of networking involved.',
                    'OSI':'Got cha! 😎 The Open Systems Interconnection model (OSI model) is a conceptual model that characterizes and standardizes the communication functions of a telecommunication or computing system without regard to their underlying internal structure and technology. Its goal is the interoperability of diverse communication systems with standard protocols. The model partitions a communication system into abstraction layers. The original version of the model defined seven layers.',
                    'model':'There are two types of conceptual models which are used on the Internet and similar comupter networks to facilitate communication and offer services. One would be the TCP/IP model and the other would be the OSI model. 😊',
                    'difference':'When it comes to general reliability, TCP/IP is considered to be a more reliable option as opposed to OSI model. The OSI model is, in most cases, referred to as a reference tool, being the older of the two models. OSI is also known for its strict protocol and boundaries. This is not the case with TCP/IP. It allows for a loosening of the rules, provided the general guidelines are met. Would you like to hear more?',
                    'moreD':'When it comes to the communications, TCP/IP supports only connectionless communication emanating from the network layer. OSI, on the other hand, seems to do quite well, supporting both connectionless and connection-oriented communication within the network layer. Last but not least is the protocol dependency of the two. TCP/IP is a protocol dependent model, whereas OSI is a protocol independent standard.'}
                    #fix moreD!
    if model in model_defs:
        speech = model_defs[model]
    else:
        speech = "I am terribly sorry... but I am not sure about the " + model + "model... Would you like me to ask someone and get back to you? 😊"

    if model != "model": #could be expanded to specific model questions and more about one model
        speech = speech + " Shall I tell you more about the layers of the " + model + " model 😊?"
    else:
        speech = speech + " Would you like to hear more about one of them? 😊"

    contextname = "model_conversation"

    #own speech return might be better!
    if addinfo == "moreD":
        speech = model_defs[addinfo] #just in model_defs[info] would be cleaner - also use addintional info for more extraction
        return {
            "speech": speech,
            "displayText": speech,
            # "data": data,
            "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Models":model,"info":info,"addInfo":addinfo}}],
            "source": "apiai-weather-webhook-sample"
            }
    if info == "more":
        if model == "TCP/IP": #set different context
            return layerintent("tcpip-layers","general"," "," ") #reset models followup for it to work with layers
        elif model == "OSI":
            return layerintent("osi-layers","general"," "," ")
        elif model == "model":
            speech = "Which one would you like to hear more about? 😎"
    if info == "difference":
        speech = model_defs[info] #define own return here with layer contexts
        addinfo = "moreD"
    #info = "more"
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"Models":model,"info":info,"addInfo":addinfo}}],
        "source": "apiai-weather-webhook-sample"
    }

def layerintent(layer, info, addinfo, model):
    layerdef = {'physical layer':'The physical layer handels mechanical and electrical/optical linkage. It converts logical symbols into electrical(optical) ones and measures optical signals to reconstruct logical symbols', 
    'data link layer':'Got it! ☺️ The data link layer covers transmission errors and handels media access. \n It is also concerned with congestion control.', 
    'network layer':'On the network layer paths from senders to recipients are chosen. Hence this layer also has to cope with heterogenius subnets and is responsibe for accounting.',
    'transport layer':'The transport layer offers secure end-to-end-communication between processes. Therefore it is also in charge for data stream control between endsystems. A few concerns of this layer are multiplexing, segmentation and acknowledgements in order to provide reliable transmission.',
    'session layer':'The name of this layer almost gives all its functionalities away! It mostly deals with communication managment, dialog control and synchronization.',
    'presentation layer':'Converting between dataformats, compression and decrompession as well as encryption are the main converns of the presentation layer.',
    'application layer':'Its name almost tells it all. The application layer handels communication between applications and deals with application specific services like e-mail, telnet etc.',
    'layer':'Alright! Layers basically are subdivisions of communication models. A Layer basically is a collection of similar functions that provide services to the layer above it and receives services from the layer below it.',
    'internet':'The internet layer has the same responsabilites as the third layer of the OSI model (which would be the network layer).',
    'link':'The link layer corresponds to the OSI model layers 1 and 2 (physical layer and data link layer).',
    'layer':'Alright layer general it is! Layers are a way of sub-dividing a communications system further into smaller parts called layers. A layer is a collection of similar functions that provide services to the layer above it and receives services from the layer below it. On each layer, an instance provides services to the instances at the layer above and requests service from the layer below. They can be subsumed to models like the OSI or TCP/IP model.'}

    layermodel = {'osi-layers':'The layers of the OSI model are (from lowest level to highest) - 1 physical layer - 2 data link layer - 3 network layer - 4 transport layer - 5 session layer - 6 presentation layer - 7 application layer. Would you like to know more about a specific layer?',
                    'tcpip-layers':'There are 4 layers in the TCP/IP model. Those would be (from lowest to highest) - 1 Link - 2 Internet - 3 Transport - 4 Application. Would you like to hear more about a specific layer?'}

    #fix more and correct defs (not best placement/usefullness)
    model_defs = {'types':'There are 7 layers in the OSI model and 4 in the TCP/IP model. Which one would you like to learn more about?',
                    'difference':'When it comes to general reliability, TCP/IP is considered to be a more reliable option as opposed to OSI model. The OSI model is, in most cases, referred to as a reference tool, being the older of the two models. OSI is also known for its strict protocol and boundaries. This is not the case with TCP/IP. It allows for a loosening of the rules, provided the general guidelines are met. Would you like to hear more?',
                    'more':'When it comes to the communications, TCP/IP supports only connectionless communication emanating from the network layer. OSI, on the other hand, seems to do quite well, supporting both connectionless and connection-oriented communication within the network layer. Last but not least is the protocol dependency of the two. TCP/IP is a protocol dependent model, whereas OSI is a protocol independent standard.'}

    if layer in layerdef:
        speech = layerdef[layer] + " Would you like to hear more? ☺️" 
        if layer == "layer" and addinfo == "more":
            speech = "Great! Would you like to hear more about osi layers or tcp/ip layers?"
            addinfo = ""
        if addinfo == "more" and layer != "layer":
            speech = "Awesome ☺️ What would you like to know more about the " + layer +"?"

        contextname = "layer_conversation"
    elif layer in layermodel:
        speech = layermodel[layer] + " Shall I tell you more about the layers of the specific model? ☺️" #add for yes followup custom hear more
        contextname = "layer_model"
    else:
        return {"followupEvent":{"name":"fallback_trigger","data":{" ":" "}}}
        #speech = "I am sorry, but I don't know about the " + layer + ". Shall I ask someone and get back to you once I know more?" 
        #contextname = "ask_help"
    if info in model_defs:
        speech = model_defs[info]
        contextname = "layer_model"
        if info == "difference":
            contextname = "layer_more" #expand this! and be carful with context -> reset!
    if model == "OSI":
        speech = layermodel['osi-layers'] #reset context
        model = " "
    if model == "TCP/IP":
        speech = layermodel['tcpip-layers']
        model = " "

    addinfo = "more"
    if info == "more":
        speech = "Okay! Here comes more about the " + layer + " 😎"
        #could set context here for spevific more for looping information
        #should be in its own more function
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"layer":layer,"info":info,"addInfo":addinfo,"Models":model}},{"name":"Layer-followup","lifespan":3,"parameters":{}}],
        "source": "apiai-weather-webhook-sample"
    }

#def more_about_layer
#redesign for general follow-up
def layer_more(layer, info):
    model_defs = {'types':'There are 7 layers in the OSI model and 4 in the TCP/IP model. Which one would you like to learn more about?',
                    'difference':'When it comes to general reliability, TCP/IP is considered to be a more reliable option as opposed to OSI model. The OSI model is, in most cases, referred to as a reference tool, being the older of the two models. OSI is also known for its strict protocol and boundaries. This is not the case with TCP/IP. It allows for a loosening of the rules, provided the general guidelines are met. Would you like to hear more?',
                    'more':'When it comes to the communications, TCP/IP supports only connectionless communication emanating from the network layer. OSI, on the other hand, seems to do quite well, supporting both connectionless and connection-oriented communication within the network layer. Last but not least is the protocol dependency of the two. TCP/IP is a protocol dependent model, whereas OSI is a protocol independent standard.'}
    speech = model_defs[info]
    contextname = "layer_model"
    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        "contextOut": [{"name":contextname,"lifespan":3,"parameters":{"layer":layer,"info":info}}],
        "source": "apiai-weather-webhook-sample"
    }



def p2p_inf(topo):
    topodef = {'p2pv1':'Every node of the overlay knows k > 2 other nodes. Data gets flooded over the edges and every node contains every information.',
                'p2pv2':'Every node contains only a small fraction of the data. Hence rare content is hard to find. This type of p2p is usually deployed via directory servers or flooding with backtracking.',
                'dht':'Distributed Hash-Tables are a structured p2p overlay and utilizes a dynamic number of nodes. I realizes a cyclic data space and since every node knows the address of its logical successor, the complexity of searches is reduced to O(n).',
                'unstructured':'Unstructured peer-to-peer networks do not impose a particular structure on the overlay network by design, but rather are formed by nodes that randomly form connections to each other.',
                'structured':'In structured peer-to-peer networks the overlay is organized into a specific topology, and the protocol ensures that any node can efficiently search the network for a file/resource, even if the resource is extremely rare.'}
    if topo in topodef:
        speech = topodef[topo]
    else:
        speech = "Could you tell me the p2p form you are interested in again?"

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }


def peer_event():
    speech = "peer event was triggered!"

    return {
    "speech": speech,
    "displayText": speech,
    # "data": data,
    # "contextOut": [],
    "source": "apiai-weather-webhook-sample",
    "followupEvent":{"name":"peerevent","data":{" ":" "}}
    }

def layer_general_event():
    speech = "Layer general event was triggered!"

    return {
    "speech": speech,
    "displayText": speech,
    # "data": data,
    # "contextOut": [],
    "source": "apiai-weather-webhook-sample",
    "followupEvent":{"name":"layergeneraltrigger","data":{" ":" "}}
    }


def prot_more_info_more(prot, infor):

    if infor == "advantages":
        speech = prot_advantages(prot)
    elif infor == "issues":
        speech = prot_disadvantages(prot)
    elif infor == "alternatives":
        speech = prot_alternatives(prot)
    elif infor == "difference":
        speech = prot_diff_udp_tcp()
    else:
        speech = "Mhh I am not quite sure about " + infor + " but I will ask someone and come back to you :) In the mean time we could talk about advantages, issues or alternatives to this protocol or something else altogehter!"

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }

def prot_diff_udp_tcp():
    return "There are two types of Internet Protocol (IP) traffic. They are TCP or Transmission Control Protocol and UDP or User Datagram Protocol. TCP is connection oriented – once a connection is established, data can be sent bidirectional. UDP is a simpler, connectionless Internet protocol."


def prot_advantages(prot):
    protdef = {'TCP':'The main advantage of TCP is that it offers connection-oriented communication - which means that  a communication session or a semi-permanent connection is established before any useful data can be transferred, and where a stream of data is delivered in the same order as it was sent',
                'HTTP':'It s greates adantage is that basically is everywhere on the internet',
                'SMTP':'Although proprietary systems (such as Microsoft Exchange and IBM Notes) and webmail systems (such as Outlook.com, Gmail and Yahoo! Mail) use their own non-standard protocols to access mail box accounts on their own mail servers, all use SMTP when sending or receiving email from outside their own systems.',
                'IMAP':'The main advantage of IMAP would be that one can acces their mails directly on the server',
                'DNS':'The Domain Name System delegates the responsibility of assigning domain names and mapping those names to Internet resources by designating authoritative name servers for each domain. Network administrators may delegate authority over sub-domains of their allocated name space to other name servers. This mechanism provides distributed and fault tolerant service and was designed to avoid a single large central database.',
                'SIP':'SIPs main advantages lies within its capability to singal and control multimedia communication sessions',
                'RTP':'RTPs greates strength is that it is designed for end-to-end, real-time, transfer of streaming media. The protocol provides facilities for jitter compensation and detection of out of sequence arrival in data, which are common during transmissions on an IP network. RTP allows data transfer to multiple destinations through IP multicast.',
                'HTML':'Advantes of HTML are...',
                'IP':'IPv4 provides safeguards to ensure that the IP packet header is error-free. A routing node calculates a checksum for a packet. If the checksum is bad, the routing node discards the packet. Although the Internet Control Message Protocol (ICMP) allows such notification, the routing node is not required to notify either end node of these errors. By contrast, in order to increase performance, and since current link layer technology is assumed to provide sufficient error detection, the IPv6 header has no checksum to protect it.',
                'UDP':'Since UDP is connectionless it is a ton fastern than TCP.',
                'RPC':'The greates advantage of the RPC model is that it implies a level of location transparency, namely that calling procedures is largely the same whether it is local or remote, but usually they are not identical, so local calls can be distinguished from remote calls. Remote calls are usually orders of magnitude slower and less reliable than local calls, so distinguishing them is important.'
                }
    return protdef[prot]


def prot_disadvantages(prot):
    protdef = {'TCP':'Some possible issues with TCP are Denial of Service, Connection hijaking and TCP veto.',
                'HTTP':'The TRACE method can be used as part of a class of attacks known as cross-site tracing; for that reason, common security advice is for it to be disabled in the server configuration. Microsoft IIS supports a proprietary "TRACK" method, which behaves similarly, and which is likewise recommended to be disabled',
                'SMTP':'One cannot delete or access mails directly on the server',
                'IMAP':'IMAPs disadvantages would be...',
                'DNS':'Several vulnerability issues were discovered and exploited by malicious users. One such issue is DNS cache poisoning, in which data is distributed to caching resolvers under the pretense of being an authoritative origin server, thereby polluting the data store with potentially false information and long expiration times (time-to-live). Subsequently, legitimate application requests may be redirected to network hosts operated with malicious intent.',
                'SIP':'Issues with SIP include...',
                'RTP':'The most common problems with RTP are...',
                'HTML':'Common issues with HTML include...',
                'IP':'Various error conditions may occur, such as data corruption, packet loss, duplication and out-of-order delivery. Because routing is dynamic, meaning every packet is treated independently, and because the network maintains no state based on the path of prior packets, different packets may be routed to the same destination via different paths, resulting in out-of-order sequencing at the receiver.',
                'UDP':'Since UDP emphazises reduced latency over reliability, it is not the best option if you need your data to arrive in the correct order to guarantee correct delivery!',
                'RPC':'I am not quite sure about RPCs disandavtages... I ll get back to you for this question though!'
                }

    return protdef[prot]


def prot_alternatives(prot):
    protdef = {'TCP':'UDP is the connection-less counterpart to TCP.',
                'HTTP':'HTTPS would be a good alternative',
                'SMTP':'IMAP or POP3 are more common alternatives',
                'IMAP':'POP3 (more commonly used today) or SMTP woudl be alternatives to IMAP',
                'DNS':'I think we did not disucss alternatives for DNS...',
                'SIP':'Alternatives to SIP would be IAX, ICE, XMPP (Google Hangouts)',
                'RTP':'Alternatives for RTP include...',
                'HTML':'HTML alternatives would consist of...',
                'IP':'There are two commonly used versions of IP - IPv4 and IPv6',
                'UDP':'TCP would be the connection-oriented counterpart to UDP.',
                'RPC':'RPCs are a form of inter-process communication (IPC), in that different processes have different address spaces: if on the same host machine, they have distinct virtual address spaces, even though the physical address space is the same; while if they are on different hosts, the physical address space is different. Many different (often incompatible) technologies have been used to implement the concept.'
                }
    return protdef[prot]


def prot_info(prot):
    protdef = {'TCP':'TCP = Transmission Control Protocol',
                'HTTP':'HTTP = Hyper Text Transfer Protocol',
                'SMTP':'SMTP = Simple Mail Transport Protocol',
                'IMAP':'IMAP = Internet Message Access Protocol',
                'DNS':'DNS = Domain Name System',
                'SIP':'SIP = Session Initiation Protocol',
                'RTP':'RTP = Real-time Transport Protocol',
                'HTML':'HTML = Hypertext Markup Language',
                'IP':'IP = Internet Protocol',
                'UDP':'UDP = User Datagram Protocol',
                'RPC':'RPC = Remote Procedure Call'
                }
    #in case of no specific protocol - entities none or protocol
    if prot in protdef:
        speech = protdef[prot] + "Would you like to hear a bit more about " + prot + " ?"
    else:
        speech = "I guess it's time to switch topics then :)"
    if prot == "none" or prot == "protocol":
        speech = "In this case... Would you like to talk about protocols in general then?"

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }

def prot_more_info(prot):
    protdef = {'TCP':'The Transmission Control Protocol (TCP) is one of the main protocols of the Internet protocol suite. It originated in the initial network implementation in which it complemented the Internet Protocol (IP). Therefore, the entire suite is commonly referred to as TCP/IP. TCP provides reliable, ordered, and error-checked delivery of a stream of octets between applications running on hosts communicating by an IP network. Major Internet applications such as the World Wide Web, email, remote administration, and file transfer rely on TCP.',
                'HTTP':'The Hypertext Transfer Protocol (HTTP) is an application protocol for distributed, collaborative, and hypermedia information systems. HTTP is the foundation of data communication for the World Wide Web. Hypertext is structured text that uses logical links (hyperlinks) between nodes containing text. HTTP is the protocol to exchange or transfer hypertext.',
                'SMTP':'Simple Mail Transfer Protocol (SMTP) is an Internet standard for electronic mail (email) transmission. Although electronic mail servers and other mail transfer agents use SMTP to send and receive mail messages, user-level client mail applications typically use SMTP only for sending messages to a mail server for relaying. For retrieving messages, client applications usually use either IMAP or POP3.',
                'IMAP':'In computing, the Internet Message Access Protocol (IMAP) is an Internet standard protocol used by e-mail clients to retrieve e-mail messages from a mail server over a TCP/IP connection. IMAP was designed with the goal of permitting complete management of an email box by multiple email clients, therefore clients generally leave messages on the server until the user explicitly deletes them.',
                'DNS':'The Domain Name System (DNS) is a hierarchical decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols. By providing a worldwide, distributed directory service, the Domain Name System is an essential component of the functionality on the Internet, that has been in use since 1985.',
                'SIP':'The Session Initiation Protocol (SIP) is a communications protocol for signaling and controlling multimedia communication sessions in applications of Internet telephony for voice and video calls, in private IP telephone systems, as well as in instant messaging over Internet Protocol (IP) networks. SIP works in conjunction with several other protocols that specify and carry the session media. Media type and parameter negotiation and media setup is performed with the Session Description Protocol (SDP), which is carried as payload in SIP messages. For the transmission of media streams (voice, video) SIP typically employs the Real-time Transport Protocol (RTP) or the Secure Real-time Transport Protocol (SRTP).',
                'RTP':'The Real-time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks. RTP is used extensively in communication and entertainment systems that involve streaming media, such as telephony, video teleconference applications, television services and web-based push-to-talk features. RTP typically runs over User Datagram Protocol (UDP). RTP is used in conjunction with the RTP Control Protocol (RTCP). While RTP carries the media streams (e.g., audio and video), RTCP is used to monitor transmission statistics and quality of service (QoS) and aids synchronization of multiple streams. RTP is one of the technical foundations of Voice over IP and in this context is often used in conjunction with a signaling protocol such as the Session Initiation Protocol (SIP) which establishes connections across the network.',
                'HTML':'Hypertext Markup Language (HTML) is the standard markup language for creating web pages and web applications. With Cascading Style Sheets (CSS) and JavaScript it forms a triad of cornerstone technologies for the World Wide Web. Web browsers receive HTML documents from a webserver or from local storage and render them into multimedia web pages. HTML describes the structure of a web page semantically and originally included cues for the appearance of the document.',
                'IP':'The Internet Protocol (IP) is the principal communications protocol in the Internet protocol suite for relaying datagrams across network boundaries. Its routing function enables internetworking, and essentially establishes the Internet. IP has the task of delivering packets from the source host to the destination host solely based on the IP addresses in the packet headers. For this purpose, IP defines packet structures that encapsulate the data to be delivered. It also defines addressing methods that are used to label the datagram with source and destination information.',
                'UDP':'In electronic communication, the User Datagram Protocol (UDP) is one of the core members of the Internet protocol suite. With UDP, computer applications can send messages, in this case referred to as datagrams, to other hosts on an Internet Protocol (IP) network. Prior communications are not required in order to set up transmission channels or data paths. UDP uses a simple connectionless transmission model with a minimum of protocol mechanism. UDP provides checksums for data integrity, and port numbers for addressing different functions at the source and destination of the datagram. It has no handshaking dialogues, and thus exposes the users program to any unreliability of the underlying network: there is no guarantee of delivery, ordering, or duplicate protection',
                'RPC':'n distributed computing, a remote procedure call (RPC) is when a computer program causes a procedure (subroutine) to execute in a different address space (commonly on another computer on a shared network), which is coded as if it were a normal (local) procedure call, without the programmer explicitly coding the details for the remote interaction. That is, the programmer writes essentially the same code whether the subroutine is local to the executing program, or remote. This is a form of client–server interaction (caller is client, executor is server), typically implemented via a request–response message-passing system.'
                }
    #in case of no specific protocol - entities none or protocol
    if prot in protdef:
        speech = protdef[prot]
    else:
        speech = "I guess it's time to switch topics then :)"
    if prot == "none" or prot == "protocol":
        speech = "In this case... Would you like to talk about protocols in general then?"

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }



def congestion_control_layer2(congestion):
    con_methods = {'aloha':'The first version of the protocol was quite simple: If you have data to send, send the data - If, while you are transmitting data, you receive any data from another station, there has been a message collision. All transmitting stations will need to try resending "later". Note that the first step implies that Pure ALOHA does not check whether the channel is busy before transmitting. Since collisions can occur and data may have to be sent again, ALOHA cannot use 100 percent of the capacity of the communications channel. How long a station waits until it transmits, and the likelihood a collision occurs are interrelated, and both affect how efficiently the channel can be used.',
                    's-aloha':'An improvement to the original ALOHA protocol was "Slotted ALOHA", which introduced discrete timeslots and increased the maximum throughput. A station can start a transmission only at the beginning of a timeslot, and thus collisions are reduced. In this case, only transmission-attempts within 1 frame-time and not 2 consecutive frame-times need to be considered, since collisions can only occur during each timeslot.',
                    'CSMA':'Carrier-sense multiple access (CSMA) is a media access control (MAC) protocol in which a node verifies the absence of other traffic before transmitting on a shared transmission medium. A transmitter attempts to determine whether another transmission is in progress before initiating a transmission using a carrier-sense mechanism. That is, it tries to detect the presence of a carrier signal from another node before attempting to transmit.',
                    'CSMA/CD':'CSMA/CD is used to improve CSMA performance by terminating transmission as soon as a collision is detected, thus shortening the time required before a retry can be attempted.',
                    'CSMA/CA':'In CSMA/CA collision avoidance is used to improve the performance of CSMA. If the transmission medium is sensed busy before transmission, then the transmission is deferred for a random interval. This random interval reduces the likelihood that two or more nodes waiting to transmit will simultaneously begin transmission upon termination of the detected transmission, thus reducing the incidence of collision.'}

    if congestion in con_methods:
        speech = con_methods[congestion]
    else:
        speech = "This method is not part of layer 2's congestion control!"

    if congestion == "RED":
        return {"followupEvent":{"name":"red_con","data":{" ":" "}}}

    if congestion == "congestion control general":
        return {"followupEvent":{"name":"con_general","data":{" ":" "}}}

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }

def congestion_control_layer4(congestion):
    con_methods = {'reno':'If three duplicate ACKs are received, Reno will perform a fast retransmit and skip the slow start phase (which is part of Tahoe s procedure) by instead halving the congestion window (instead of setting it to 1 MSS like Tahoe), setting the slow start threshold equal to the new congestion window, and enter a phase called Fast Recovery.',
                    'tahoe':'If three duplicate ACKs are received, Tahoe performs a fast retransmit, sets the slow start threshold to half of the current congestion window, reduces the congestion window to 1 MSS, and resets to slow start state',
                    'TCP congestion control':'Congestion control via TCP is deployed either with Reno or Tahoe. Whenever duplicate ACKs are received either a slow start or a fast recovery is performed'}
    #speech = con_methods[congestion]
    if congestion in con_methods:
        speech = con_methods[congestion]
    else:
        speech = "This method is not part of layer 4's congestion control!"

    if congestion == "RED":
        return {"followupEvent":{"name":"red_con","data":{" ":" "}}}

    if congestion == "congestion control general":
        return {"followupEvent":{"name":"con_general","data":{" ":" "}}}

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }


def makeWebhookResultTriggerEvent():
    speech = "It looks like you triggered an event!"

    return {
    "speech": speech,
    "displayText": speech,
    # "data": data,
    # "contextOut": [],
    "source": "apiai-weather-webhook-sample",
    "followupEvent":{"name":"eventtry","data":{" ":" "}}
    }
        #"speech": speech,
        #"displayText": speech,
        # "data": data,
        # "contextOut": [],
        #"source": "apiai-weather-webhook-sample"
        #"followupEvent": "eventtry"
    #}

def makeWebhookResultLayerAbout(layer):
    layerdef = {'physical layer':'The physical layer handels mechanical and electrical/optical linkage. It converts logical symbols into electrical(optical) ones and measures optical signals to reconstruct logical symbols', 
    'data link layer':'The data link layer covers transmission errors and handels media access. It is also concerned with congestion control.', 
    'network layer':'On the network layer paths from senders to recipients are chosen. Hence this layer also has to cope with heterogenius subnets and is responsibe for accounting.',
    'transport layer':'The transport layer offers secure end-to-end-communication between processes. Therefore it is also in charge for data stream control between endsystems. A few concerns of this layer are multiplexing, segmentation and acknowledgements in order to provide reliable transmission.',
    'session layer':'The name of this layer almost gives all its functionalities away! It mostly deals with communication managment, dialog control and synchronization.',
    'presentation layer':'Converting between dataformats, compression and decrompession as well as encryption are the main converns of the presentation layer.',
    'application layer':'Its name almost tells it all. The application layer handels communication between applications and deals with application specific services like e-mail, telnet etc.',
    'layer':'Alright! Layers basically are subdivisions of communication models. A Layer basically is a collection of similar functions that provide services to the layer above it and receives services from the layer below it.',
    'internet':'The internet layer has the same responsabilites as the third layer of the OSI model (which would be the network layer).',
    'link':'The link layer corresponds to the OSI model layers 1 and 2 (physical layer and data link layer).'}
    #maybe add a would you like to hear more right here! Would be a nice conversation flow!

    #might check if layer is defined in our dic!
    speech = layerdef[layer]

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }

def makeWebhookResult(data):
    query = data.get('query')
    if query is None:
        return {}

    result = query.get('results')
    if result is None:
        return {}

    channel = result.get('channel')
    if channel is None:
        return {}

    item = channel.get('item')
    location = channel.get('location')
    units = channel.get('units')
    if (location is None) or (item is None) or (units is None):
        return {}

    condition = item.get('condition')
    if condition is None:
        return {}

    # print(json.dumps(item, indent=4))

    speech = "Today in " + location.get('city') + ": " + condition.get('text') + \
             ", the temperature is " + condition.get('temp') + " " + units.get('temperature')

    print("Response:")
    print(speech)

    return {
        "speech": speech,
        "displayText": speech,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }

def makeWebhookResultForGetJoke(data):
    valueString = data.get('value')
    joke = valueString.get('joke')
    speechText = joke
    displayText = joke
    return {
        "speech": speechText,
        "displayText": displayText,
        # "data": data,
        # "contextOut": [],
        "source": "apiai-weather-webhook-sample"
    }


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))

    print("Starting app on port %d" % port)

    app.run(debug=False, port=port, host='0.0.0.0')
