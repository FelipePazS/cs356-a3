package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;
import java.util.TimerTask;

class MyTimerTask extends TimerTask {

	Ethernet ARP_request;
	Iface outFace;
	public int TTL;
	Router router;
	Timer timer;
	int ip;
	ConcurrentHashMap map;

	public MyTimerTask(Ethernet request, Iface outIface, Router _router, ConcurrentHashMap map, Timer _timer){
		this.ARP_request = request;
		this.outFace = outIface;
		this.TTL = 2;
		this.timer = _timer;
		this.router = _router;
		this.map = map;
	}

    @Override
    public void run() {
        if (this.TTL > 0){
			this.TTL -= 1;
			this.router.sendPacket(ARP_request, outFace);
			if (this.TTL == 0 || this.TTL < 0){
				timer.cancel();
			}
		}
		else {
			if(map.containsKey(ip)){
				map.remove(ip);
			}
			timer.cancel();
		}
    }

}

class Queue_ARP{
	public Queue<Ethernet> q;
	long time_sent;
	Iface outFace;
	Timer timer;

	public Queue_ARP(Iface outIface, Timer timer){
		this.q = new LinkedList<Ethernet>();
		this.outFace = outIface;
		this.timer = timer;
	}

	public void done(){
		timer.cancel();
	}
}

class unwantedRIP extends TimerTask{

	Ethernet eth;
	Iface iface;
	Router router;
	public void unwantedRIP(Ethernet request, Iface outIface, Router _router){
		this.eth = request;
		this.iface = outIface;
		this.router = _router;
	}
	@Override
    public void run() {
		this.router.sendPacket(this.eth, this.iface);
    }

}

class ripEntry{
	int  ip;    /* address of destination */
    int  nextHop;        /* address of next hop */
    int  cost;          /* distance metric */
	int subnet;
    float   last_update;
	bool is_neighbor;

	public ripEntry(int des,int sb, int hop, int _cost, bool set_timer){
		this.destination = des;
		this.nextHop = hop;
		this.cost = _cost;
		this.subnet = sb;
		if (set_timer){
			is_neighbor = false;
			last_update = System.currentTimeMillis();
		}
		else {
			is_neighbor = true;
		}
	}
}

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	private Map<int, ripEntry> ripTable;
	Timer timer;
	
	/** ARP cache for the router */
	private ConcurrentHashMap<Integer,Queue_ARP> ip_queue_map;
	private ArpCache arpCache;

	private static final int ICMP_TIME_EXCEEDED_TYPE = 11;
	private static final int ICMP_TIME_EXCEEDED_CODE = 0;
	private static final int ICMP_DEST_NET_UNREACH_TYPE = 3;
	private static final int ICMP_DEST_NET_UNREACH_CODE = 0;
	private static final int ICMP_DEST_HOST_UNREACH_TYPE = 3;
	private static final int ICMP_DEST_HOST_UNREACH_CODE = 1;
	private static final int ICMP_DEST_PORT_UNREACH_TYPE = 3;
	private static final int ICMP_DEST_PORT_UNREACH_CODE = 3;
	private static final int ICMP_ECHO_REQ = 8;

	private static final int RIP_ADDR = IPv4.toIPv4Address("224.0.0.9");
	private static final String BROADCAST_MAC_ADDR = "FF:FF:FF:FF:FF:FF";




	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile, bool hasTable)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ripTable = new HashMap<int, ripEntry>();
		timer = new Timer(true);
		this.ip_queue_map = new ConcurrentHashMap<Integer,Queue_ARP>();
		if (!hasTable){
			RIPv2 rip_packet = new RIPv2();
			// create this table with the neighbours
			for (Iface iface : this.interfaces.values()){}
				rip_packet.addEntry(new RIPv2Entry(iface.getIpAddresss(), iface.getSubnetMask(), 0))
				this.ripTable.insert(new ripEntry(iface.getIpAddresss(), 0, iface.getSubnetMask(), false))
			}

			// send our table to everybody
			rip_packet.setCommand(RIPv2.COMMAND_REQUEST);
			UDP udp = new UDP();
			udp.setSourcePort(UDP.RIP_PORT);
			udp.setDestinationPort(UDP.RIP_PORT);
			udp.setPayload(rip_packet);

			IPv4 ipPacket = new IPv4();
			ipPacket.setDestinationAddress(RIP_ADDR);
			ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
			ipPacket.setPayload(udp);

			Ethernet eth = new Ethernet();
			eth.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
			eth.setPayload(ipPacket);

			for (Iface iface : this.interfaces.values()){
				this.sendPacket(eth, iface);
			}

			MyTimerTask task = new unwantedRIP();
			timer.schedule(task, 10*1000, 10*1000);
		}
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
			break;
		}
		
		/********************************************************************/
	}

	private void handleARPPacket(Ethernet etherPacket, Iface inIface){
		ARP arpPacket = (ARP)etherPacket.getPayload();
        int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		switch(arpPacket.getOpCode())
		{
		case ARP.OP_REQUEST:
			if (targetIp == inIface.getIpAddress()){
				Ethernet eth_response = new Ethernet();
				eth_response.setEtherType(Ethernet.TYPE_ARP);
				eth_response.setSourceMACAddress(inIface.getMacAddress().toString());
				eth_response.setDestinationMACAddress(etherPacket.getSourceMACAddress());

				ARP arp_response = new ARP();
				arp_response.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arp_response.setProtocolType(ARP.PROTO_TYPE_IP);
				arp_response.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
				arp_response.setProtocolAddressLength((byte) 4);
				arp_response.setOpCode(ARP.OP_REPLY);
				arp_response.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
				arp_response.setSenderProtocolAddress(inIface.getIpAddress());
				arp_response.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
				arp_response.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

				eth_response.setPayload(arp_response);
				this.sendPacket(eth_response, inIface);
			}
			break;
		
		case ARP.OP_REPLY:
			// Populate the ARP cache
			byte[] sender_MAC = arpPacket.getSenderHardwareAddress();
			byte[] temp_IP = arpPacket.getSenderProtocolAddress();
			int sender_IP = ByteBuffer.wrap(temp_IP).getInt();
			arpCache.insert(new MACAddress(sender_MAC), sender_IP);

			// Dequeue and send all packets waiting for the MAC
			if (ip_queue_map.containsKey(sender_IP)){
				Queue_ARP queue = ip_queue_map.get(sender_IP);
				queue.done();
				for (Ethernet packet : queue.q){
					packet.setDestinationMACAddress(sender_MAC);
					this.sendPacket(packet, queue.outFace);
				}
				ip_queue_map.remove(sender_IP);
			}
			break;
		}
	}

	private void update_rip(RIPv2 rip, Iface iface){
		List<RIPv2Entry> their_entries = rip.getEntries();
		for (RIPv2Entry entry : their_entries){
			if(ripTable.containsKey(entry.getAddress())){

			}
			else {
				ripEntry n_entry = new ripEntry(entry.getAddress(), entry.getSubnetMask(),iface.getIpAddress(), true);
				ripTable.put(entry.getAddress(), n_entry);
			}
		}
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");


		// Handle RIP
        if (ipPacket.getDestinationAddress() == RIP_ADDR && ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
        	UDP udp = (UDP) ipPacket.getPayload();
        	if (udp.getDestinationPort() == UDP.RIP_PORT) {
				RIPv2 rip = (RIPv2) udp.getPayload();
				switch(rip.getCommand())
				{
				case RIPv2.COMMAND_REQUEST:
					// update my table and send it to the requesting router
					this.update_rip(rip);
					break;
				
				case RIPv2.COMMAND_RESPONSE:
					// update my table

					break;
				}
			}

		}

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        {
        	this.handleICMP(etherPacket, inIface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
        	return;
        }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
        		byte protocol = ipPacket.getProtocol();
        		if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
        			this.handleICMP(etherPacket,inIface, ICMP_DEST_PORT_UNREACH_TYPE, ICMP_DEST_PORT_UNREACH_CODE);
				} else if (protocol == IPv4.PROTOCOL_ICMP) {
        			ICMP icmp = (ICMP) ipPacket.getPayload();
        			if (icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
        				this.handleICMP(etherPacket, inIface, ICMP_ECHO_REQ, 0);
					}
				}
        		return;
        	}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
		// Here not use
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        {
        	this.handleICMP(etherPacket, inIface, ICMP_DEST_NET_UNREACH_TYPE, ICMP_DEST_NET_UNREACH_CODE);
        	return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { 
			Ethernet eth_request = new Ethernet();
			// Queue the packet and generate an ARP request
			if (this.ip_queue_map.containsKey(nextHop)){
				Queue_ARP queue = ip_queue_map.get(nextHop);
				queue.q.add(etherPacket);
				return;
			}
			else{
				// Generate ARP Request
				eth_request.setEtherType(Ethernet.TYPE_ARP);
				eth_request.setSourceMACAddress(inIface.getMacAddress().toString());
				eth_request.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");

				ARP arp_request = new ARP();
				arp_request.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arp_request.setProtocolType(ARP.PROTO_TYPE_IP);
				arp_request.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
				arp_request.setProtocolAddressLength((byte) 4);
				arp_request.setOpCode(ARP.OP_REQUEST);
				arp_request.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
				arp_request.setSenderProtocolAddress(ByteBuffer.allocate(4).putInt(inIface.getIpAddress()).array());
				arp_request.setTargetHardwareAddress(ByteBuffer.allocate(6).putInt(0).array());
				arp_request.setTargetProtocolAddress(ByteBuffer.allocate(4).putInt(nextHop).array());

				eth_request.setPayload(arp_request);

				// Create Queue struct
				Timer _timer = new Timer(true);
				MyTimerTask task = new MyTimerTask(eth_request, outIface, this,ip_queue_map, _timer);
				Queue_ARP queue = new Queue_ARP(outIface, _timer);
				queue.q.add(etherPacket);
				ip_queue_map.put(nextHop, queue);

				_timer.schedule(task, 1000, 1000);
			}

			this.sendPacket(eth_request, outIface);
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    private void handleICMP(Ethernet ogEtherPacket, Iface ogIface, int IcmpType, int IcmpCode) {

		IPv4 ogIpPacket = (IPv4) ogEtherPacket.getPayload();

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(ogIface.getMacAddress().toBytes());

		int sourceAddr = ogIpPacket.getSourceAddress();

		// Here not use routetable
		RouteEntry bestMatch = this.routeTable.lookup(sourceAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{ return; }

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = sourceAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{ return; }

		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		// Set IP header
		IPv4 ip = new IPv4();
		final byte ICMP_STANDARD_TTL = 64;
		ip.setTtl(ICMP_STANDARD_TTL);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		if (IcmpType == ICMP_ECHO_REQ) {
			ip.setSourceAddress(ogIpPacket.getDestinationAddress());
		} else {
			ip.setSourceAddress(ogIface.getIpAddress());
		}
		ip.setDestinationAddress(ogIpPacket.getSourceAddress());

		// Set ICMP header
		ICMP icmp = new ICMP();
		icmp.setIcmpCode((byte) IcmpCode);
		icmp.setIcmpType((byte) IcmpType);

		// Set Data
		Data data = new Data();
		if (IcmpType == ICMP_ECHO_REQ) {
			ICMP echoPayload = (ICMP) ogIpPacket.getPayload();
			icmp.setIcmpCode((byte) 0);
			icmp.setIcmpType((byte) 0);
			data.setData(echoPayload.getPayload().serialize());
		} else {
			int ipHeaderLength = ogIpPacket.getHeaderLength() * 4;
			final int NUM_BYTES_AFTER_IP_HEADER = 8;
			final int NUM_BYTES_PADDING = 4;
			int dataPayloadLength = NUM_BYTES_PADDING + ipHeaderLength + NUM_BYTES_AFTER_IP_HEADER;
			byte[] dataPayload = new byte[dataPayloadLength];
			byte[] ogData = ogIpPacket.serialize();
			for (int i = 0; i < ipHeaderLength + NUM_BYTES_AFTER_IP_HEADER; i++) {
				dataPayload[i + NUM_BYTES_PADDING] = ogData[i];
			}
			data.setData(dataPayload);
		}

		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		this.sendPacket(ether, ogIface);
	}

	private void handleRIP(Iface ogIface, int ripCommand) {

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(ogIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(BROADCAST_MAC_ADDR);

		IPv4 ip = new IPv4();
		final byte ICMP_STANDARD_TTL = 64;
		ip.setTtl(ICMP_STANDARD_TTL);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(ogIface.getIpAddress());

		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		Data data = new Data();
		
		RIPv2 rip = new RIPv2();
		rip.setCommand((byte) ripCommand);

	}


}
