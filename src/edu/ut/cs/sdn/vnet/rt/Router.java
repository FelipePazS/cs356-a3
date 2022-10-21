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
	ConcurrentHashMap<Integer, Queue_ARP> map;

	public MyTimerTask(Ethernet request, int ip, Iface outIface, Router _router, ConcurrentHashMap<Integer, Queue_ARP> map, Timer _timer){
		this.ARP_request = request;
		this.outFace = outIface;
		this.TTL = 2;
		this.timer = _timer;
		this.router = _router;
		this.map = map;
		this.ip = ip;
	}

    @Override
    public void run() {
        if (this.TTL > 0){
			this.TTL -= 1;
			if (this.TTL == 0 || this.TTL < 0){
				timer.cancel();
			}
		}
		else {
			if(map.containsKey(ip)){
				Queue_ARP queue = map.get(ip);
				for (Ethernet packet : queue.q){
					router.handleICMP(packet, this.outFace, 3, 1);
				}
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

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	private ConcurrentHashMap<Integer, RIPv2Entry> ripTable;
	
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
	public Router(String host, DumpFile logfile, boolean hasTable)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ip_queue_map = new ConcurrentHashMap<Integer,Queue_ARP>();
		this.ripTable = new ConcurrentHashMap<Integer, RIPv2Entry>();
		if (!hasTable) {
			// Fill up table
			for (Iface iface : this.interfaces.values()) {
				RIPv2Entry entry = new RIPv2Entry();
				entry.setAddress(iface.getIpAddress());
				entry.setSubnetMask(iface.getSubnetMask());
				entry.setNextHopAddress(0);
				entry.setMetric(0);
				this.ripTable.put(entry.getAddress(), entry);
				// Send out requests
				this.handleRIP(null, iface, RIPv2.COMMAND_REQUEST, false);
			}
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
			IPv4 ipPacket = (IPv4) etherPacket.getPayload();
			if (ipPacket.getDestinationAddress() == RIP_ADDR && ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
				UDP udp = (UDP) ipPacket.getPayload();
				if (udp.getDestinationPort() == UDP.RIP_PORT) {
					RIPv2 rip = (RIPv2) udp.getPayload();
					if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
						handleRIP(etherPacket, inIface, RIPv2.COMMAND_RESPONSE, true);
					} else {
						handleRIP(etherPacket, inIface, (byte) 0, true);
					}
				}
			}
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
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

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
				Timer timer = new Timer(true);
				MyTimerTask task = new MyTimerTask(eth_request, nextHop, outIface, this,  this.ip_queue_map, timer);
				Queue_ARP queue = new Queue_ARP(outIface, timer);
				queue.q.add(etherPacket);
				ip_queue_map.put(nextHop, queue);

				timer.schedule(task, 1000, 1000);
			}

			this.sendPacket(eth_request, outIface);
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    public void handleICMP(Ethernet ogEtherPacket, Iface ogIface, int IcmpType, int IcmpCode) {

		IPv4 ogIpPacket = (IPv4) ogEtherPacket.getPayload();

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(ogIface.getMacAddress().toBytes());

		int sourceAddr = ogIpPacket.getSourceAddress();

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

	private void handleRIP(Ethernet ogEther, Iface ogIface, byte ripCommand, boolean specific) {
		if (ripCommand == (byte) 0){
			// I got a response or unsolicited response, update my table
			IPv4 ip = (IPv4) ogEther.getPayload();
			UDP udp = (UDP) ip.getPayload();
			RIPv2 rip = (RIPv2) udp.getPayload();
			update_table(rip.getEntries(), ip.getSourceAddress(), ogIface);
		}
		else {
			// creating a request or response 
			if (ogEther != null){
				IPv4 ip = (IPv4) ogEther.getPayload();
				UDP udp = (UDP) ip.getPayload();
				RIPv2 rip = (RIPv2) udp.getPayload();
				update_table(rip.getEntries(), ip.getSourceAddress(), ogIface);
			}
			Ethernet ether = new Ethernet();
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ether.setSourceMACAddress(ogIface.getMacAddress().toBytes());
			if (!specific) {
				ether.setDestinationMACAddress(BROADCAST_MAC_ADDR);
			} else {
				ether.setDestinationMACAddress(ogEther.getDestinationMACAddress());
			}
	
			IPv4 ip = new IPv4();
			final byte ICMP_STANDARD_TTL = 64;
			ip.setTtl(ICMP_STANDARD_TTL);
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ip.setSourceAddress(ogIface.getIpAddress());
			if (!specific) {
				ip.setDestinationAddress(RIP_ADDR);
			} else {
				IPv4 ogIp = (IPv4) ogEther.getPayload();
				ip.setDestinationAddress(ogIp.getSourceAddress());
			}
	
			UDP udp = new UDP();
			udp.setSourcePort(UDP.RIP_PORT);
			udp.setDestinationPort(UDP.RIP_PORT);
	
			RIPv2 rip = new RIPv2();
			rip.setCommand((byte) ripCommand);
	
			Data data = new Data();
			data.setData(rip.serialize());
	
	
			udp.setPayload(data);
			ip.setPayload(udp);
			ether.setPayload(ip);
			this.sendPacket(ether, ogIface);
		}
		
	}


	void update_table(List<RIPv2Entry> entries, int ip, Iface iface){
		for (RIPv2Entry entry : entries){
			int d1 = 1;

			int d2 = entry.getMetric();
			int d3 = Integer.MAX_VALUE;
			RIPv2Entry entry_to_be_modified = new RIPv2Entry();
			if (this.ripTable.containsKey(entry.getAddress())){
				entry_to_be_modified = this.ripTable.get(entry.getAddress());
				d3 = entry_to_be_modified.getMetric();
			}
			if ((d1 + d2) <= d3){
				entry_to_be_modified.setMetric(d1 + d2);
				entry_to_be_modified.setNextHopAddress(ip);
			}

			// update route table
			if (!routeTable.update(entry.getAddress(), ip, iface.getSubnetMask() , iface)){
				routeTable.insert(entry.getAddress(), ip, iface.getSubnetMask() , iface);
			}
		}
	}

}
