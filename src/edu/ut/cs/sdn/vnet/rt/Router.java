package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
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



	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
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
        { return; }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    private void handleICMP(Ethernet ogEtherPacket, Iface ogIface, int IcmpType, int IcmpCode) {

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


}
