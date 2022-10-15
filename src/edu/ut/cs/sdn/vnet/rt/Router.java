package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ARP;
import java.nio.ByteBuffer;
import java.util.*;

class Queue_ARP{
	public Queue<Ethernet> q;
	public int TTL;
	Ethernet ARP_request;
	long time_sent;
	Iface outFace;

	public Queue_ARP(Ethernet request){
		this.q = new LinkedList<Ethernet>();
		this.TTL = 3;
		this.ARP_request = request;
	}
}

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	private Map<Integer,Queue_ARP> ip_queue_map;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ip_queue_map = new HashMap<Integer,Queue_ARP>();
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
		// handle Queue packets with time to send
		if (!ip_queue_map.isEmpty()){
			Iterator<Map.Entry<Integer, Queue_ARP>> it = ip_queue_map.entrySet().iterator();
			while (it.hasNext()){
				Map.Entry<Integer, Queue_ARP> entry = it.next();
				Queue_ARP queue = entry.getValue();
				long current_time = System.currentTimeMillis();
				if (((current_time - queue.time_sent) / 1000) > (long) 1){
					if ((((current_time - queue.time_sent) / 1000) >= (long) 2 )|| queue.TTL == 0){
						// TODO: GENERATE  destination host unreachable message
						it.remove();
					}
					else {
						queue.TTL = queue.TTL - 1;
						this.sendPacket(queue.ARP_request, queue.outFace);
					}
				}
			}
		}
		
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
				for (Ethernet packet : queue.q){
					packet.setDestinationMACAddress(sender_MAC);
					this.sendPacket(packet, queue.outFace);
				}
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
        { return; }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ return; }
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
        { return; }

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
				if (((queue.time_sent - System.currentTimeMillis()) / 1000) >= (long) 1 && queue.TTL != 0){
					queue.TTL -= 1;
					eth_request = queue.ARP_request;
					queue.time_sent = System.currentTimeMillis();
				}
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
				Queue_ARP queue = new Queue_ARP(eth_request);
				queue.q.add(etherPacket);
				queue.TTL = queue.TTL - 1;
				queue.time_sent = System.currentTimeMillis();
				queue.outFace = outIface;

				ip_queue_map.put(nextHop, queue);
			}

			this.sendPacket(eth_request, outIface);
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
