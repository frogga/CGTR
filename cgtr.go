package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"log"
	"net"
	//"os"
	//"strconv"
	"time"
	"flag"
	"strings"
)
type CGProbe struct{
	Ttl uint8
	Id uint16
	Buf gopacket.NewSerializeBuffer
	TsPrep time.Time
	TsSend time.Time
	TsRecv time.Time
}
//we assume three IPs here
type IPTimeStampOption struct {
	Pointer uint8
	Oflwflg uint8
	Ip1 net.IP
	Ts1 uint32
	Ip2 net.IP
	Ts2 uint32
	Ip3 net.IP
	Ts3 uint32
}

var (
	err error
	Infomap=[...]string{"srcip","dstip","firstip","secondip","thirdip"}
	IPinfo map[string]net.IP
	Probeinfo map[uint32]CGProbe
	Eth *net.Interface
	GwMAC net.HardwareAddr
	LinkTTL = flag.Int("ttl",0,"The TTL value to reach the first IP in triplet")
	Payloadsize = flag.Int("S",64,"TCP payload size for the probe packets")
	Eth_str =flag.String("i","","Network interface for outgoing packets")
	Srcip_str = flag.String("s","","The source IP address")
	Dstip_str = flag.String("d","","The destination IP address")
	Triplet_str = flag.String("l","","Comma seperated triplet IP")
	GatewayMAC_str = flag.String("m","FF:FF:FF:FF:FF:FF","Network gateway's MAC address")
)

//get the external IP if it is not provided
/*func externalIP(sip,inf string) (net.IP, net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip, iface , nil
		}
	}
	return nil, nil, errors.New("are you connected to the network?")
}*/

func random_payload(p []byte) (n int, err error) {
	todo := len(p)
	offset := 0
	for {
		val := int64(r.src.Int63())
		for i := 0; i < 8; i++ {
			p[offset] = byte(val & 0xff)
			todo--
			if todo == 0 {
				return len(p), nil
			}
			offset++
			val >>= 8
		}
	}
}

func craft_packet(TTLstart int, IPmap map[string]net.IP, Probemap map[uint32]CGProbe,chan_probe chan<- *CGProbe){
	var buffer gopacket.SerializeBuffer
	var options gopacket.SerializeOptions
	var eth_layer *layers.Ethernet
	var ip_layer *layers.IPv4
	var tcp_layer *layers.TCP
	
	var payload []byte
	 
	//send them 1 second later
	tsstart :=time.Now().Add(time.Duration(1)*time.Second)
	payload = make([]byte,Payloadsize)
	n,err:=random_payload(payload)
	log.Println("Made %d byte payload",n)
	r :=rand.New(rand.NewSource(99))

	for i:=0; i<3; i++ {
		for j:=0; j<2; j++{
			p:=&CGProbe{}
			p.Ttl = uint8(TTLstart+i)
			p.Id = uint16(r.Intn(20480))
			seq=uint32(r.Intn(100000)*100+i*10+j) //random number multiplies by 100 to shift two digit left
			log.Println("Creating probe id %v id %v",p.Id,seq)
			p.TsPrep = tsstart
			//add 1 us here to perserve the sending sequence
			tsstart = tsstart.Add(time.Duration(1)*time.Microsecond)
			//craft the ip options
			optbuf:=new (bytes.Buffer)
			tsoption:=IPTimeStampOption{Pointer:uint8(4+8*3+1),Oflwflg:uint8(3),Ip1:Infomap["firstip"],Ts1:uint32(0),Ip2:Infomap["secondip"],Ts2:uint32(0),Ip3:Infomap["thirdip"],Ts3:uint32(0)}
			for _, v :=range tsoption {
				err := binary.Write(optbuf,binaryBigEndian,v)
				if err != nil {
					log.Println("binary.Write failed:", err)
				}
			}
			optlen:=2+len(optbuf.Bytes())
			
			ipopt:=[]layers.IPv4Option{layers.IPv4Option{OptionType:uint8(0x44), OptionLength:uint8(optlen),optbuf.Bytes()}}
			eth_layer = &layers.Ethernet {
				SrcMAC: *Eth.HardwareAddr,
				DstMAC: GwMAC,
				EthernetType: 0x0800,
			}
			ip_layer = &layers.IPv4{
		  	SrcIP: IPmap["srcip"],
		  	DstIP: IPmap["dstip"],
		  	Id: p.Id ,
		  	TTL: p.Ttl,
		  	Options: ipopt,
			}
			tcp_layer = &layer.TCP {
				SrcPort: layersTCPPort(25555),
				DstPort: layers.TCPPort(80),
				Seq: seq, 
				PSH: true,
				ACK: true,
			}
			
			p.Buf=gopacket.NewSerializeBuffer()
			options=gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			gopacket.SerializeLayers(p.Buf,options,eth_layer,ip_layer,tcp_layer,gopacket.Payload(payload),)
			Probemap[seq] = p
			//schedule the packet
			chan_probe<-p
		}
	}
}

func initpcap(iface *net.Interface, ipmap map[string]net.IP) (*pcap.Handle, error){
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil,err
	}
	defer handle.Close()
	filter := fmt.Sprintf("icmp or host %s",ipmap["dstip"].String())
	err = handle.SetBPFFilter(filter)
	if err!=nil {
		return nil,err
	}
	return handle,nil
}

func sendpcap(handle *pcap.Handle, chan_outprobe chan<- *CGProbe){
	for probe :=range chan_probe {
		go preparesend(handle,probe.Buf.Bytes(),probe.TsPrep)
	}
}

func preparesend(handle *pcap.Handle, pck []byte, t time.Time){
	time.Sleep(t.Sub(time.Now()))
	handle.WritePacketData(pck)
}

func recvpcap(handle *pcap.Handle, chan_response <-chan *CGProbe){
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
  	fmt.Println(packet)
  	//parse the packet
  	parsepacket(packet)
	}
}

func parsepacket(pkt gopacket.Packet){
	var ethl layers.Ethernet
	var ipv4l layers.IPv4
	var icmpv4l layers.ICMPv4
	var tcpl layers.TCP
		
	parser := gopacket.NewDecodingLayerParser(layers.LayerTyperEthernet, &ethl, &ipv4l, &icmpv4l, &tcpl)
	decoded :=[]gopacket.LayerType{}
	err:=parser.DecodeLayers(pkt, &decoded)
	for _, layerType := range decoded {
  	switch layerType {
  		case layers.LayerTypeTCP:
  			//This shd be the outgoing probes. Check the tcp sequence number. just quick check here. we shd further verify other fields in later version
  			if  _, exist:=Probeinfo[tcpl.Seq]; exist {
  				Probeinfo[tcpl.Seq].TsSend = pkt.Metadata().CaptureInfo.Timestamp
  				log.Println("Got outgoing packet: ts %v seq %v", pkt.Metadata().CaptureInfo.Timestamp, tcpl.Seq)
  			}
  		case layers.LayerTypeICMPv4:
  			//check if this is a response packet
  			if icmpv4l.TypeCode.Type()== layers.ICMPv4TypeTimeExceeded && icmpv4l.TypeCode.Code()==layers.ICMPv4CodeTTLExceeded {
  				//TTL exceeded packet
  				log.Println("Payload: %x",pkt.Payload())
  				//it should contains the original IP packet header
  				
  			}
  		
  		//chan_response<-packet
  	}
	}
}

func cgtr_do(){
	//craft packets
	//schedule and send packets
	//read and parse responses
	//compute results
}

func main(){
	IPinfo = make(map[string]net.IP)
	Probeinfo = make(map[uint32]CGProbe)
	flag.Parse()
	if IPinfo["dstip"]=net.ParseIP(*Dstip_str); IPinfo["dstip"]==nil || IPinfo["dstip"].To4()==nil {
		log.Fatalln("Input: Destination IP is incorrect or not set")
	}
	if IPinfo["srcip"]=net.ParseIP(*Srcip_str); IPinfo["srcip"]==nil ||IPinfo["srcip"].To4()==nil  {
		log.Fatalln("Input: Source IP is incorrect or not set")
	}
	if *LinkTTL==0 {
		log.Fatalln("Input: TTL to first IP in triplet is incorrect or not set")
	}
	if Eth, err=net.InterfaceByName(*Eth_str); err!=nil {
		log.Fatalln("Input: Interface is incorrect. Error %s",err)
	}
	if GwMAC, err=net.ParseMAC(*GatewayMAC_str); err!=nil {
		log.Fatalln("Input: Gateway MAC address is incorrect. Error %s",err)
	}
	tip:=strings.Split(*Triplet_str,",")
	if len(tip)!=3{
		log.Fatalln("Input: Triplet IP error")
	}
	for i:=0; i<3; i++ {
		IPinfo[Infomap[i+2]] = net.ParseIP(tip[i])
		if IPinfo[Infomap[i+2]]==nil || IPinfo[Infomap[i+2]].To4()==nil {
			log.Fatalln("Input: %s error",Infomap[i])
		}
		log.Printf("Got %s:%s\n",Infomap[i],IPinfo[Infomap[i]].String())
	}
	
	if err=initpcap(Eth); err!=nil {
		log.Fatalln("pcap failed: %s",err)
	}
	chan_probe:=make(chan CGProbe)
	defer close(chan_probe)
	chan_response:=make(chan CGProbe)
	defer close(chan_response)
	go sendpcap (handle, &chan_probe, Probeinfo)
	go recvpcap (handle, &chan_response, Probeinfo)
	
	
}