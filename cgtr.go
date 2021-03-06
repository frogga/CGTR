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
	"sync"
	"bytes"
	"encoding/binary"
	"reflect"
	"fmt"
)
type CGProbe struct{
	Ttl uint8
	Id uint16
	Buf gopacket.SerializeBuffer
	TsPrep time.Time
	TsSend time.Time
	TsRecv time.Time
	RespIP net.IP
	Internetts []uint32
}
//we assume three IPs here
type IPTimeStampOption struct {
	Pointer uint8
	Oflwflg uint8
	Ip1 uint32
	Ts1 uint32
	Ip2 uint32
	Ts2 uint32
	Ip3 uint32
	Ts3 uint32
}

var (
	err error
	Infomap=[...]string{"srcip","dstip","firstip","secondip","thirdip"}
	IPinfo map[string]net.IP
	Probeinfo = struct {
		sync.RWMutex
		m map[uint16]*CGProbe
	}{m: make(map[uint16]*CGProbe)}
	Eth *net.Interface
	GwMAC net.HardwareAddr
	wg sync.WaitGroup
	wgpcap sync.WaitGroup
	rcount int
	LinkTTL = flag.Int("ttl",0,"The TTL value to reach the first IP in triplet")
	Payloadsize = flag.Int("S",64,"TCP payload size for the probe packets")
	Eth_str =flag.String("i","","Network interface for outgoing packets")
	Srcip_str = flag.String("s","","The source IP address")
	Dstip_str = flag.String("d","","The destination IP address")
	Triplet_str = flag.String("l","","Comma seperated triplet IP")
	GatewayMAC_str = flag.String("m","FF:FF:FF:FF:FF:FF","Network gateway's MAC address")
	Numpacket = flag.Int("n",5,"Number of probe packets to each IP")
	Gap = flag.Int("g",0,"The spacing between probe packet in us")
	Tout = flag.Int("T",5,"Timeout in second")
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
		val := int64(rand.Int63())
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

func one_payload(p []byte) (n int, err error) {
	todo := len(p)
	offset := 0
	for {
		val := int64(0xffffffffffff)
		for i := 0; i < 8; i++ {
			p[offset] = byte(val & 0x01)
			todo--
			if todo == 0 {
				return len(p), nil
			}
			offset++
			val >>= 8
		}
	}
}

func IPtouint32(addr net.IP) (u uint32){
	ip4:=addr.To4()
	u|=uint32(ip4[3])
	u|=uint32(ip4[2])<<8
	u|=uint32(ip4[1])<<16
	u|=uint32(ip4[0])<<24
	return
}

func craft_packet(TTLstart int, IPmap map[string]net.IP, chan_probe chan<- *CGProbe){
//	var buffer gopacket.SerializeBuffer
	var options gopacket.SerializeOptions
	var eth_layer *layers.Ethernet
	var ip_layer *layers.IPv4
	var tcp_layer *layers.TCP
	
	var payload []byte
	 
	//send them 1 second later
	tsstart :=time.Now().Add(time.Duration(1)*time.Second)
	payload = make([]byte,*Payloadsize)
	//n,err:=random_payload(payload)
	n,err:=one_payload(payload)
	if err!=nil {
		log.Println("Generate payload failed")
	}
	log.Println("Made byte payload",n)
	r :=rand.New(rand.NewSource(99))

	for i:=0; i<3; i++ {
		for j:=0; j<*Numpacket; j++{
			p:=&CGProbe{}
			p.Ttl = uint8(TTLstart+i)
			p.Id = uint16(r.Intn(20480))
			//seq:=uint32(r.Intn(100000)*100+i*10+j) //random number multiplies by 100 to shift two digit left
			seq:=uint32(100000*100+i*10+j) 
			
			p.TsPrep = tsstart
			//add 1 us here to perserve the sending sequence
			tsstart = tsstart.Add(time.Duration(*Gap)*time.Microsecond)
			log.Println("Creating probe id, seq, ts",p.Id,seq, tsstart)
			//craft the ip options
			optbuf:=new(bytes.Buffer)
			tsoption:=IPTimeStampOption{Pointer:uint8(4+1),Oflwflg:uint8(3),Ip1:IPtouint32(IPinfo["firstip"]),Ts1:uint32(0),Ip2:IPtouint32(IPinfo["secondip"]),Ts2:uint32(0),Ip3:IPtouint32(IPinfo["thirdip"]),Ts3:uint32(0)}
			v:=reflect.ValueOf(tsoption)
			
			for k:=0; k<v.NumField(); k++ {
				err := binary.Write(optbuf,binary.BigEndian,v.Field(k).Interface())
				if err != nil {
					log.Println("binary.Write failed:", err)
				}
			}
			optlen:=2+len(optbuf.Bytes())
			//fmt.Println("optionlen: ",optlen)
			opt:=layers.IPv4Option{OptionType:uint8(0x44), OptionLength:uint8(optlen),OptionData:optbuf.Bytes()}
			ipopt:=[]layers.IPv4Option{opt}
			eth_layer = &layers.Ethernet {
				SrcMAC: Eth.HardwareAddr,
				DstMAC: GwMAC,
				EthernetType: 0x0800,
			}
			ip_layer = &layers.IPv4{
				Version: uint8(0x4),
				//IHL: uint8(0x9),
		  	SrcIP: IPmap["srcip"],
		  	DstIP: IPmap["dstip"],
		  	Id: p.Id ,
		  	TTL: p.Ttl,
		  	Flags: layers.IPv4DontFragment,
		  	Protocol: layers.IPProtocolTCP,
		  	Options: ipopt,
			}
			tcp_layer = &layers.TCP {
				SrcPort: layers.TCPPort(25500+i*10+j),
				DstPort: layers.TCPPort(80),
				Window: 1500,
				Seq: seq, 
				//SYN:true,
				PSH: true,
				ACK: true,
			}
			tcp_layer.SetNetworkLayerForChecksum(ip_layer)
			p.Buf=gopacket.NewSerializeBuffer()
			options=gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			gopacket.SerializeLayers(p.Buf,options,eth_layer,ip_layer,tcp_layer,gopacket.Payload(payload),)
			Probeinfo.Lock()
			Probeinfo.m[uint16(25500+i*10+j)] = p
			Probeinfo.Unlock()
			//fmt.Printf("Buf: %x \n",p.Buf.Bytes())
			//schedule the packet
			chan_probe<-p
		}
	}
}

func initpcap(iface *net.Interface, ipmap map[string]net.IP) (*pcap.Handle, error){
	log.Println("Initpcap: ",iface.Name)
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil,err
	}
	
	filter := fmt.Sprintf("icmp or host %s",ipmap["dstip"].String())
	err = handle.SetBPFFilter(filter)
	if err!=nil {
		return nil,err
	}
	return handle,nil
}

func sendpcap(handle *pcap.Handle, chan_outprobe <-chan *CGProbe){
	log.Println("Send ready")
	for probe :=range chan_outprobe {
		go preparesend(handle,probe.Buf.Bytes(),probe.TsPrep)
	}
}

func preparesend(handle *pcap.Handle, pck []byte, t time.Time){
	time.Sleep(t.Sub(time.Now()))
	handle.WritePacketData(pck)
}

func recvpcap(handle *pcap.Handle, chan_response <-chan *CGProbe, wgp, wgsent *sync.WaitGroup){
	log.Println("Recv prep ",handle, handle.LinkType())
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Recv ready")
	wgp.Done()
  for packet := range packetSource.Packets() {
  	//parse the packet
  	if done:=parsepacket(packet,wgsent); done{
  		return
  	}
	}
}

func parsepacket(pkt gopacket.Packet, wgsent *sync.WaitGroup)bool{
	var ethl layers.Ethernet
	var ipv4l layers.IPv4
	var icmpv4l layers.ICMPv4
	var tcpl layers.TCP
	var payl gopacket.Payload
		
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethl, &ipv4l, &icmpv4l, &tcpl,&payl)
	//parser_icmppayload := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,&ipv4l,&tcpl,&payl)
	
	
	decoded :=[]gopacket.LayerType{}
	//decoded_icmp := []gopacket.LayerType{}
	
	err:=parser.DecodeLayers(pkt.Data(), &decoded)
	if err!=nil{
		log.Println("Decode layer failed ",err)
	}
	
	for _, layerType := range decoded {
  	switch layerType {
  		case layers.LayerTypeTCP:
  			//This shd be the outgoing probes. Check the tcp sequence number. just quick check here. we shd further verify other fields in later version
  			//log.Printf("Got TCP packet\n")
  			Probeinfo.RLock()
  			if  _, exist:=Probeinfo.m[uint16(tcpl.SrcPort)]; exist {
  				Probeinfo.RUnlock()
  				Probeinfo.Lock()
  				Probeinfo.m[uint16(tcpl.SrcPort)].TsSend = pkt.Metadata().CaptureInfo.Timestamp
  				Probeinfo.Unlock()
  				log.Printf("Got outgoing packet: ts %v sport %d seq %v", pkt.Metadata().CaptureInfo.Timestamp, tcpl.SrcPort, tcpl.Seq)
  				goto parsefinish
  			}else{
  				//packet reach destination?
  				prid:=uint16(tcpl.DstPort)
  				if _, exist:=Probeinfo.m[prid]; exist && ipv4l.SrcIP.Equal(IPinfo["dstip"]) {
  					Probeinfo.RUnlock()
  					tmpipopt:=IPTimeStampOption{}
  					buf:=bytes.NewBuffer(ipv4l.Options[0].OptionData)
  					err=binary.Read(buf ,binary.BigEndian,&tmpipopt )
  					Probeinfo.Lock()
  					Probeinfo.m[prid].RespIP = ipv4l.SrcIP
  					Probeinfo.m[prid].TsRecv = pkt.Metadata().CaptureInfo.Timestamp
  					Probeinfo.m[prid].Internetts=[]uint32{tmpipopt.Ts1,tmpipopt.Ts2,tmpipopt.Ts3}
  					Probeinfo.Unlock()
  					log.Printf("RST IP Option Port: %d ts: %v ts1: %v ts2 %v ts3: %v\n", tcpl.DstPort, pkt.Metadata().CaptureInfo.Timestamp,tmpipopt.Ts1,tmpipopt.Ts2,tmpipopt.Ts3 )
  					rcount++
  					
  				}else{
  					Probeinfo.RUnlock()
  				}
  				goto parsefinish
  				//fmt.Println(pkt)
  			}
  			
  		case layers.LayerTypeICMPv4:
  			//check if this is a response packet
  			if icmpv4l.TypeCode.Type()== layers.ICMPv4TypeTimeExceeded && icmpv4l.TypeCode.Code()==layers.ICMPv4CodeTTLExceeded {
  				//TTL exceeded packet
  				//log.Printf("Got ICMP TTL \n")
  				//it should contains the original IP packet header
  				tmpp:=gopacket.NewPacket(pkt.ApplicationLayer().Payload(), layers.LayerTypeIPv4, gopacket.NoCopy)
  				//err=parser.DecodeLayers(pkt.ApplicationLayer().Payload(), &decoded_icmp)
  				if tmpiplayer:=tmpp.Layer(layers.LayerTypeIPv4); tmpiplayer!=nil {
  					tmpip,_ :=tmpiplayer.(*layers.IPv4)
  					rcount++
  					tmpipopt:=IPTimeStampOption{}
  					buf:=bytes.NewBuffer(tmpip.Options[0].OptionData)
  					err=binary.Read(buf ,binary.BigEndian,&tmpipopt )
  					if err!=nil{
  						log.Println("Fail to parse IP option ",err)
  					}else{
  						log.Printf("ICMP-TTL Src: %v Id: %v Option ts1: %v ts2 %v ts3: %v\n",ipv4l.SrcIP, tmpip.Id, tmpipopt.Ts1,tmpipopt.Ts2,tmpipopt.Ts3 )
  						if tmptcp:=tmpp.Layer(layers.LayerTypeTCP); tmptcp!=nil {
	  						tmptcpl,_:=tmptcp.(*layers.TCP)
	  						prid:=uint16(tmptcpl.SrcPort)
	  						if _, exist:=Probeinfo.m[prid]; exist{
		  						Probeinfo.Lock()
		  						Probeinfo.m[prid].RespIP = ipv4l.SrcIP
		  						Probeinfo.m[prid].TsRecv = pkt.Metadata().CaptureInfo.Timestamp
		  						Probeinfo.m[prid].Internetts=[]uint32{tmpipopt.Ts1,tmpipopt.Ts2,tmpipopt.Ts3}
		  						Probeinfo.Unlock()
		  					}else{
		  						log.Println("id not exit", uint16(tmptcpl.SrcPort))
		  					}
		  				}else{
		  					log.Println("cannot decode tcp layer")
		  				}
		  				goto parsefinish
  					}
  				}
  				
  				
  			}
  		
  		//chan_response<-packet
  	}
	}
	parsefinish:
	if rcount==(*Numpacket)*3 {
		rcount++
		print_summary()
		wgsent.Done()
		return true
	}
	return false
}

func print_summary(){
	Probeinfo.RLock()
	for i:=0; i<3 ; i++{
		for j:=0; j<*Numpacket; j++{
			pid:=uint16(25500+i*10+j)
			rtt:=Probeinfo.m[pid].TsRecv.Sub(Probeinfo.m[pid].TsSend).Seconds()*1000
			fmt.Printf("Probe to port %d, Hop %v, TTL %d, RTT %v ms, TS %v\n", pid, Probeinfo.m[pid].RespIP, Probeinfo.m[pid].Ttl, rtt, Probeinfo.m[pid].Internetts)
		}
	}
	Probeinfo.RUnlock()
}

func waittimeout(t int, wgsent *sync.WaitGroup){
	time.Sleep(time.Second*time.Duration(t))
		//timeout
	log.Println("Timeout")
	print_summary()
	wgsent.Done()
}

func cgtr_do(){
	//craft packets
	//schedule and send packets
	//read and parse responses
	//compute results
}

func main(){
	var handle *pcap.Handle
	var handlerecv *pcap.Handle
	IPinfo = make(map[string]net.IP)
	//Probeinfo = make(map[uint32]CGProbe)
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
		log.Printf("Got %s:%s\n",Infomap[i+2],IPinfo[Infomap[i+2]].String())
	}
	//the pcap handler for sending packets
	if handle,err=initpcap(Eth,IPinfo); err!=nil {
		log.Fatalln("pcap failed: %s",err)
	}
	//the pcap handler for recv packets
	if handlerecv,err=initpcap(Eth,IPinfo); err!=nil {
		log.Fatalln("pcap failed: %s",err)
	}
	defer handle.Close()
	defer handlerecv.Close()
	rcount = 0
	chan_probe:=make(chan *CGProbe,(*Numpacket)*3)
	defer close(chan_probe)
	chan_response:=make(chan *CGProbe)
	defer close(chan_response)
	wgpcap.Add(1)
	wg.Add(1)
	go sendpcap (handle, chan_probe)
	go recvpcap (handlerecv, chan_response,&wgpcap,&wg)
	wgpcap.Wait()
	
	go craft_packet(*LinkTTL, IPinfo, chan_probe)
	//TTLstart int, IPmap map[string]net.IP, chan_probe chan<- *CGProbe){
	
	go waittimeout(*Tout, &wg)
	//wait either timeout or received all icmp messages
	log.Println("Wait until finish")
	wg.Wait()
	
}