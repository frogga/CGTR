package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	//"os"
	//"strconv"
	"time"
	"flag"
	"strings"
)
type CGProbe struct{
	Ttl int
	Id int
	Buf gopacket.Packet
	TsPrep time.Time
	TsSend time.Time
	TsRecv time.Time
}

var (
	err error
	Infomap=[...]string{"srcip","dstip","firstip","secondip","thirdip"}
	IPinfo map[string]net.IP
	Eth *net.Interface
	GwMAC net.HardwareAddr
	LinkTTL = flag.Int("ttl",0,"The TTL value to reach the first IP in triplet")
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

func craft_packet(TTLstart int, IPmap map[string]net.IP){
	var buffer gopacket.SerializeBuffer
	var options gopacket.SerializeOptions
	var eth_layer *layers.Ethernet
	var ip_layer *layers.IPv4
	var tcp_layer *layers.TCP
	

	for i:=0; i<3; i++ {
		for j:=0; j<2; j++{
			eth_layer = &layers.Ethernet {
				SrcMAC: *Eth.HardwareAddr,
				DstMAC: GwMAC,
				EthernetType: 0x0800,
			}
			ip_layer = &layers.IPv4{
		  	SrcIP: IPmap["srcip"],
		  	DstIP: IPmap["dstip"],
		  	
			}
			tcp_layer = &layer.TCP {
				DstPort: layers.TCPPort(80),
				Ack: 123456, //an arbitrary number
				PSH: true,
				ACK: true,
			}
			buffer=gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(buffer,options,)
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
	
	
}