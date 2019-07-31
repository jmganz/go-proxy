package main

import "os"
import "log"
import "net"
import "strconv"
import "encoding/binary"

//import "github.com/docopt/docopt-go"
//import "github.com/ghedo/go.pkt/routing"
import "github.com/ghedo/go.pkt/capture/pcap"
//import "github.com/ghedo/go.pkt/filter"
import "github.com/ghedo/go.pkt/layers"
import "github.com/ghedo/go.pkt/network"
import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/udp"
import "github.com/ghedo/go.pkt/packet/ipv4"
import "github.com/ghedo/go.pkt/packet/eth"
import "github.com/ghedo/go.pkt/packet/raw"

func main() {
  log.SetFlags(0)

  src, err := pcap.Open("eno1")
  if err != nil {
    log.Fatal(err)
  }
  defer src.Close()
/*
  dst, err := pcap.Open("ark0")
  if err != nil {
    log.Fatal(err)
  }
  defer dst.Close()
*/
  // you may configure the source further, e.g. by activating
  // promiscuous mode.

  err = src.Activate()
  if err != nil {
    log.Fatal(err)
  }
/*
  err = dst.Activate()
  if err != nil {
    log.Fatal(err)
  }
*/

  addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	//log.Println(addrs)

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//log.Println(ipnet.IP.String())
			}
		}
	}

  for {
    buf, err := src.Capture()
    if err != nil {
      log.Fatal(err)
    }

    // Assume Ethernet as datalink layer
    pkt, err := layers.UnpackAll(buf, packet.Eth)
    if err != nil {
      log.Fatal(err)
    }

    udp_pkt := layers.FindLayer(pkt, packet.UDP)
    if (nil != udp_pkt) {
      if (len(buf) > 44) {
        if ( 0x56EC == binary.BigEndian.Uint16(buf[42:44]) ) {
          //log.Println(pkt)
          //log.Println("START")

          //log.Println(buf)
          //log.Println("ETHERNET")
          //log.Println(pkt)
          //log.Println("IPv4")
          //ip_pkt := layers.FindLayer(pkt, packet.IPv4)
          //log.Println(ip_pkt)
          //log.Println("UDP")
          //log.Println(udp_pkt)
          log.Println("\n\n\n*** Found a Proxy Packet ***")
          log.Printf("client - %d.%d.%d.%d:%d\n", buf[56], buf[57], buf[58], buf[59], binary.BigEndian.Uint16(buf[76:78]))
          log.Printf("proxy - %d.%d.%d.%d:%d\n", buf[72], buf[73], buf[74], buf[75], binary.BigEndian.Uint16(buf[78:80]))
          log.Println(string(buf[80:]))
          log.Println("*** FINISH ***")

          //log.Println("*** new ether ***")
          eth_pkt := eth.Make()
          eth_pkt.DstAddr = buf[0:6]
          eth_pkt.SrcAddr = buf[6:12]
          eth_pkt.Type = eth.IPv4
          //log.Println(eth_pkt)

          //log.Println("*** new ipv4 ***")
          ip4_pkt := ipv4.Make()
          ip4_pkt.Version = ((buf[14] >> 4) & 0xF)
          ip4_pkt.IHL = (buf[14] & 0xF)
          ip4_pkt.TOS = buf[15]

          // This is actually the UDP length
          ip4_pkt.Length = binary.BigEndian.Uint16(buf[16:18]) - 38
          ip4_pkt.Id = binary.BigEndian.Uint16(buf[18:20])
          //ip4_pkt.Flags = binary.BigEndian.Uint16(buf[20:22])
          //ip4_pkt.Flags = ip_pkt.Flags
          ip4_pkt.Flags = 10
          ip4_pkt.TTL = uint8(buf[22])
          ip4_pkt.Protocol = ipv4.UDP
          //ip4_pkt.Checksum = 0x51a9 // TODO: compute this properly
          //log.Println("*** SOURCE ADDRESSES ***")
          //log.Println(buf[56:60])
          //ip4_pkt.SrcAddr = buf[56:60]
          //log.Println(buf[72:76])
          ip4_pkt.SrcAddr = buf[72:76]
          //ip4_pkt.DstAddr = buf[72:76]
          ip4_pkt.DstAddr = buf[30:34]
          //log.Println(ip4_pkt)

          //log.Println("*** new udp ***")
          fwd_udp := udp.Make()
          fwd_udp.SrcPort = binary.BigEndian.Uint16(buf[76:78])
          fwd_udp.DstPort = binary.BigEndian.Uint16(buf[78:80])
          //log.Println(fwd_udp)

          //log.Println("*** new data ***")
          raw_pkt := raw.Make()
          raw_pkt.Data = buf[80:]
          //log.Println(raw_pkt)

          fwd_udp.SetPayload(raw_pkt)
          ip4_pkt.SetPayload(fwd_udp)
          eth_pkt.SetPayload(ip4_pkt)

          buf, err := layers.Pack(eth_pkt, ip4_pkt, fwd_udp, raw_pkt)
          if err != nil {
            log.Fatal("Error packing: %s", err)
          }
          log.Println("New Buffer:")
          log.Println(buf)

          log.Println("New Packet:")
          new_pkt, err := layers.UnpackAll(buf, packet.Eth)
          if err != nil {
            log.Fatal(err)
          }
          log.Println(new_pkt)

          err = network.Send(src, eth_pkt, ip4_pkt, fwd_udp, raw_pkt)
          if err != nil {
            log.Fatal(err)
          }

        } // packet contains magic number 0x56EC, so it's a Proxy Packet
      } // length > 44 bytes
      if ( len(buf) < 45 || 0x56EC != binary.BigEndian.Uint16(buf[42:44]) ) {
        proxy_ports := map[uint16]bool {4242:true, 4252:true, 7777:true, 7778:true, 7787:true, 7788:true, 26900:true, 26901:true, 26902:true, 26903:true, 26904:true, 26905:true, 26910:true, 26911:true, 26912:true, 26913:true, 26914:true, 26915:true, 26916:true, 26917:true, 26918:true, 26919:true, 26920:true, 27025:true, 27026:true, 27027:true, 27028:true, 27029:true, 27030:true, 27215:true, 27225:true, 32330:true, 32340:true}
        origin_ip, err := strconv.Atoi(os.Getenv("ORIGINIP"))
        if err != nil {
          log.Fatal(err)
        }
        proxy_ip, err  := strconv.Atoi(os.Getenv("PROXYIP"))
        if err != nil {
          log.Fatal(err)
        }
        // Check if the source or destination port matches values we're listening on
        _, matchSrc := proxy_ports[binary.BigEndian.Uint16(buf[34:36])]
        _, matchDst := proxy_ports[binary.BigEndian.Uint16(buf[36:38])]
        if (matchSrc || matchDst) {
          // buf[26:30] is src ip
          // buf[30:34] is dst ip
          // buf[34:36] is src port
          // buf[36:38] is dst port

          log.Println("\n\n\n*** Convert Non-Proxy Packet ***")
          //log.Println(buf)
          //log.Println("ETHERNET")
          //log.Println(pkt)
          //log.Println("IPv4")
          //ip_pkt := layers.FindLayer(pkt, packet.IPv4)
          //log.Println(ip_pkt)
          //log.Println("UDP")
          //log.Println(udp_pkt)
          //log.Println(string(buf[80:]))
          log.Println("*** data ***")
          raw_pkt := raw.Make()
          raw_pkt.Data = buf[42:]
          //log.Println(raw_pkt.Data)
          log.Println(string(buf[42:len(buf)]))
          log.Println("packet is ", len(buf), " bytes long")
          log.Println("*** FINISH ***")

          eth_pkt := eth.Make()
          eth_pkt.DstAddr = buf[0:6]
          eth_pkt.SrcAddr = buf[6:12]
          eth_pkt.Type = eth.IPv4

          ip4_pkt := ipv4.Make()
          ip4_pkt.Version = ((buf[14] >> 4) & 0xF)
          ip4_pkt.IHL = (buf[14] & 0xF)
          ip4_pkt.TOS = buf[15]
          ip4_pkt.Length = binary.BigEndian.Uint16(buf[16:18]) + 38
          log.Println("LENGTH - ", ip4_pkt.Length)
          //buf[42:44] = 0x56EC
          binary.BigEndian.PutUint16(buf[42:44], 0x56EC)
          ip4_pkt.Id = binary.BigEndian.Uint16(buf[18:20])
          ip4_pkt.Flags = 10
          ip4_pkt.TTL = uint8(buf[22])
          ip4_pkt.Protocol = ipv4.UDP
          //ip4_pkt.Checksum = 0x51a9 // TODO: compute this properly
          //buf[44:60] = binary.BigEndian.Uint128(origin_ip) // client - server ip
          //binary.BigEndian.PutUint128(buf[44:60], origin_ip) // client - server ip
          buf2 := make([]byte, ip4_pkt.Length)
          binary.BigEndian.PutUint64(buf2[44:52], 0) // client - server ip
          binary.BigEndian.PutUint64(buf2[52:60], uint64(origin_ip)) // client - server ip
          //buf[60:76] = binary.BigEndian.Uint128(uint64(proxy_ip)) // proxy - spectrum ip
          log.Println("good1")
          binary.BigEndian.PutUint64(buf2[60:68], 0) // proxy - spectrum ip
          binary.BigEndian.PutUint64(buf2[68:76], uint64(proxy_ip)) // proxy - spectrum ip
          //buf[76:78] = binary.BigEndian.Uint16(udp_pkt.SrcPort)
          binary.BigEndian.PutUint16(buf2[76:78], binary.BigEndian.Uint16(buf[34:36]))
          //buf[78:80] = binary.BigEndian.Uint16(udp_pkt.DstPort)
          // binary.BigEndian.PutUint16(buf2[78:80], binary.BigEndian.Uint16(buf[36:38]))
          // Do I need to add 10 to the port number to handle the proxy port communication?
          binary.BigEndian.PutUint16(buf2[78:80], binary.BigEndian.Uint16(buf[36:38]) + 10)
          log.Printf("client - %d.%d.%d.%d:%d\n", buf2[56], buf2[57], buf2[58], buf2[59], binary.BigEndian.Uint16(buf2[76:78]))
          log.Printf("proxy - %d.%d.%d.%d:%d\n", buf2[72], buf2[73], buf2[74], buf2[75], binary.BigEndian.Uint16(buf2[78:80]))
          //ip4_pkt.SrcAddr = buf[6:12]
          ip4_pkt.DstAddr = buf2[72:76]
          ip4_pkt.SrcAddr = buf2[56:60]

          fwd_udp := udp.Make()
          // TODO: Fix this
          fwd_udp.SrcPort = binary.BigEndian.Uint16(buf2[76:78])
          fwd_udp.DstPort = binary.BigEndian.Uint16(buf2[78:80])
          log.Println(fwd_udp)

          log.Println("*** new data ***")
          // raw_pkt := raw.Make()
          // buf2[80:] = buf[42:]
          raw_pkt.Data = buf[42:]
          log.Println(raw_pkt)

          fwd_udp.SetPayload(raw_pkt)
          ip4_pkt.SetPayload(fwd_udp)
          eth_pkt.SetPayload(ip4_pkt)

          buf2, err := layers.Pack(eth_pkt, ip4_pkt, fwd_udp, raw_pkt)
          if err != nil {
            log.Fatal("Error packing: %s", err)
          }

          log.Println("New Buffer:")
          log.Println(buf2)

          log.Println("New Packet:")
          new_pkt, err := layers.UnpackAll(buf, packet.Eth)
          if err != nil {
            log.Fatal(err)
          }
          log.Println(new_pkt)

          err = network.Send(src, eth_pkt, ip4_pkt, fwd_udp, raw_pkt)
          if err != nil {
            log.Fatal(err)
          }
        } // if the ports match, turn it into a Proxy Packet
      } // this is not a Proxy Packet
    } // UDP packet

  }

}
