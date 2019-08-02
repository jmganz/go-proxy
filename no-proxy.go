package main

import "os"
import "log"
import "net"
import "strconv"
import "encoding/binary"

import "github.com/ghedo/go.pkt/capture/pcap"
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
  // you may configure the source further, e.g. by activating
  // promiscuous mode.

  err = src.Activate()
  if err != nil {
    log.Fatal(err)
  }

  addrs, err := net.InterfaceAddrs()
  if err != nil {
    log.Fatal(err)
  }


  for _, a := range addrs {
    if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
      if ipnet.IP.To4() != nil {
      }
    }
  }

  origin_ip, err := strconv.Atoi(os.Getenv("ORIGINIP"))
  if err != nil {
    log.Fatal(err)
  }
  private_ip, err := strconv.Atoi(os.Getenv("PRIVATEIP"))
  if err != nil {
    log.Fatal(err)
  }
  proxy_ip, err  := strconv.Atoi(os.Getenv("PROXYIP"))
  if err != nil {
    log.Fatal(err)
  }
  log.Println(proxy_ip)

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
      // Check if the source or destination port matches values we're listening on
      proxy_ports := map[uint16]bool {4242:true, 4252:true, 7777:true, 7778:true, 7787:true, 7788:true, 26900:true, 26901:true, 26902:true, 26903:true, 26904:true, 26905:true, 26910:true, 26911:true, 26912:true, 26913:true, 26914:true, 26915:true, 27015:true, 27016:true, 27017:true, 27018:true, 27019:true, 27020:true, 27025:true, 27026:true, 27027:true, 27028:true, 27029:true, 27030:true, 27215:true, 27225:true, 32330:true, 32340:true}
      correct_ports := map[uint16]bool {4242:true, 7777:true, 7778:true, 26900:true, 26901:true, 26902:true, 26903:true, 26904:true, 26905:true, 27015:true, 27016:true, 27017:true, 27018:true, 27019:true, 27020:true, 27215:true, 32330:true}
      higher_ports := map[uint16]bool {4252:true, 7787:true, 7788:true, 26910:true, 26911:true, 26912:true, 26913:true, 26914:true, 26915:true, 27025:true, 27026:true, 27027:true, 27028:true, 27029:true, 27030:true, 27225:true, 32340:true}
      _, matchSrc := proxy_ports[binary.BigEndian.Uint16(buf[34:36])]
      _, matchDst := proxy_ports[binary.BigEndian.Uint16(buf[36:38])]
      if (matchSrc || matchDst) {
        // buf[26:30] is src ip
        // buf[30:34] is dst ip
        // buf[34:36] is src port
        // buf[36:38] is dst port
        srcIP := binary.BigEndian.Uint32(buf[26:30])
        dstIP := binary.BigEndian.Uint32(buf[30:34])
        srcPort := binary.BigEndian.Uint16(buf[34:36])
        dstPort := binary.BigEndian.Uint16(buf[36:38])

        if (srcIP == uint32(private_ip) {
          binary.BigEndian.PutUint32(buf[26:30], uint32(origin_ip))
          _, matchSrcPort := proxy_ports[binary.BigEndian.Uint16(buf[36:38])]
          if (matchSrcPort) {
            
          }
          log.Println("This packet is going OUT")
        }
        if ((srcIP == uint32(origin_ip)) || (srcIP == uint32(private_ip))) {
          log.Println("This packet is going OUT")
        }
        if ((dstIP == uint32(origin_ip)) || (dstIP == uint32(private_ip))) {
          log.Println("This packet is coming IN")
          // SUBTRACT 10 FROM dstPort
          binary.BigEndian.PutUint16(buf[34:36], binary.BigEndian.Uint16(buf[34:36]) - 10) // SrcPort
          
        }

        log.Println("\n\n\n*** Packet Match ***")
        //log.Println(buf)
        //log.Println("ETHERNET")
        //log.Println(pkt)
        //log.Println("IPv4")
        //ip_pkt := layers.FindLayer(pkt, packet.IPv4)
        //log.Println(ip_pkt)
        //log.Println("UDP")
        //log.Println(udp_pkt)
        //log.Println(string(buf[80:]))
        log.Println("Old Packet:")
        old_pkt, err := layers.UnpackAll(buf, packet.Eth)
        if err != nil {
          log.Fatal(err)
        }
        log.Println(old_pkt)
        log.Println("*** data ***")
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
        ip4_pkt.Length = binary.BigEndian.Uint16(buf[16:18])
        log.Println("LENGTH - ", ip4_pkt.Length)
        ip4_pkt.Id = binary.BigEndian.Uint16(buf[18:20])
        ip4_pkt.Flags = 10
        ip4_pkt.TTL = uint8(buf[22])
        ip4_pkt.Protocol = ipv4.UDP
        //ip4_pkt.Checksum = 0x51a9 // TODO: compute this properly
        //binary.BigEndian.PutUint16(buf2[76:78], binary.BigEndian.Uint16(buf[34:36]) + 10) // SrcPort
        //binary.BigEndian.PutUint16(buf2[78:80], binary.BigEndian.Uint16(buf[36:38])) // DstPort
        //binary.BigEndian.PutUint32(buf[30:34], uint32(origin_ip))
        ip4_pkt.SrcAddr = buf[26:30]
        ip4_pkt.DstAddr = buf[30:34]

        fwd_udp := udp.Make()
        fwd_udp.SrcPort = binary.BigEndian.Uint16(buf[34:36])
        fwd_udp.DstPort = binary.BigEndian.Uint16(buf[36:38])
        fwd_udp.Checksum = binary.BigEndian.Uint16(buf[38:40])

        raw_pkt := raw.Make()
        if (len(buf) > 42) {
          raw_pkt.Data = buf[42:len(buf)]
        }
        fwd_udp.SetPayload(raw_pkt)
        ip4_pkt.SetPayload(fwd_udp)
        eth_pkt.SetPayload(ip4_pkt)

        buf, err = layers.Pack(eth_pkt, ip4_pkt, fwd_udp, raw_pkt)

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
      } // if the ports match, process it
    } // UDP packet
  }
}
