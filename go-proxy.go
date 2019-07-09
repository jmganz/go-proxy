package main

import "log"
//import "net"
import "encoding/binary"

//import "github.com/docopt/docopt-go"
//import "github.com/ghedo/go.pkt/routing"
import "github.com/ghedo/go.pkt/capture/pcap"
//import "github.com/ghedo/go.pkt/filter"
import "github.com/ghedo/go.pkt/layers"
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

  dst, err := pcap.Open("ark0")
  if err != nil {
    log.Fatal(err)
  }
  defer dst.Close()

  // you may configure the source further, e.g. by activating
  // promiscuous mode.

  err = src.Activate()
  if err != nil {
    log.Fatal(err)
  }

  err = dst.Activate()
  if err != nil {
    log.Fatal(err)
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
          log.Println("START")
          log.Println(buf)
          log.Println("ETHERNET")
          log.Println(pkt)
          log.Println("IPv4")
          ip_pkt := layers.FindLayer(pkt, packet.IPv4)
          log.Println(ip_pkt)
          log.Println("UDP")
          log.Println(udp_pkt)
          log.Println("Found a Proxy Packet!")
          //srcIP := binary.BigEndian.Uint32(buf[56:60])
          //dstIP := binary.BigEndian.Uint32(buf[72:76])
          log.Printf("client - %d.%d.%d.%d:%d\n", buf[56], buf[57], buf[58], buf[59], binary.BigEndian.Uint16(buf[76:78]))
          log.Printf("proxy - %d.%d.%d.%d:%d\n", buf[72], buf[73], buf[74], buf[75], binary.BigEndian.Uint16(buf[78:80]))
          log.Println(string(buf[80:]))
          log.Println("FINISH")

          log.Println("*** new ether ***")
          eth_pkt := eth.Make()
          eth_pkt.DstAddr = buf[0:6]
          eth_pkt.SrcAddr = buf[6:12]
          eth_pkt.Type = eth.IPv4
          log.Println(eth_pkt)

          log.Println("*** new ipv4 ***")
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
          ip4_pkt.Checksum = 0x51a9 // TODO: compute this properly
          ip4_pkt.SrcAddr = buf[56:60]
          //ip4_pkt.DstAddr = buf[72:76]
          ip4_pkt.DstAddr = buf[30:34]
          log.Println(ip4_pkt)

          log.Println("*** new udp ***")
          fwd_udp := udp.Make()
          fwd_udp.SrcPort = binary.BigEndian.Uint16(buf[76:78])
          fwd_udp.DstPort = binary.BigEndian.Uint16(buf[78:80])
          log.Println(fwd_udp)


          log.Println("*** new data ***")
          raw_pkt := raw.Make()
          raw_pkt.Data = buf[80:]
          log.Println(raw_pkt)



          buf, err := layers.Pack(eth_pkt, ip4_pkt, fwd_udp, raw_pkt)
          if err != nil {
            log.Fatal("Error packing: %s", err)
          }
          log.Println("HERE'S THE NEW BUFFER")
          log.Println(buf)

          log.Println("HERE'S THE NEW PACKET")


          new_pkt, err := layers.UnpackAll(buf, packet.UDP)
          if err != nil {
            log.Fatal(err)
          }
          log.Println(new_pkt)

        } // packet contains magic number 0x56EC
      } // length > 44 bytes
    } // UDP packet
    
  }
    
}
