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
//import "github.com/ghedo/go.pkt/packet/udp"
//import "github.com/ghedo/go.pkt/packet/ipv4"

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
          log.Println(buf)
          log.Println("")
          log.Println("Found a Proxy Packet!")
          //srcIP := binary.BigEndian.Uint32(buf[56:60])
          //dstIP := binary.BigEndian.Uint32(buf[72:76])
          log.Printf("client - %d.%d.%d.%d:%d\n", buf[56], buf[57], buf[58], buf[59], binary.BigEndian.Uint16(buf[76:78]))
          log.Printf("proxy - %d.%d.%d.%d:%d\n", buf[72], buf[73], buf[74], buf[75], binary.BigEndian.Uint16(buf[78:80]))
          log.Println(string(buf[80:]))
          ip_pkt := layers.FindLayer(pkt, packet.IPv4)
          log.Println(ip_pkt)
          //log.Println(ip_pkt)
          /*
          packet := ipv4.Packet {
            Version: 4,
            IHL: 5,
            Length: 28,
            TOS: 80,
            Id: 15,
            TTL: 56,
            Flags: ipv4.DontFragment,
            Protocol: ipv4.UDP,
            SrcAddr: buf[56:60],
            DstAddr: buf[72:76],
          }
          */
        }
      }
    }





/*
    data := layers.FindLayer(pkt, packet.Raw)
    if (nil != data) {
      //log.Println(udp_pkt)
      //data := udp_pkt.Payload()
      log.Println(data)
    }
*/
    /*
    payload := pkt.Payload() // IP
    if (nil != payload) {
      payload = payload.Payload() // UDP / TCP
      if (nil != payload) {
        packetType := payload.GetType()
        if ("UDP" == packetType.String()) {
          //log.Println(packetType)
          udpData := payload.Payload()
          if (nil != udpData) {
            log.Println(buf)
            log.Println(packet.UDP)
            //unpacked := udpData.Unpack(newBuf)
            //log.Println(udpData.GetLength())
            //log.Println(unpacked)
            log.Println("")
          }
        }
      }
    }
    */
    /*
    if (pkt.Match("UDP")) {
      log.Println("UDP!")
    }
    */
    
    
    
    
    //log.Println("PACKET!!!")

    /*
    flt, err := filter.Compile("udp or tcp", packet.Eth, true)
    if err != nil {
      log.Fatal(err)
    }
    log.Println(flt)
    log.Println(buf)
    */

    //if flt.Match([]byte(0x56EC)) {
    //  log.Println("MATCH!!!")
    //  log.Println(buf)
    //}
    // do something with the packet
    
  }
    
}
