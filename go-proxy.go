package main

import "log"
//import "net"

//import "github.com/docopt/docopt-go"
//import "github.com/ghedo/go.pkt/routing"
import "github.com/ghedo/go.pkt/capture/pcap"
//import "github.com/ghedo/go.pkt/filter"
import "github.com/ghedo/go.pkt/layers"
import "github.com/ghedo/go.pkt/packet"
//import "github.com/ghedo/go.pkt/packet/udp"

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

    //log.Println(pkt)
    //log.Println("")
    //log.Println(pkt.Payload().Payload().GetType())
    payload := pkt.Payload()
    if (nil != payload) {
      payload = payload.Payload()
      if (nil != payload) {
        packetType := payload.GetType()
        if ("UDP" == packetType.String()) {
          log.Println(packetType)
          log.Println(payload.GetLength())
          log.Println("")
        }
      }
    }
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
