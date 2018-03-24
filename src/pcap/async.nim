import asyncdispatch, asyncnet, rawsockets, net, os
import unsigned
import strutils
import wrapper


type
  AsyncPcap* = ref object
    pcap: pcap_t
    fd: AsyncFd

proc newAsyncPcap*(pcap: pcap_t): AsyncPcap =
  let fd = pcap_get_selectable_fd(pcap)
  pcap.checkError fd

  result = AsyncPcap(
    pcap: pcap,
    fd: fd.AsyncFd
  )

  register(result.fd)

proc readPacket*(ap: AsyncPcap): Future[string] =
  var retFuture = newFuture[string]("asyncpcap.readPacket")

  proc cb(fd: AsyncFd): bool =
    var packet: ptr pcap_pkthdr
    var buffer: cstring
    let ret = pcap_next_ex(ap.pcap, addr packet, addr buffer)
    case ret
    of 0:
      return false # No packet received, ask to be called again.
    of 1:
      assert buffer != nil
      # Copy data buffer.
      var data = newString(packet.caplen)
      copyMem(addr data[0], buffer, data.len)

      retFuture.complete(data)
      result = true
    else:
      ap.pcap.checkError(ret)

  if not cb(ap.fd):
    addRead(ap.fd, cb)

  return retFuture