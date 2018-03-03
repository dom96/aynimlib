import posix

when defined(macosx):
  const
    libName = "libpcap.dylib"
    defaultIfName* = "en0"
else:
  const
    libName = "libpcap.so"
    defaultIfName* = "eth0"

type
  pcap_t* {.importc: "pcap_t", header: "<pcap/pcap.h>".} = ptr object
  pcap_pkthdr* {.importc: "struct pcap_pkthdr", header: "<pcap/pcap.h>",
                 final, pure.} = object
    ts*: Timeval
    caplen*: uint32
    len*: uint32

const PCAP_ERRBUF_SIZE* = 256

# https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-bpf.c#L234
# http://www.tcpdump.org/linktypes.html
const
  DLT_PRISM_HEADER* = 119
  DLT_AIRONET_HEADER* = 120
  DLT_IEEE802_11_RADIO* = 127
  DLT_IEEE802_11_RADIO_AVS* = 163

proc pcap_open_live*(dev: cstring, snaplen: cint, promisc: cint,
                     to_ms: cint, errbuf: pointer): pcap_t
  {.cdecl, dynlib: libName, importc.}

proc pcap_create*(source: cstring, errbuf: pointer): pcap_t 
  {.cdecl, dynlib: libName, importc.}
proc pcap_activate*(pcap: pcap_t): cint 
  {.cdecl, dynlib: libName, importc.}

# pcap_findalldevs
# pcap_freealldevs
# pcap_lookupdev

proc pcap_open_offline*(fname: cstring, errbuf: pointer): pcap_t
  {.cdecl, dynlib: libName, importc.}

# pcap_fopen_offline
# pcap_open_dead

proc pcap_close*(pcap: pcap_t)
  {.cdecl, dynlib: libName, importc.}

proc pcap_set_snaplen*(pcap: pcap_t, snaplen: cint): cint 
  {.cdecl, dynlib: libName, importc.}
proc pcap_snapshot*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_set_promisc*(pcap: pcap_t, promisc: cint): cint 
  {.cdecl, dynlib: libName, importc.}
proc pcap_set_rfmon*(pcap: pcap_t, rfmon: cint): cint 
  {.cdecl, dynlib: libName, importc.}
proc pcap_can_set_rfmon*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_set_timeout*(pcap: pcap_t, to_ms: cint): cint 
  {.cdecl, dynlib: libName, importc.}

proc pcap_set_buffer_size*(pcap: pcap_t, buffer_size: cint): cint
  {.cdecl, dynlib: libName, importc.}

# pcap_set_tstamp_type
# pcap_list_tstamp_types
# pcap_free_tstamp_types
# pcap_tstamp_type_val_to_name
# pcap_tstamp_type_val_to_description
# pcap_tstamp_name_to_val
# pcap_datalink
# pcap_file
# pcap_is_swapped
# pcap_major_version
# pcap_minor_version

# pcap_dispatch
# pcap_loop

proc pcap_next*(pcap: pcap_t, h: ptr pcap_pkthdr): cstring
  {.cdecl, dynlib: libName, importc.}

proc pcap_next_ex*(pcap: pcap_t, pkt_header: ptr ptr pcap_pkthdr,
                   pkt_data: ptr cstring): cint
  {.cdecl, dynlib: libName, importc.}

# pcap_next_ex
# pcap_breakloop

proc pcap_setnonblock*(pcap: pcap_t, nonblock: cint, errbuf: pointer): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_getnonblock*(pcap: pcap_t, errbuf: pointer): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_get_selectable_fd*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_set_datalink*(pcap: pcap_t, val: cint): cint
  {.cdecl, dynlib: libName, importc.}

proc pcap_geterr*(pcap: pcap_t): cstring
  {.cdecl, dynlib: libName, importc.}

proc pcap_datalink*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc.}

proc checkError*(pcap: pcap_t, ret: cint) =
  if ret < 0:
    raise newException(OSError, $pcap_geterr(pcap))

when isMainModule:
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  if not p.isNil():
    # pcap_set_buffer_size(p, 1500.cint)
    # p.pcap_set_nonblock(1, nil)
    p.checkError p.pcap_set_timeout(1000.cint)
    p.checkError pcap_activate(p)
    var ph: pcap_pkthdr
    var data = pcap_next(p, addr(ph))
    if data != nil:
      echo(ph.len, ", ", ph.caplen, " ", $ph.ts)
      var res: string = newString(ph.caplen)
      res.setLen(ph.caplen)
      copyMem(cast[pointer](res.cstring), data, ph.caplen)
    else:
      echo "Data is nil"
  else:
    echo "Could not open pcap"



