
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include <pcap.h>

#include <mruby.h>
#include <mruby/data.h>

#ifdef __OpenBSD__
#include <netinet/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#include <arpa/inet.h>
#include <net/if_arp.h>


struct state {
  pcap_t *pcap;
};

struct cb_args {
  mrb_state *mrb;
  mrb_value cb;
};


static void pcap_state_free(mrb_state *mrb, void *ptr)
{
  struct state *st = (struct state *)ptr;
  
  if( st->pcap != NULL ){
    pcap_close(st->pcap);
    st->pcap = NULL;
  }
}

static struct mrb_data_type pcap_state_type = { "Pcap", pcap_state_free };


static mrb_value pcap_initialize(mrb_state *mrb, mrb_value self)
{
  char    errbuf[PCAP_ERRBUF_SIZE];
  struct state *st = mrb_malloc(mrb, sizeof(struct state));
  const char *ifname;
  
  mrb_int snaplen = 100;
  mrb_int timeout = 100;
  mrb_int promisc = 1;
  
  mrb_get_args(mrb, "z|ii", &ifname, &snaplen, &timeout);
  
  st->pcap = pcap_open_live(ifname, snaplen, promisc, timeout, errbuf);
  if( st->pcap == NULL ) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pcap_open_live failed: %S", mrb_str_new_cstr(mrb, errbuf));
    goto ret;
  }

  
  DATA_PTR(self)  = (void*)st;
  DATA_TYPE(self) = &pcap_state_type;
  
  
ret:
  return self;
}

static void pcap_packet_handler(u_char *v, const struct pcap_pkthdr *h, const u_char *bytes)
{
  // uint32_t                    ip;
  struct ether_addr           *ether_src, *ether_dest;
  struct in_addr              *ip_src, *ip_dest;
  struct ether_header         *heth;
  struct cb_args              *args = (struct cb_args *)v;
  mrb_value                   r_ret;
  
  heth = (struct ether_header*) bytes;
  
  if( ntohs(heth->ether_type) == ETHERTYPE_ARP){
    struct arphdr       *harp;
    
    harp = (struct arphdr*)(heth + 1);
    
    ether_src = (struct ether_addr*)(harp + 1);
    ip_src = (struct in_addr *)((void*)ether_src + harp->ar_hln);
    
    ether_dest = (struct ether_addr*)((void*)ip_src + harp->ar_pln);
    ip_dest = (struct in_addr *)((void*)ether_dest + harp->ar_hln);
    
    struct RClass *c = mrb_class_get(args->mrb, "ARPPacket");
    
    r_ret = mrb_funcall(args->mrb, mrb_obj_value(c), "new", 5,
        mrb_str_new_cstr(args->mrb, ether_ntoa(ether_src)),
        mrb_str_new_cstr(args->mrb, ether_ntoa(ether_dest)),
        mrb_fixnum_value( ntohs(harp->ar_op) ),
        mrb_str_new_cstr(args->mrb, inet_ntoa(*ip_src)),
        mrb_str_new_cstr(args->mrb, inet_ntoa(*ip_dest))
      );
    
    mrb_funcall(args->mrb, args->cb, "call", 1, r_ret);
  }

  
  // check packet type and source (ignore packet from us)
  // if( ntohs(heth->ether_type) == ETHERTYPE_ARP){
  //   // MSG("arp from %02x:%02x:%02x:%02x:%02x:%02x\n",
  //   //     ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]
  //   //   );
    
  //   if( !same_ether(ether_src, hwaddr) ) {
  //     // only consider ARP WHO_HAS
  //     // and ignore the adress if it is our target
  //     DEBUG("ip: %s, target: %s ? %d\n", inet_ntoa( *((struct in_addr *) &ip) ), target_address, strcmp( inet_ntoa( *((struct in_addr *) &ip) ), target_address) );
  //     if( (ntohs(harp->ar_op) == ARPOP_REQUEST) && strcmp( inet_ntoa( *((struct in_addr *) &ip) ), target_address) )  {
  //       memcpy(&ip, (char*)harp + LIBNET_ARP_H + (harp->ar_hln * 2) + harp->ar_pln, 4);
      
  //       INFO("taking over ip %s.\n", inet_ntoa( *((struct in_addr *) &ip)) );
  //       set_interface_addr(ifname, (struct in_addr *) &ip);
  //     }
  //   }
  // }
  
}

static mrb_value pcap_stop(mrb_state *mrb, mrb_value self)
{
  // pcap_breakloop
  return mrb_nil_value();
}

static mrb_value pcap_capture(mrb_state *mrb, mrb_value self)
{
  const char *filter;
  struct bpf_program bpf;
  struct state *st = (struct state *) DATA_PTR(self);
  struct cb_args args;
  
  mrb_get_args(mrb, "z&", &filter, &args.cb);
  args.mrb = mrb;
  
  /* compile pcap filter */
  if( pcap_compile(st->pcap, &bpf, filter, 0, 0) == -1 ) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pcap_compile(): %S\n", mrb_str_new_cstr(mrb, pcap_geterr(st->pcap)));
    goto ret;
  }
  
  if( pcap_setfilter(st->pcap, &bpf) == -1 ) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pcap_setfilter(): %S\n", mrb_str_new_cstr(mrb, pcap_geterr(st->pcap)));
  }
  
  if( pcap_loop(st->pcap, 0, pcap_packet_handler, (u_char *)&args) == -1 ){
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pcap_loop(): %S\n", mrb_str_new_cstr(mrb, pcap_geterr(st->pcap)));
  }


ret:
  return mrb_nil_value();
}


void mrb_mruby_pcap_gem_init(mrb_state *mrb)
{
  struct RClass *class = mrb_define_class(mrb, "PcapSniffer", NULL);
  
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_define_method(mrb, class, "initialize", pcap_initialize, ARGS_REQ(1));
  mrb_define_method(mrb, class, "capture", pcap_capture, ARGS_REQ(1));
  mrb_define_method(mrb, class, "stop", pcap_stop, ARGS_NONE());
      
  mrb_gc_arena_restore(mrb, ai);

}

void mrb_mruby_pcap_gem_final(mrb_state* mrb)
{
  
}
