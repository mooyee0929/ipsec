#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>

#include <arpa/inet.h>
extern bool running;



Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
  
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  if(ipToString(hdr.saddr) == config.remote.c_str()){
    printf("iphdr.version: %d ",hdr.version);
    printf("iphdr.hdrlen: %d ",hdr.ihl*4);
    std::cout<<"iphdr.source: "<<ipToString(hdr.saddr)<<" ";
    std::cout<<"iphdr.dest: "<<ipToString(hdr.daddr)<<" ";

    state.ipId = ntohs(hdr.id);

    int headerLength = hdr.ihl*4;
    state.recvPacket = true;
    // Track current IP id
    state.ipId = hdr.id;
    // Call dissectESP(payload) if next protocol is ESP
    // std::cout<<"headerlength: "<<headerLength<<" ";
    auto payload = buffer.last(buffer.size() - headerLength);
    //ESP : 50
    if(hdr.protocol == IPPROTO_ESP){
      printf("ESP , ");
      dissectESP(payload);
      
    }
  }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    std::cout<<" non-empty ";
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  state.espseq = ntohl(hdr.seq);
  // Call dissectTCP(payload) if next protocol is TCP
  //TCP: 6, ICMP: 1, UDP: 17
  if(buffer.front() == 6 || buffer.back() == 6){
    auto&& iphdr_reduce = *reinterpret_cast<iphdr*>(buffer.data());
    uint8_t headerLength = iphdr_reduce.ihl*4;
    auto payload = buffer.last(buffer.size() - headerLength);
    printf("TCP , ");
    dissectTCP(payload);
  }
  
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq);
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 255;
  hdr.id = htons(state.ipId);
  hdr.protocol = IPPROTO_ESP;
  // 0|df|mf 13
  hdr.frag_off = 0;
  hdr.frag_off |= IP_MF;
  hdr.frag_off &= ~IP_DF;
  hdr.saddr = inet_addr(config.local.c_str());
  hdr.daddr = inet_addr(config.remote.c_str());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));
  
  printf("encap ip, ");

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  iphdr* iphedr = reinterpret_cast<iphdr*>(&hdr);
  uint32_t sum = 0;
  auto buf = reinterpret_cast<const uint16_t*>(iphedr);
  for (int i = 0; i < iphedr->ihl * 2; i++) {
    sum += buf[i];
  }
  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xFFFF);
  }

  hdr.check = htons(~sum);
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq);

  printf("encap esp, ");

  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = nextBuffer.size() - 2;
  payloadLength += padSize;
  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = 6;
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(std::span{buffer.data(), payloadLength});
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  if(state.sendAck){
    hdr.ack = 1;
  }else{
    hdr.ack = 0;
  }
  hdr.doff = sizeof(tcphdr);
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  hdr.ack_seq = state.tcpackseq+1;
  hdr.seq = htonl(state.tcpseq);
  hdr.window = htons(65535);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  state.tcpseq += payloadLength;
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  struct PseudoIPv4Header ipv4;
  ipv4.src = inet_addr(config.local.c_str());
  ipv4.dst = inet_addr(config.remote.c_str());
  ipv4.zero = 0;
  ipv4.protocol = 6;
  ipv4.length = payloadLength;
  printf("encap tcp, ");
  hdr.check = htons(tcpchecksum(ipv4));
  return payloadLength;
}


uint16_t tcpchecksum(struct PseudoIPv4Header &ipv4) {
    int nleft = sizeof(struct PseudoIPv4Header);
    int sum = 0;
    uint16_t answer = 0;
    sum += ipv4.src;
    sum += ipv4.dst;
    sum += ipv4.protocol;
    sum += ipv4.length;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}
