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
#include <numeric>
extern bool running;


// #define DUMP_PACKET 1
// #define SHOW_ENCAPSULATE 1

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
  int headerLength = hdr.ihl*4;
  if(ipToString(hdr.saddr) == config.remote.c_str()){
    state.recvPacket = true;
    std::map<int, std::string> protocol_names = {
      {IPPROTO_IP, "IP"},   {IPPROTO_ICMP, "ICMP"}, {IPPROTO_TCP, "TCP"},
      {IPPROTO_UDP, "UDP"}, {IPPROTO_IPV6, "IPv6"}, {IPPROTO_ESP, "ESP"},
    };

#if DUMP_PACKET
    // Dump IP packet
    std::cout << "-------------dissectIPv4--------------\n";
    std::cout << "Source IP: " << ipToString(hdr.saddr) << "\n";
    std::cout << "Destination IP: " << ipToString(hdr.daddr) << "\n";
    std::cout << "Protocol: " << protocol_names[hdr.protocol] << "\n";
    std::cout << "Payload Length: " << ntohs(hdr.tot_len) - headerLength << "\n";
#endif
  }else{
    state.recvPacket = false;
    // Track current IP id
    state.ipId = hdr.id;
  }

  // Call dissectESP(payload) if next protocol is ESP
  auto payload = buffer.last(buffer.size() - headerLength);
  //ESP : 50
  if(hdr.protocol == IPPROTO_ESP){
    dissectESP(payload);
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
  if (state.recvPacket == false) {
    state.espseq = ntohl(hdr.seq);
    config.spi = ntohl(hdr.spi);
  }
  // Call dissectTCP(payload) if next protocol is TCP
  //TCP: 6, ICMP: 1, UDP: 17
  struct ESPTrailer esptrail;
  // printf("proro : %d",buffer.back());
  esptrail.next = buffer.back();
  buffer = buffer.first(buffer.size() - 1);
  esptrail.padlen = buffer.back();
  auto payload = buffer.first(buffer.size()  - esptrail.padlen -1);

#if DUMP_PACKET
  std::cout << "-------------dissectESP--------------\n";
  std::cout << "SPI: " << ntohl(hdr.spi) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Padding Length: " << esptrail.padlen << "\n";
  std::cout << "Next Header: " << esptrail.next << "\n";
  std::cout << "Payload Length: " << payload.size() << "\n";
#endif

  if(esptrail.next == IPPROTO_TCP){
    dissectTCP(payload);
  }
  
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);


#if DUMP_PACKET
  std::cout << "-------------dissectTCP--------------\n";
  std::cout << "Source Port: " << ntohs(hdr.source) << "\n";
  std::cout << "Destination Port: " << ntohs(hdr.dest) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Acknowledge Number: " << ntohl(hdr.ack_seq) << "\n";
  std::cout << "Data Offset: " << hdr.doff << "\n";
  std::cout << "Window: " << ntohs(hdr.window) << "\n";
  std::cout << "Checksum: " << ntohs(hdr.check) << "\n";
  std::cout << "Urgent Pointer: " << ntohs(hdr.urg_ptr) << "\n";
  std::cout << "Payload Length: " << payload.size() << "\n";
  std::cout << "-------------------------------------\n";
#endif

  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq);
  state.tcpackseq = ntohl(hdr.ack_seq);
  
  
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  state.tcpseq += payload.size();
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
    state.espseq++;
    // state.ipId++;
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
  hdr.ttl = 64;
  hdr.id = htons(ntohs(state.ipId) + 1);
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000);
  hdr.saddr = inet_addr(config.local.c_str());
  hdr.daddr = inet_addr(config.remote.c_str());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));


  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  hdr.check = ipchecksum(hdr);

#if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateIPv4--------------\n";
  std::cout << "Source IP: " << ipToString(hdr.saddr) << "\n";
  std::cout << "Destination IP: " << ipToString(hdr.daddr) << "\n";
  std::cout << "Protocol: " << hdr.protocol << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
  std::cout << "-------------------------------------\n";
#endif

  return payloadLength;
}

uint16_t ipchecksum(struct iphdr iphdr) {
  struct iphdr* temp_ptr = &iphdr;
  uint16_t* iphdr_ptr = (uint16_t*)temp_ptr;
  size_t hdr_len = iphdr.ihl * 4;
  uint32_t sum = 0;

  // Calculate the checksum for the IP header
  while (hdr_len > 1) {
    sum += *iphdr_ptr++;
    hdr_len -= 2;
  }

  // Deal with odd header len
  if (hdr_len) {
    sum += (*iphdr_ptr) & htons(0xFF00);
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq+1);

  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = (4 - ((payloadLength + sizeof(ESPTrailer)) % 4)) % 4;
  std::iota(endBuffer.begin(), endBuffer.begin() + padSize, 1);

  payloadLength += padSize;
  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = IPPROTO_TCP;
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
    auto result = config.aalg->hash(std::span{buffer.data(), (size_t)payloadLength});
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }


  #if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateESP--------------\n";
  std::cout << "SPI: " << ntohl(hdr.spi) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Padding Length: " << (int)endBuffer[padSize] << "\n";
  std::cout << "Next Header: " << (int)endBuffer[padSize + 1] << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
#endif

  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()){
    hdr.psh = 1;
  }
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  hdr.ack_seq = htonl(state.tcpseq);
  hdr.seq = htonl(state.tcpackseq);
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  state.tcpackseq += payload.size();
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  struct PseudoIPv4Header ipv4;
  ipv4.src = inet_addr(config.local.c_str());
  ipv4.dst = inet_addr(config.remote.c_str());
  ipv4.zero = 0;
  ipv4.protocol = IPPROTO_TCP;
  ipv4.length = payloadLength;
  hdr.check = tcpchecksum(ipv4, hdr, payload); //不用htons?

#if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateTCP--------------\n";
  std::cout << "Source Port: " << ntohs(hdr.source) << "\n";
  std::cout << "Destination Port: " << ntohs(hdr.dest) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Acknowledge Number: " << ntohl(hdr.ack_seq) << "\n";
  std::cout << "Data Offset: " << hdr.doff << "\n";
  std::cout << "Window: " << ntohs(hdr.window) << "\n";
  std::cout << "Checksum: " << ntohs(hdr.check) << "\n";
  std::cout << "Urgent Pointer: " << ntohs(hdr.urg_ptr) << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
  std::cout << "Payload Content: " << payload << "\n";

#endif

  return payloadLength;
}


uint16_t tcpchecksum(struct PseudoIPv4Header &ipv4, struct tcphdr tcphdr, const std::string& payload) {
    int sum = 0;
    uint16_t answer = 0;
    // Calculate the TCP pseudo-header checksum
    sum += (ipv4.src >> 16) & 0xFFFF;
    sum += ipv4.src & 0xFFFF;
    sum += (ipv4.dst >> 16) & 0xFFFF;
    sum += ipv4.dst & 0xFFFF;
    sum += htons(ipv4.protocol);
    uint16_t tcphdr_len = tcphdr.th_off * 4;
    uint16_t tcp_len = tcphdr_len + payload.size();
    sum += htons(tcp_len);
    // Create a buffer to store the TCP header and payload
    // Then calculate them together in the buffer
    uint8_t* buf = (uint8_t*)malloc((tcphdr_len + payload.size()) * sizeof(uint8_t));
    memcpy(buf, &tcphdr, tcphdr_len);
    memcpy(buf + tcphdr_len, payload.c_str(), payload.size());
    uint16_t* pl_ptr = (uint16_t*)buf;
    while (tcp_len > 1) {
      sum += *pl_ptr++;
      tcp_len -= 2;
    }

     // Deal with odd header len
    if (tcp_len) {
      sum += (*pl_ptr) & htons(0xFF00);
    }

    while (sum >> 16) {
      sum = (sum >> 16) + (sum & 0xFFFF);
    }
    answer = ~sum;
    return (answer);
}
