#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>


std::vector<uint8_t> keya ;
std::vector<uint8_t> keye ;
uint32_t *src = (uint32_t *)malloc(4096 * sizeof(uint32_t));
uint32_t *dst = (uint32_t *)malloc(4096 * sizeof(uint32_t));
uint32_t spi;
uint8_t auth;
uint8_t enc;

void sa_print(struct sadb_ext *ext){
  printf("sa ext: \n");
  struct sadb_sa *sa = (struct sadb_sa*)ext;
  if(sa->sadb_sa_exttype==SADB_EXT_SA){
    uint32_t spi = ntohl(sa->sadb_sa_spi);
	printf("spi: 0x%x\n",spi); 
	auth = sa->sadb_sa_auth;
	enc = sa->sadb_sa_encrypt;
	printf("auth: "); 
	switch(auth){
	case  SADB_AALG_NONE:
			printf("SADB_AALG_NONE\n"); break;
    case  SADB_AALG_MD5HMAC:
			printf("SADB_AALG_MD5HMAC\n"); break;
    case  SADB_AALG_SHA1HMAC:
	case  SADB_AALG_MAX:
			printf("SADB_AALG_SHA1HMAC\n"); break;
	default:	printf(" [unknown auth %d]\n", auth);
	}
	printf("enc: ");
	switch(enc){
	case  SADB_EALG_NONE:
			printf("SADB_EALG_NONE\n"); break;
    case  SADB_EALG_DESCBC:
			printf("SADB_EALG_DESCBC\n"); break;
	case  SADB_EALG_3DESCBC:
			printf("SADB_EALG_3DESCBC\n"); break;
    case  SADB_EALG_NULL:
	case  SADB_EALG_MAX:
			printf("SADB_EALG_NULL\n"); break;
	default:	printf(" [unknown enc %d]\n", enc);
	}
  }
};

void lifetime_print(struct sadb_ext *ext){
  printf("lifetime ext: \n");
};

void address_print(struct sadb_ext *ext){
  printf("address ext: ");
  struct sadb_address *sadbaddr = (struct sadb_address*)ext;
  if(sadbaddr->sadb_address_exttype==SADB_EXT_ADDRESS_SRC){
    printf("addr type: src\n");
	memcpy(src, (char *)sadbaddr + sizeof(struct sadb_address)+4, (sadbaddr->sadb_address_len*8-sizeof(struct sadb_address))*8);
	std::cout<<"src: "<<ipToString(*src)<<"/"<<sadbaddr->sadb_address_prefixlen<<std::endl;
  }else if(sadbaddr->sadb_address_exttype==SADB_EXT_ADDRESS_DST){
	printf("addr type: dst\n");
	memcpy(dst, (char *)sadbaddr + sizeof(struct sadb_address)+4, (sadbaddr->sadb_address_len*8-sizeof(struct sadb_address))*8);
	std::cout<<"dst: "<<ipToString(*dst)<<"/"<<sadbaddr->sadb_address_prefixlen<<std::endl;
  }
};

void key_print(struct sadb_ext *ext){
  unsigned char *p;
	int bits, tmp = 0;
  printf("key ext: ");
  struct sadb_key *sadbkey = (struct sadb_key*)ext;
  if(sadbkey->sadb_key_exttype==SADB_EXT_KEY_AUTH){
    printf("key enc: Auth\n");
	unsigned char *p = (unsigned char *)(sadbkey + 1);
	int bits = sadbkey->sadb_key_bits;
	keya.clear();
	std::cout << "Key len:"<<sadbkey->sadb_key_bits<<"(bits) 0x";
	for (; bits > 0; p++, bits -= 8){
	std::cout << std::hex << (int)*p << std::dec;
	keya.push_back(*p);
	}std::cout << std::endl;
  }else if(sadbkey->sadb_key_exttype==SADB_EXT_KEY_ENCRYPT){
	unsigned char *p = (unsigned char *)(sadbkey + 1);
	int bits = sadbkey->sadb_key_bits;
	keye.clear();
	std::cout << "Key len:"<<sadbkey->sadb_key_bits<<"(bits) 0x";
	for (; bits > 0; p++, bits -= 8){
	std::cout << std::hex << (int)*p << std::dec;
	keye.push_back(*p);
	}std::cout << std::endl;
  }

};

void supported_print(struct sadb_ext *ext){
  printf("supported ext: \n");
};

const char * get_sadb_msg_type(int type)
{
	static char buf[100];
	switch (type) {
	case SADB_RESERVED:	return "Reserved";
	case SADB_GETSPI:	return "Get SPI";
	case SADB_UPDATE:	return "Update";
	case SADB_ADD:		return "Add";
	case SADB_DELETE:	return "Delete";
	case SADB_GET:		return "Get";
	case SADB_ACQUIRE:	return "Acquire";
	case SADB_REGISTER:	return "Register";
	case SADB_EXPIRE:	return "Expire";
	case SADB_FLUSH:	return "Flush";
	case SADB_DUMP:		return "Dump";
	default:			sprintf(buf, "[Unknown type %d]", type);
						return buf;
	}
}

const char * get_sadb_satype(int type)
{
	static char buf[100];
	switch (type) {
	case SADB_SATYPE_UNSPEC:	return "Unspecified";
	case SADB_SATYPE_AH:		return "IPsec AH";
	case SADB_SATYPE_ESP:		return "IPsec ESP";
	case SADB_SATYPE_RSVP:		return "RSVP";
	case SADB_SATYPE_OSPFV2:	return "OSPFv2";
	case SADB_SATYPE_RIPV2:		return "RIPv2";
	case SADB_SATYPE_MIP:		return "Mobile IP";
	default:					sprintf(buf, "[Unknown satype %d]", type);
								return buf;
	}
}


void print_sadb_msg(struct sadb_msg *msg, int msglen)
{
	struct sadb_ext *ext;

	if (msglen != msg->sadb_msg_len * 8) {
		printf("SADB Message length (%d) doesn't match msglen (%d)\n",
			msg->sadb_msg_len * 8, msglen);
		return;
	}
	if (msg->sadb_msg_version != PF_KEY_V2) {
		printf("SADB Message version not PF_KEY_V2\n");
		return;
	}
	printf("SADB Message %s, len %d, errno %d, satype %s, seq %d, pid %d\n",
		get_sadb_msg_type(msg->sadb_msg_type), msg->sadb_msg_len * 8, msg->sadb_msg_errno,
		get_sadb_satype(msg->sadb_msg_satype), msg->sadb_msg_seq,
		msg->sadb_msg_pid);
	if (msg->sadb_msg_errno != 0)
		printf(" errno %s\n", strerror(msg->sadb_msg_errno));
	if (msglen == sizeof(struct sadb_msg))
		return;	/* no extensions */
	msglen -= sizeof(struct sadb_msg);
	ext = (struct sadb_ext *)(msg + 1);
  	
	while (msglen > 0) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_RESERVED:	printf(" Reserved Extension\n"); break;
		case SADB_EXT_SA:	sa_print(ext); break;
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
				  lifetime_print(ext); break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
					address_print(ext); break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
					key_print(ext); break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
					printf(" [identity...]\n"); break;
		case SADB_EXT_SENSITIVITY:
					printf(" [sensitivity...]\n"); break;
		case SADB_EXT_PROPOSAL:
					printf(" [proposal...]\n"); break;
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
					supported_print(ext); break;
		case SADB_EXT_SPIRANGE:
					printf(" [spirange...]\n"); break;
		default:	printf(" [unknown extension %d]\n", ext->sadb_ext_type);
		}
		msglen -= ext->sadb_ext_len << 3;
		ext = (struct sadb_ext*)((char *)ext + (ext->sadb_ext_len << 3));
	}
}


std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_UNSPEC;
  msg.sadb_msg_len = sizeof(msg) / 8;
  msg.sadb_msg_pid = getpid();
  
  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (s == -1) {
        perror("Socket creation error");
        exit(1);
  }
  print_sadb_msg(&msg, sizeof(msg));
  int re = write(s, &msg, sizeof(msg));
  if (re == -1) {
        perror("send error: ");
        exit(1);
  }
  printf("\nMessages returned:\n");
  int size = 0;

  char buf[4096];
  int goteof = 0;
  struct sadb_msg *msgp;
  while (goteof == 0) {
    int msglen;
	// /* Read and print SADB_DUMP replies until done 
	msglen = read(s, &buf, sizeof(buf));
	msgp = (struct sadb_msg *)&buf;
	print_sadb_msg(msgp, msglen);
	if (msgp->sadb_msg_seq == 0) {
		goteof = 1;
	}
	size += sizeof(*msgp);
  }
  

	// TODO: Set size to number of bytes in response message
	//   int size = sizeof(sadb_msg);
	std::span<uint8_t> auth_key = keya;
	//   std::cout<<auth_key.data()<<" /// "<<auth_key.size();
	std::span<uint8_t> enc_key = keye;
	// Has SADB entry
	if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    config.spi = ntohl(spi);
    config.aalg = std::make_unique<ESP_AALG>(auth, auth_key);
    // Have enc algorithm:
    // config.ealg = std::make_unique<ESP_AALG>(SADB_AALG_SHA1HMAC, _key); ???
    // No enc algorithm:
    config.ealg = std::make_unique<ESP_EALG>(enc, enc_key);
    // Source address:
    config.local = ipToString(*src);
    // Destination address:
    config.remote = ipToString(*dst);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
