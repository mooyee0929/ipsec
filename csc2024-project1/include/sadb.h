#pragma once
#include <linux/pfkeyv2.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include "encoder.h"
#include "util.h"

struct ESPConfig {
  // For ESP Header
  uint32_t spi;
  // ESP encryption
  std::unique_ptr<ESP_EALG> ealg;
  // ESP authentication
  std::unique_ptr<ESP_AALG> aalg;
  // Remote IP address
  std::string remote;
  // Local IP address
  std::string local;
  friend std::ostream& operator<<(std::ostream& os, const ESPConfig& config);
};

std::optional<ESPConfig> getConfigFromSADB();
void print_sadb_msg(struct sadb_msg *msg, int msglen);
const char * get_sadb_msg_type(int type);
const char * get_sadb_satype(int type);

void sa_print(struct sadb_ext *ext);
void lifetime_print(struct sadb_ext *ext);
void address_print(struct sadb_ext *ext);
void key_print(struct sadb_ext *ext);
void supported_print(struct sadb_ext *ext);