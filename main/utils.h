#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <sys/param.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <esp_intr_alloc.h>
#include <esp_spiffs.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <mbedtls/md5.h> // MD5 library
#include <mbedtls/sha1.h> // SHA1 library
#include <esp_timer.h> // Timer for precise timestamp

#include "lwip/apps/sntp.h"


unsigned char* get_md5(char *password, char *token);

unsigned char* get_sha1(const unsigned char* str);

void base64_encode(char *input, size_t len, char *output);

char* get_xencode(char* msg, char* key, size_t* out_len);

void sync_time();

void set_system_time();

long long get_timestamp();

void hmac_md51(unsigned char* out, unsigned char* data, int dlen, unsigned char* key, int klen);