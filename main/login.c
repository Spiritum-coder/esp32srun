#include "login.h"

static char token[70]; 
static char ip_address[16] = "0.0.0.0";
static long long current_time_ms;
static bool get_response = false;
static esp_http_client_handle_t client1;

void get_ip_as_string() {
    // 获取默认网络接口
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) {
        ESP_LOGE("IP_CHECK", "Failed to get netif handle");
        strncpy(ip_address, "No network", sizeof(ip_address) - 1);
        ip_address[sizeof(ip_address) - 1] = '\0';
        return;
    }

    // 获取 IP 信息
    esp_netif_ip_info_t ip_info;
    esp_err_t ret = esp_netif_get_ip_info(netif, &ip_info);
    if (ret != ESP_OK) {
        ESP_LOGE("IP_CHECK", "Failed to get IP info: %s", esp_err_to_name(ret));
        strncpy(ip_address, "IP Error", sizeof(ip_address) - 1);
        ip_address[sizeof(ip_address) - 1] = '\0';
        return;
    }

    // 转换 IP 地址为字符串
    snprintf(ip_address, sizeof(ip_address), IPSTR, IP2STR(&ip_info.ip));
}

char* get_callback(){
    static char callback_str[64];  // 分配静态内存来存储最终的回调字符

    char random_sequence[15 + 1];
    // 随机生成序列长度，范围从1到MAX_LENGTH
    for (int i = 0; i < 15; i++) {
        // 生成0 - 9的随机数字并添加到序列中
        random_sequence[i] = rand() % 10 + '0';
    }
    random_sequence[15] = '\0';

    // 生成回调字符串
    snprintf(callback_str, sizeof(callback_str), "jQuery1124%s_%lld", random_sequence, current_time_ms);
    
    return callback_str;
}

void get_time(){
    current_time_ms = get_timestamp();
}


esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGI("HTTP_EVENT", "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_DATA:
            if (evt->data_len > 0) {
                ESP_LOGI("HTTP_EVENT", "Response data: %.*s", evt->data_len, (char*)evt->data);
                const char *challenge_start = strstr((char*)evt->data, "\"challenge\":\"");
                if (challenge_start) {
                    // 找到 challenge 字段后，跳过字段名部分，指向 challenge 值的开始位置
                    challenge_start += strlen("\"challenge\":\"");

                    // 找到结束的引号
                    const char *challenge_end = strchr(challenge_start, '\"');
                    if (challenge_end) {
                        // 计算 challenge 值的长度
                        size_t challenge_len = challenge_end - challenge_start;

                        // 确保 buffer 足够大
                        if (challenge_len < sizeof(token)) {
                            // 提取 challenge 字段的值到 token 数组
                            memcpy(token, challenge_start, challenge_len);
                            token[challenge_len] = '\0';  // 确保 null 结尾
                            ESP_LOGI("HTTP_EVENT", "Challenge token: %s", token);
                        } else {
                            ESP_LOGW("HTTP_EVENT", "Challenge token is too long");
                        }
                    }
                }
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

esp_err_t _http_event_handler1(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGE("HTTP_EVENT", "HTTP_EVENT_ERROR");
            break;

        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI("HTTP_EVENT", "HTTP_EVENT_HEADER_SENT");
            break;

        case HTTP_EVENT_ON_DATA:
            ESP_LOGI("HTTP_EVENT", "HTTP_EVENT_ON_DATA");
            // 处理响应体数据
            if (evt->data && evt->data_len > 0) {
                // 打印响应体数据
                ESP_LOGI("HTTP_EVENT", "Received %d bytes of data", evt->data_len);
                ESP_LOGI("HTTP_EVENT", "Response body:%.*s", evt->data_len, (char*)evt->data);
            }
            get_response = true;
            break;

        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI("HTTP_EVENT", "HTTP_EVENT_ON_FINISH, Response completed");
            break;

        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI("HTTP_EVENT", "HTTP_EVENT_DISCONNECTED");
            break;

        default:
            break;
    }
    return ESP_OK;
}

void get_token(const char *username) {
    esp_http_client_config_t config = {
        .url = "http://192.168.167.115/cgi-bin/get_challenge",
        .event_handler = _http_event_handler,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_header(client, "User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"); // 设置 User-Agent
    esp_http_client_set_header(client, "Referer", "http://192.168.167.115/"); 
    esp_http_client_set_header(client, "Host", "nap.cug.edu.cn"); 

    char *params = (char *)malloc(256);

    sprintf(params, "?callback=%s&username=%s&ip=%s&_=%lld", get_callback(), username, ip_address, current_time_ms);
    
    ESP_LOGI("Get Token", "params: %s", params);

    char *full_url = (char *)malloc(512); // 存储完整的 URL
    sprintf(full_url, "http://192.168.167.115/cgi-bin/get_challenge%s", params);
    ESP_LOGI("HTTP", "URL: %s", full_url);

    esp_http_client_set_url(client, full_url);
    ESP_ERROR_CHECK(esp_http_client_perform(client));

    free(params);
    free(full_url);

    while(strlen(token) <= 0){
        //等待获取token
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
    esp_http_client_cleanup(client);

    ESP_LOGI("HTTP_EVENT", "Client clean up end");

}



char* get_info(const char *username, const char *password) {
    char *ac_id = "1";
    char *enc = "srun_bx1";

    // 计算拼接后字符串大致长度（粗略估算，可能需要根据实际调整）
    int total_length = strlen(username) + strlen(password) + strlen(ip_address) + strlen(ac_id) + strlen(enc) + 100;  // 额外预留一些字符用于分隔等
    char* result = (char*)malloc(total_length * sizeof(char));
    if (result == NULL) {
        return NULL;  // 内存分配失败
    }
    snprintf(result, total_length-1, "{\"username\":\"%s\",\"password\":\"%s\",\"ip\":\"%s\",\"acid\":\"%s\",\"enc_ver\":\"%s\"}", username, password, ip_address, ac_id, enc);

    ESP_LOGI("Encode", "info:%s", result);

    return result;
}


char* get_chksum(char *username, char* hmd5, char* info){
    char* ac_id = "1";
    char* n = "200";
    char* type = "1";


    int len = strlen(username) + strlen(hmd5) + strlen(info) +
          strlen(ac_id) + strlen(ip_address) + strlen(n) + strlen(type) +
          7 * strlen(token);

    ESP_LOGI("Encode", "Chksum Len%d", len);

    char* chkstr = (char*)malloc((len + 1) * sizeof(char));

    if (!chkstr) {
        ESP_LOGE("Encode", "Memory allocation failed");
        return NULL;
    }

    memset(chkstr, 0, len + 1);

    // 拼接字符串
    snprintf(chkstr, len + 1, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            token, username, token, hmd5, token, ac_id,
            token, ip_address, token, n, token, type, token, info);
    
    // ESP_LOGI("Encode", "chkstr %s", chkstr);


    char* chkstr_sha1 = (char*)get_sha1((unsigned char*)chkstr);
    free(chkstr);
	return chkstr_sha1;
}

char* urlencode(const char *str) {
    // 计算需要的缓冲区大小
    size_t len = strlen(str);
    size_t result_len = len * 3 + 1;  // 每个字符最多需要3个字节（%xx形式）

    char *encoded = malloc(result_len);
    if (!encoded) {
        return NULL;
    }

    size_t i = 0, j = 0;
    while (i < len) {
        unsigned char c = (unsigned char)str[i];

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || (c == '-') || (c == '_') || (c == '.') || (c == '~')) {
            encoded[j++] = c;  // 如果是合法字符，直接复制
        } else {
            // 否则，转为 %xx 形式
            sprintf(&encoded[j], "%%%.2X", c);
            j += 3;
        }

        i++;
    }

    encoded[j] = '\0';
    return encoded;
}



void login(char *username, char *password) {


    get_ip_as_string();
    get_time();
    get_token(username);


    size_t xencodeLen;
    //登录流程
    char* xencode = get_xencode(get_info(username, password), token, &xencodeLen);
    ESP_LOGI("Encode_EVENT", "Xencode End");
    char* info = (char *)malloc(((xencodeLen+1) * 4 / 3 + 10) * sizeof(char));
    ESP_LOGW("Encode_EVENT", "xencode len %d", (xencodeLen));
    ESP_LOGW("Encode_EVENT", "Info len %d", ((xencodeLen+1) * 4 / 3 + 10));
    base64_encode(xencode, xencodeLen, info);
    free(xencode);
    ESP_LOGI("Encode_EVENT", "Base64 End");

    int newLen = strlen(info) + 8;  // 7是"{SRBX1}"的长度
    char* newInfo = (char *)malloc(newLen * sizeof(char));
    strcpy(newInfo, "{SRBX1}");
    strcat(newInfo, info);
    free(info);
    ESP_LOGI("Encode_EVENT", "Info got");
    char* hmd5 = (char*)get_md5(password, token);
    ESP_LOGW("Encode_EVENT", "HMD5 %s", hmd5);

    char* chksum = get_chksum(username, hmd5, newInfo);
    ESP_LOGI("Encode_EVENT", "Chksum %s", chksum);

    char* newPassword = (char *)malloc((strlen(hmd5) + 10) * sizeof(char));
    snprintf(newPassword, (strlen(hmd5) + 10), "{MD5}%s", hmd5);
    free(hmd5);
    ESP_LOGI("Encode_EVENT", "Hmd5 got");

    get_time();
    esp_http_client_config_t config = {
      .url = "http://192.168.167.115/cgi-bin/srun_portal",
      .event_handler = _http_event_handler1, 
      .buffer_size = 2048,
      .buffer_size_tx = 2048,
    };
    client1 = esp_http_client_init(&config);

    esp_http_client_set_header(client1, "User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"); // 设置 User-Agent
    esp_http_client_set_header(client1, "Referer", "http://192.168.167.115/"); 
    esp_http_client_set_header(client1, "Host", "nap.cug.edu.cn"); 

    char* encode_password = urlencode(newPassword);
    char* encode_ip = urlencode(ip_address);
    char* encode_chksum = urlencode(chksum);
    char* encode_info = urlencode(newInfo);

    free(newInfo);
    free(chksum);
    free(newPassword);



    char *params1 = (char *)malloc(600);
    sprintf(params1, "?callback=%s&action=login&username=%s&password=%s&ac_id=1&ip=%s&chksum=%s&info=%s&n=200&type=1&os=windows+10&name=Windows&double_stack=0&_=%lld", 
    get_callback(), 
    username,
    encode_password,
    encode_ip, 
    encode_chksum, 
    encode_info,
    current_time_ms);



    char *full_url = (char *)malloc(700); // 存储完整的 URL
    sprintf(full_url, "http://192.168.167.115/cgi-bin/srun_portal%s", params1);
    ESP_LOGI("HTTP", "URL: %s", full_url);

    esp_http_client_set_url(client1, full_url);

    esp_err_t err = esp_http_client_perform(client1);
    if (err!= ESP_OK) {
        ESP_LOGE("HTTP", "HTTP client perform failed with error: %d", err);
        esp_http_client_cleanup(client1);
        return;
    }
    esp_http_client_close(client1);
    esp_http_client_cleanup(client1);
}