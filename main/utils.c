#include "utils.h"

#define LENGTH_MD5_RESULT 16
#define LENGTH_BLOCK 64


static const char base64Alpha[] = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";



void charArrayToHexString(const char *input, size_t len, char *output) {
    int i;
    // 遍历输入字符数组，将每个字符转换为对应的两位十六进制表示
    for (i = 0; i < len; i++) {
        sprintf(output + i * 2, "%02x", (unsigned char)input[i]);
    }
    // 终止符
    output[i * 2] = '\0';
}


void hmac_md51(unsigned char* out, unsigned char* data, int dlen, unsigned char* key, int klen)
{
	int i;
	ESP_LOGI("Encode", "Start MD5");
	

	// 使用 malloc 为数组动态分配内存
	unsigned char *tempString16 = (unsigned char *)malloc(LENGTH_MD5_RESULT * sizeof(unsigned char));
	unsigned char *OneEnding = (unsigned char *)malloc(LENGTH_BLOCK * sizeof(unsigned char));
	unsigned char *TwoEnding = (unsigned char *)malloc(LENGTH_BLOCK * sizeof(unsigned char));
	unsigned char *ThreeEnding = (unsigned char *)malloc((LENGTH_BLOCK + dlen) * sizeof(unsigned char));
	unsigned char *FourEnding = (unsigned char *)malloc(LENGTH_MD5_RESULT * sizeof(unsigned char));
	unsigned char *FiveEnding = (unsigned char *)malloc(LENGTH_BLOCK * sizeof(unsigned char));
	unsigned char *SixEnding = (unsigned char *)malloc((LENGTH_BLOCK + LENGTH_MD5_RESULT) * sizeof(unsigned char));
	
	unsigned char ipad;
	unsigned char opad;
	mbedtls_md5_context md5_ctx;
	
	ipad = 0x36;
	opad = 0x5c;
	
	
/*(1) 在密钥key后面添加0来创建一个长为B(64字节)的字符串(OneEnding)。如果key的长度klen大于64字节，则先进行md5运算，使其长度klen=16字节。 */
 
	for ( i = 0; i < LENGTH_BLOCK; i++)
	{
			OneEnding[i] = 0;
	}
 
	if ( klen > LENGTH_BLOCK)
	{
		mbedtls_md5_init(&md5_ctx);
		mbedtls_md5_starts(&md5_ctx);
		mbedtls_md5_update(&md5_ctx, key, strlen((char *)key));
		mbedtls_md5_finish(&md5_ctx, tempString16);
 
		for (i = 0; i < LENGTH_MD5_RESULT; i++)
			OneEnding[i] = tempString16[i];
	}	
	else
	{
	   for (i = 0; i < klen; i++)
			OneEnding[i] = key[i] ;
	}
	
	
/*(2) 将上一步生成的字符串(OneEnding)与ipad(0x36)做异或运算，形成结果字符串(TwoEnding)。*/
	for ( i = 0; i < LENGTH_BLOCK; i++)
	{
		TwoEnding[i] = OneEnding[i] ^ ipad; 
	}
/*(3) 将数据流data附加到第二步的结果字符串(TwoEnding)的末尾。*/
	for ( i = 0; i < LENGTH_BLOCK; i++ )
	{
		ThreeEnding[i] = TwoEnding[i];
	}
	for ( ; i < dlen + LENGTH_BLOCK; i++)
	{
		ThreeEnding[i] = data[i - LENGTH_BLOCK];
	}
/*(4) 做md5运算于第三步生成的数据流(ThreeEnding)。*/

	mbedtls_md5_init(&md5_ctx);
	mbedtls_md5_starts(&md5_ctx);
	mbedtls_md5_update(&md5_ctx, ThreeEnding, LENGTH_BLOCK + dlen);
	mbedtls_md5_finish(&md5_ctx, FourEnding);

	
/*(5) 将第一步生成的字符串(OneEnding)与opad(0x5c)做异或运算，形成结果字符串(FiveEnding)。*/
	for ( i = 0 ; i < LENGTH_BLOCK; i++ )
	{
			FiveEnding[i] = OneEnding[i] ^ opad;
	}
/*(6) 再将第四步的结果(FourEnding)附加到第五步的结果字符串(FiveEnding)的末尾。*/
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		SixEnding[i] = FiveEnding[i];
	}
	for ( ; i < (LENGTH_BLOCK + LENGTH_MD5_RESULT); i++)
	{
		SixEnding[i] = FourEnding[i - LENGTH_BLOCK];
	}
/*(7) 做md5运算于第六步生成的数据流(SixEnding)，输出最终结果(out)。*/
	mbedtls_md5_init(&md5_ctx);
	mbedtls_md5_starts(&md5_ctx);
	mbedtls_md5_update(&md5_ctx, SixEnding, LENGTH_BLOCK + LENGTH_MD5_RESULT);
	mbedtls_md5_finish(&md5_ctx, tempString16);

    charArrayToHexString((char*)tempString16, LENGTH_MD5_RESULT, (char*)out);

	free(tempString16);
	free(OneEnding);
	free(TwoEnding);
	free(ThreeEnding);
	free(FourEnding);
	free(FiveEnding);
	free(SixEnding);


}



void base64_encode(char *input, size_t len, char *output) {
    int pad = (int)len % 3;
    
    // If padding is needed, append '\0' to make it multiple of 3
    char *s = (char *)input;
    char* padded_input = NULL;
    if (pad) {
        padded_input = (char *)malloc(len + (3 - pad));
        if (padded_input == NULL) {
            ESP_LOGW("Encode_EVENT", "Malloc Failure");
            return;
        }
        memcpy(padded_input, input, len);
        memset(padded_input + len, '\0', (3 - pad));
        s = padded_input;
    }

    int j = 0;
    for (int i = 0; i < len ; i += 3) {
        uint32_t triplet = (unsigned char)s[i] << 16 | (unsigned char)s[i+1] << 8 | (unsigned char)s[i+2];
        output[j++] = base64Alpha[triplet >> 18];
        output[j++] = base64Alpha[(triplet >> 12) & 0x3F];
        output[j++] = base64Alpha[(triplet >> 6) & 0x3F];
        output[j++] = base64Alpha[triplet & 0x3F];
    }
    ESP_LOGW("Encode_EVENT", "output %d", j);

    // Adjust padding for Base64 encoding
    if (pad == 1) {
        output[j-1] = '=';
        output[j-2] = '=';
    } else if (pad == 2) {
        output[j-1] = '=';
    }

    // Null-terminate the string
    output[j] = '\0';
    if(padded_input != NULL){
        free(padded_input);
        padded_input = NULL;
    }

    ESP_LOGW("Heap status", " %d", heap_caps_check_integrity(MALLOC_CAP_INTERNAL, true));
}


unsigned char* get_md5(char *password, char *token) {

	unsigned char * out = (unsigned char *)malloc(33);
    ESP_LOGI("Encode", "HMD5ing");
    ESP_LOGI("Encode", "password %s", password);
    ESP_LOGI("Encode", "token %s", token);
	hmac_md51(out, (unsigned char *)password , strlen(password), (unsigned char *)token , strlen(token));
	ESP_LOGI("Encode", "HMD5 end");
    return out;
}


unsigned char* get_sha1(const unsigned char* str){
    mbedtls_sha1_context sha1_ctx;;

    unsigned char* decrypt = (unsigned char*)malloc(21);;

    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, str, strlen((char *)str));
    mbedtls_sha1_finish(&sha1_ctx, decrypt);
    decrypt[20] = '\0';

    unsigned char* ret = (unsigned char*)malloc(41);

    charArrayToHexString((char*)decrypt, 20, (char*)ret);
    return ret;
}



// xencode 实现

unsigned char ordat(const char* msg, size_t idx) {
    if (msg[idx] != '\0') {
        return (unsigned char)msg[idx];
    }
    return 0;
}

unsigned int* sencode(const char* msg, int key, size_t* len) {
    size_t l = strlen(msg);
    *len = (l / 4) + (l % 4 ? 1 : 0) + (key ? 1 : 0);
    unsigned int* pwd = (unsigned int*)malloc((*len) * sizeof(unsigned int));

    size_t idx = 0;
    for (size_t i = 0; i < l; i += 4) {
        unsigned int value = ordat(msg, i) |
                             (ordat(msg, i + 1) << 8) |
                             (ordat(msg, i + 2) << 16) |
                             (ordat(msg, i + 3) << 24);
        pwd[idx++] = value;
    }

    if (key) {
        pwd[idx] = (unsigned int)l;
    }

    return pwd;
}

void int_to_bytes(unsigned int value, char* result) {
    result[0] = (char)(value & 0xFF);          
    result[1] = (char)((value >> 8) & 0xFF);   
    result[2] = (char)((value >> 16) & 0xFF);  
    result[3] = (char)((value >> 24) & 0xFF);  
}

char* lencode(unsigned int* msg, size_t len, int key, size_t* out_len) {
    size_t l = len;
    size_t ll = (l - 1) << 2;  // (l - 1) * 4

    if (key) {
        unsigned int m = msg[l - 1];
        if (m < ll - 3 || m > ll) {
            return NULL;  // 如果 m 不在合理范围内，则返回 NULL
        }
        ll = m;  // 更新 ll
    }

    size_t total_len = l * 4;
    char* result = (char*)malloc(total_len + 1);
    if (result == NULL) {
        return NULL;
    }
    ESP_LOGW("Encode_EVENT", "lencode len %d", total_len);

    char temp[4];
    size_t idx = 0;
    for (size_t i = 0; i < l; i++) {
        int_to_bytes(msg[i], temp);
        memcpy(result + idx, temp, 4);
        idx += 4;
    }
    if (key) {
        result[ll] = '\0';
        *out_len = ll;
    } else {
        result[total_len] = '\0';
        *out_len = total_len;
    }

    return result;
}

char* get_xencode(char* msg, char* key, size_t* out_len) {
    size_t pwd_len, pwdk_len;
    unsigned int* pwd = sencode(msg, 1, &pwd_len);
    unsigned int* pwdk = sencode(key, 0, &pwdk_len);

    if (pwdk_len < 4) {
        unsigned int* new_pwdk = realloc(pwdk, 4 * sizeof(unsigned int));
        if (new_pwdk == NULL) {
            // 处理内存分配失败的情况，可能是返回错误或终止
            free(pwdk);
            return NULL;
        }
        pwdk = new_pwdk;
        for (int i = pwdk_len; i < 4; i++) {
            pwdk[i] = 0;
        }
    }

    size_t n = pwd_len - 1;
    unsigned int z = pwd[n];
    unsigned int y = pwd[0];
    unsigned int c = 0x86014019 | 0x183639A0;
    unsigned int m, e, p, q;
    q = (unsigned int)(6 + 52 / (n + 1));

    unsigned int d = 0;
    while (q > 0) {
        d = (d + c) & (0x8CE0D9BF | 0x731F2640);
        e = (d >> 2) & 3;
        p = 0;
        while (p < n) {
            y = pwd[p + 1];
            m = (z >> 5) ^ (y << 2);
            m = m + (((y >> 3) ^ (z << 4)) ^ (d ^ y));
            m = m + (pwdk[(p & 3) ^ e] ^ z);
            pwd[p] = pwd[p] + (m & (0xEFB8D130 | 0x10472ECF));
            z = pwd[p];
            p = p + 1;
        }
        y = pwd[0];
        m = (z >> 5) ^ (y << 2);
        m = m + (((y >> 3) ^ (z << 4)) ^ (d ^ y));
        m = m + (pwdk[(p & 3) ^ e] ^ z);
        pwd[n] = pwd[n] + (m & (0xBB390742 | 0x44C6F8BD));
        z = pwd[n];
        q = q - 1;
    }

    size_t len_out_len;
    char* encoded_msg = lencode(pwd, pwd_len, 0, &len_out_len);
    *out_len = len_out_len;
    free(pwd);
    free(pwdk);
    // 释放中间变量的空间
    free(msg);
    return encoded_msg;
}

static const char *TAG = "TimeSync";

void sync_time(){
    // 初始化 SNTP
    ESP_LOGI(TAG, "Initializing SNTP...");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org"); // 默认 NTP 服务器
    sntp_init();

    // 等待时间同步
    time_t now;
    struct tm timeinfo;
    int count = 0;
    while (timeinfo.tm_year < (2025 - 1900)) { // 检查年份是否合理
        ESP_LOGI(TAG, "Waiting for system time to be set...");
        time(&now);
        localtime_r(&now, &timeinfo);
        vTaskDelay(2000 / portTICK_PERIOD_MS); // 每隔 2 秒检查一次
        count++;
        if(count >= 10){
            break;
        }
    }
    ESP_LOGI(TAG, "Sync completed!");
}

void set_system_time() {
    // 设置需要的时间，例如 2024-12-12 12:34:56
    struct timeval tv;
    struct tm tm_time = {
        .tm_year = 2025 - 1900, // 年份从 1900 开始计算
        .tm_mon = 1 - 1,       // 月份从 0 开始
        .tm_mday = 8,
        .tm_hour = 20,
        .tm_min = 15,
        .tm_sec = 45
    };

    // 将 tm 转换为 time_t（秒级时间戳）
    tv.tv_sec = mktime(&tm_time); // 秒部分
    tv.tv_usec = 0;              // 微秒部分设置为 0

    // 设置系统时间
    if (settimeofday(&tv, NULL) == 0) {
        ESP_LOGI(TAG, "System time set successfully!");
    } else {
        ESP_LOGE(TAG, "Failed to set system time.");
    }
}

long long get_timestamp(){


    time_t now;
    struct tm timeinfo;

    time(&now);
    localtime_r(&now, &timeinfo);
    if(timeinfo.tm_year < (2024 - 1900)) {
        set_system_time();
        time(&now);
        localtime_r(&now, &timeinfo);
    }
    struct timeval tv;
    gettimeofday(&tv, NULL); // 获取当前时间
    ESP_LOGI(TAG, "Time get successfully!");

    // 毫秒级时间戳
    long long milliseconds = tv.tv_sec * 1000L + tv.tv_usec / 1000;
    return milliseconds;
}
 
 
 

 