// 출력용 비콘 프레임 구조체
struct airodump_beacon{
    uint8_t BSSID [6];
    int PWR;
    int BEACONS;
    uint8_t CH;
    uint8_t *ESSID; //가변
};

// 출력용 probe request와 response 프레임 구조체
struct airodump_probe{
    uint8_t BSSID [6];
    uint8_t STATION [6];
    int PWR;
    int Frames;
    uint8_t *PROBE; //가변
};

// radio 헤더 구조체
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
};

// beacon 프레임 구조체
struct beacon_frame{
    uint8_t beacon_frame;
    uint8_t flags;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6];
    uint16_t fragment_sequence_number; // 한꺼번에(no need)
};

// probe 프레임 구조체
struct probe_frame{
    uint8_t probe_frame;
    uint8_t flags;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6];
    uint16_t fragment_sequence_number; // 한꺼번에(no need)
};

// SSID 구조체
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t ssid[];

} Tag_SSID;

// Supported rates(MB) 구조체
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t rates[];
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Supported_Rates;

// DS파트구조체
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t channel;

} Tag_DS;

//RSN파트 구조체(security)
// 전반부, 중반부, 후반부를 나눈 이유는 가변길이가 중간에 하나 섞이기 때문이다.
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint16_t rsn_version;
    uint32_t group_cipher; // 그룹 암호화 알고리즘
    uint16_t pairwise_cipher_count; // 페어와이즈 암호화 알고리즘의 수
}Tag_RSN_Information_Front;

typedef struct{
    uint32_t * pairwise_cipher_list; // 페어와이즈 암호화 알고리즘 리스트(가변길이)
    uint16_t auth_key_mngt_count; // 인증 방법의 수
} Tag_RSN_Information_Middle;

typedef struct{
    uint32_t * auth_key_mngt_list; // 인증 방법 리스트(가변길이)
    uint16_t rsn_capabilities; // RSN 능력
} Tag_RSN_Information_Back;

// Extended_Supported_Rates (MB)
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t rates[];
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Extended_Supported_Rates;

// Traffic_Indication_Map
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t DTIM_count;
    uint8_t DTIM_period;
    uint8_t bitmap;
    uint8_t virtual_bitmap[]; // 가변
} Tag_Traffic_Indication_Map;

//ERP Information
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t erp_information;
} Tag_ERP_Information;

// wireless management 구조체
struct wireless_management{
    uint8_t fixed_parameter[12];
    Tag_SSID SSID;
    Tag_Supported_Rates Rates;
    Tag_DS DS;
    Tag_Traffic_Indication_Map TIM;
    Tag_ERP_Information ERP_INFO;
    Tag_Extended_Supported_Rates E_Rates;
    uint8_t ht_capabilities[28]; //고정
    uint8_t ht_information[24]; //고정
    Tag_RSN_Information_Front r_f;
    Tag_RSN_Information_Middle r_m;
    Tag_RSN_Information_Back r_b;

};