#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    uint16_t fragment_sequence_number; // 한꺼번에
};

typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t ssid[];

} Tag_SSID;

typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t rates[];
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Supported_Rates;

typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t channel;

} Tag_DS;
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint16_t rsn_version;
    uint32_t group_cipher; // 그룹 암호화 알고리즘
    uint16_t pairwise_cipher_count; // 페어와이즈 암호화 알고리즘의 수
}Tag_RSN_Information_Front;

// 전반부와 후반부를 나눈 이유는 가변길이가 중간에 하나 섞이기 때문이다.

typedef struct{
    uint32_t * pairwise_cipher_list; // 페어와이즈 암호화 알고리즘 리스트(가변길이)
    uint16_t auth_key_mngt_count; // 인증 방법의 수
} Tag_RSN_Information_Middle;

typedef struct{
    uint32_t * auth_key_mngt_list; // 인증 방법 리스트(가변길이)
    uint16_t rsn_capabilities; // RSN 능력
} Tag_RSN_Information_Back;

typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t rates[];
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Extended_Supported_Rates;

typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t DTIM_count;
    uint8_t DTIM_period;
    uint8_t bitmap;
    uint8_t virtual_bitmap[]; // 가변
} Tag_Traffic_Indication_Map;

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

// 비콘 여부 판별
int process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    uint16_t radiotap_header_length = radio_hdr->len;
    u_char type_subtype = packet[radiotap_header_length];
    u_char type = (type_subtype & 0x0C) >> 2;    // 타입 필드
    u_char subtype = (type_subtype & 0xF0) >> 4; // 서브타입 필드
    if (type == 0 && subtype == 8) {
        printf("Beacon Frame Captured\n");
        return 1;
    } else {
        return 0;
    }
}

// pwr 구하기 위한 길이 조정 함수
int getFieldLength(uint32_t presentFlags, int field) {
    int length = 0;
    printf("presentFlags :%d , field: %d\n", presentFlags, field);
    // TSFT, Flags, Rate, Channel, FHSS, dBm Antenna Signal 등 필드의 길이를 처리
    
    int yn = presentFlags & (1 << field);
    printf("yn: %d\n", yn);
    if (yn) {
        switch (field) {
            case 0:
                length += 8;
                printf("TSFT is exist\n");
                break; // TSFT
            case 1:
                length += 1;
                printf("Flags is exist\n");
                break; // Flags
            case 2:
                length += 1;
                printf("Rate is exist\n");
                break; // Rate
            case 3:
                length += 4;
                printf("Channel is exist\n");
                break; // Channel
            case 4:
                length += 2;
                printf("FHSS is exist\n");
                break; // FHSS

            case 31:
                length +=999;
                printf("Next present flag is exist\n");
                break;
            // 다른 필드에 대한 길이 처리 추가
        }
    }
    return length;
}



int find_signal_strength(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    int target=0;
    printf("len:%d\n", offset);
    int signal_strength = 0;
    /*
    first_present = ((first_present >> 24) & 0x000000ff) | ((first_present >> 8) & 0x0000ff00) |
              ((first_present << 8) & 0x00ff0000) | ((first_present << 24) & 0xff000000);
    printf("firstaddress 0x%x\n", first_present);
    */
    int num=1;
    while(1){
        uint32_t first_present = *(uint32_t *)(packet + (4*num));
        printf("original present %x\n", first_present);
        
        for(int i=0; i<=4; i++){
            target += getFieldLength(first_present,i);
        }
        num+=1;
        
        uint32_t next_present = *(uint32_t *)(packet + (4*num));
        if(getFieldLength(next_present,31)==999){
            continue;
        }
        else{
            break;
        }
        
    }
    printf("target location: %d\n", target);
    target = *(char *)(packet + (4*(num+1)) + target);

    return target;
}

void find_bssid(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct beacon_frame *beacon_fr = (struct beacon_frame *)(packet+offset);
    
    printf("beaconframe %x\n", beacon_fr->beacon_frame);
    uint8_t *bssid = beacon_fr->bss_id;
    for(int i=0; i<=5; i++){
        printf("%02x", bssid[i]);
        if (i != 5) {
            printf(":");
        }
    }
    printf("\n");
}



void find_wireless_static(const struct pcap_pkthdr *header, const u_char *packet) 
{
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct wireless_management *wl_mg = (struct wireless_management *)(packet + offset + 24); // 24는 비콘프레임의 fix값
    // printf("wireless version: %x\n",wl_mg->version);
    Tag_SSID * SSID = &(wl_mg->SSID);
    uint8_t *ssid = SSID->ssid;
    int ssid_length = SSID->tag_length;
    printf("ssid:");
    for(int i=0; i<ssid_length; i++){
        printf("%c", ssid[i]);

    }
    printf("\n");
}

void print_cipher_type(uint32_t cipher){
    switch(cipher){
        case 0x01ac0f00: printf("WEP-40\n"); break;
        case 0x02ac0f00: printf("TKIP\n"); break;
        case 0x03ac0f00: printf("WRAP\n"); break;
        case 0x04ac0f00: printf("CCMP\n"); break;
        case 0x05ac0f00: printf("WEP-104\n"); break;
        default: printf("Unknown\n"); break;
    }
}

void print_auth_type(uint32_t auth){
    switch(auth){
        case 0x01ac0f00: printf("802.1X/WPA\n"); break;
        case 0x02ac0f00: printf("PSK/WPA2\n"); break;
        case 0x03ac0f00: printf("FT/802.1X\n"); break;
        case 0x04ac0f00: printf("FT/PSK\n"); break;
        case 0x05ac0f00: printf("802.1X/WPA2\n"); break;
        case 0x06ac0f00: printf("PSK/WPA2\n"); break;
        default: printf("Unknown\n"); break;
    }
}

int Is_RSN(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *wireless_tagged_frame) 
{
    Tag_RSN_Information_Front * rsn_f = (Tag_RSN_Information_Front *)wireless_tagged_frame;
    printf("rsn_tag_number:%d\n", rsn_f->tag_number);
    if(rsn_f->tag_number ==48)
    {
        return 1;
    }
    else{
        return 0;
    }
}



void find_wireless_dynamic(const struct pcap_pkthdr *header, const u_char *packet) 
{
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    uint8_t *wireless_tagged_frame = (uint8_t *)(packet + offset + 24 + 12);
    Tag_SSID * ssid = (Tag_SSID *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + ssid->tag_length);

    Tag_Supported_Rates * rates = (Tag_Supported_Rates *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + rates->tag_length);

    Tag_DS * ds = (Tag_DS *)wireless_tagged_frame;
    uint8_t channel = ds->channel;
    printf("channel: %x\n", channel);
    wireless_tagged_frame += (2 + ds->tag_length);

    Tag_Traffic_Indication_Map * tim = (Tag_Traffic_Indication_Map *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + tim->tag_length);

    Tag_ERP_Information * erp = (Tag_ERP_Information *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + erp->tag_length);

    Tag_Extended_Supported_Rates * esr = (Tag_Extended_Supported_Rates *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + esr->tag_length);
    
    wireless_tagged_frame += 52;//고정길이

    if(Is_RSN(header, packet, wireless_tagged_frame)){
    // 맨첫번째
    Tag_RSN_Information_Front * rsn_f = (Tag_RSN_Information_Front *)wireless_tagged_frame;
    int pairwise_count = rsn_f->pairwise_cipher_count;
    uint32_t EncandCipher = rsn_f->group_cipher;
    printf("group_cipherinfo : %02x\n", EncandCipher);
    print_cipher_type(EncandCipher);
    printf("pairwise count: %d\n", pairwise_count);
    wireless_tagged_frame += 10;//고정길이

    //중간
    Tag_RSN_Information_Middle *rsn_m;
    rsn_m = (Tag_RSN_Information_Middle *)malloc(sizeof(Tag_RSN_Information_Middle));
    rsn_m->pairwise_cipher_list = (uint32_t *)malloc(sizeof(uint32_t) * pairwise_count);
    memcpy(rsn_m->pairwise_cipher_list, wireless_tagged_frame, sizeof(uint32_t) * pairwise_count);
    
    for(int i=0; i<pairwise_count; i++){
        printf("pairwise_cipherinfo:%x\n", rsn_m->pairwise_cipher_list[i]);
    }
    wireless_tagged_frame += (pairwise_count * 4); 

    memcpy(&rsn_m->auth_key_mngt_count, wireless_tagged_frame, sizeof(uint16_t));
    int auth_key_mngt_count = rsn_m->auth_key_mngt_count;
    printf("auth_key count : %d\n", auth_key_mngt_count);
    wireless_tagged_frame += 2;

    //끝
    
    Tag_RSN_Information_Back *rsn_b;
    rsn_b = (Tag_RSN_Information_Back *)malloc(sizeof(Tag_RSN_Information_Back));
    rsn_b->auth_key_mngt_list = (uint32_t *)malloc(sizeof(uint32_t) * auth_key_mngt_count);
    memcpy(rsn_b->auth_key_mngt_list, wireless_tagged_frame, sizeof(uint32_t) * auth_key_mngt_count);

    for(int i=0; i<auth_key_mngt_count; i++){
        printf("authinfo:%x\n", rsn_b->auth_key_mngt_list[i]);
        print_auth_type(rsn_b->auth_key_mngt_list[i]);
    }
    
    }

    

    /*
    Tag_SSID * SSID = &(wl_mg->SSID);
    uint8_t *ssid = SSID->ssid;
    int ssid_length = SSID->tag_length;
    printf("ssid:");
    for(int i=0; i<ssid_length; i++){
        printf("%c", ssid[i]);

    }
    printf("\n");
    
    wireless_tagged_frame += (2 + rsn->tag_length);
    */


}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 2;
    }

    // 사용자가 지정한 네트워크 인터페이스 열기
    handle = pcap_open_offline("test_beacon.pcapng", errbuf); // 현재 디렉터리의 "test_beacon.pcap" 파일 열기
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file 'test_beacon.pcapng': %s\n", errbuf);
        return 2;
    }

    while (1) {
        const u_char *packet;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue; // 타임아웃 발생
        if (res == -1) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
            break;
        }

        int IS_beacon = process_packet(header, packet);
        if (IS_beacon) {
            char signal_strength = find_signal_strength(header, packet);
            int pwr = (int)signal_strength;
            printf("pwr %d\n", pwr);
            find_bssid(header, packet);
            find_wireless_static(header, packet);
            find_wireless_dynamic(header, packet);
        }
    }

    // 종료
    pcap_close(handle);
    return 0;
}


/*#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

//radio 헤더 구조체
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;

};

// 비콘 여부 판별
int process_packet(const struct pcap_pkthdr *header, const u_char *packet) {

    struct radiotap_header * radio_hdr = (struct radiotap_header *)packet;

    uint16_t radiotap_header_length = radio_hdr->len;

    u_char type_subtype = packet[radiotap_header_length];
    u_char type = (type_subtype & 0x0C)>>2; // 타입 필드
    u_char subtype = (type_subtype & 0xF0)>>4; // 서브타입 필드

    if (type == 0 && subtype == 8) 
    { 
        printf("Beacon Frame Captured\n");
        return 1;
    }
    else{
        return 0;
    }
}

//pwr구하기 위한 길이조정 함수
int getFieldLength(uint32_t presentFlags, int field) {
    int length = 0;

    // TSFT, Flags, Rate, Channel, FHSS, dBm Antenna Signal 등 필드의 길이를 처리
    if (presentFlags & (1 << field)) {
        switch (field) {
            case 0: length += 8; break; // TSFT
            case 1: length += 1; break; // Flags
            case 2: length += 1; break; // Rate
            case 3: length += 4; break; // Channel
            case 4: length += 2; break; // FHSS
            // 다른 필드에 대한 길이 처리 추가
            case 5: length += 1; break; // dBm Antenna Signal
            // ...
        }
    }
    return length;
}


int find_signal_strength(const struct pcap_pkthdr *header, const u_char *packet){
    
    struct radiotap_header * radio_hdr = (struct radiotap_header *)packet;


    int offset = radio_hdr->len;
    printf("len:%d\n", offset);
    int signal_strength = 0;

    uint32_t present = *(uint32_t*)(packet + offset);

    present = ((present >> 24) & 0x000000ff) |
              ((present >> 8) & 0x0000ff00) |
              ((present << 8) & 0x00ff0000) |
              ((present << 24) & 0xff000000);

    printf("firstaddress 0x%x\n", present);

    return signal_strength;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 2;
    }

    // 사용자가 지정한 네트워크 인터페이스 열기
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    while (1) {
        const u_char *packet;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // 타임아웃 발생
        if (res == -1) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
            break;
        }

        int IS_beacon = process_packet(header, packet);
        if(IS_beacon){
            int signal_strength = find_signal_strength(header, packet);
            printf("pwr %d\n", signal_strength);

        }

    }

    // 종료
    pcap_close(handle);
    return 0;
}
*/