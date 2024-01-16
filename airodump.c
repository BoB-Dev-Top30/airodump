#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // sleep 함수를 위해 필요

// airodump 출력용 비콘 프레임 구조체

struct airodump_beacon{
    uint8_t BSSID [6];
    int PWR;
    int BEACONS;
    uint8_t CH;
    uint8_t *ESSID; //가변
};


// airodump 출력용 probe 프레임 구조체
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
    uint16_t fragment_sequence_number; // 한꺼번에
};

// probe 프레임 구조체
struct probe_frame{
    uint8_t probe_frame;
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
    } 
    
    else if(type == 0 && subtype == 4) {
        printf("Probe Request Frame Captured\n");
        return 2;
    }
    else if(type == 0 && subtype == 5){
        printf("Probe Response Frame Captured\n");
        return 3;
    }
    else{
        return 0;
    }
}


// pwr 구하기 위한 길이 조정 함수
int getFieldLength(uint32_t presentFlags, int field) {
    int length = 0;
    // TSFT, Flags, Rate, Channel, FHSS, dBm Antenna Signal 등 필드의 길이를 처리
    
    int yn = presentFlags & (1 << field);
    if (yn) {
        switch (field) {
            case 0:
                length += 8;
                break; // TSFT
            case 1:
                length += 1;
                break; // Flags
            case 2:
                length += 1;
                break; // Rate
            case 3:
                length += 4;
                break; // Channel
            case 4:
                length += 2;
                break; // FHSS

            case 31:
                length +=999;
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
    target = *(char *)(packet + (4*(num+1)) + target);

    return target;
}

void find_bssid(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *bssid) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct beacon_frame *beacon_fr = (struct beacon_frame *)(packet+offset);
    
    printf("beaconframe %x\n", beacon_fr->beacon_frame);
    memcpy(bssid, beacon_fr->bss_id, 6);  // 변경된 부분
    
    
    
    for(int i=0; i<=5; i++){
        printf("%02x", bssid[i]);
        if (i != 5) {
            printf(":");
        }
    }
    printf("\n");
    
}

void find_station_request(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *station) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct probe_frame *probe_fr = (struct probe_frame *)(packet+offset);
    
    printf("probeframe %x\n", probe_fr->probe_frame);
    memcpy(station, probe_fr->source_address, 6);  // 변경된 부분
    
    for(int i=0; i<=5; i++){
        printf("%02x", station[i]);
        if (i != 5) {
            printf(":");
        }
    }
    printf("\n");
    
}

void find_station_response(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *station) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct probe_frame *probe_fr = (struct probe_frame  *)(packet+offset);
    
    printf("probeframe %x\n", probe_fr->probe_frame);
    memcpy(station, probe_fr->destination_address, 6);  // 변경된 부분
    
    for(int i=0; i<=5; i++){
        printf("%02x", station[i]);
        if (i != 5) {
            printf(":");
        }
    }
    printf("\n");
    
}




uint8_t * find_wireless_static(const struct pcap_pkthdr *header, const u_char *packet, int *ssid_length) 
{
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;
    
    struct wireless_management *wl_mg = (struct wireless_management *)(packet + offset + 24); // 24는 비콘프레임의 fix값
    // printf("wireless version: %x\n",wl_mg->version);
    Tag_SSID * SSID = &(wl_mg->SSID);
    uint8_t *ssid = SSID->ssid;
    *ssid_length = SSID->tag_length;
    /*
    printf("ssid:");
    for(int i=0; i<ssid_length; i++){
        printf("%c", ssid[i]);

    }
    printf("\n");
    */

    return ssid;
}



char* print_cipher_type(uint32_t cipher){
    char* cipher_str;
    switch(cipher){
        case 0x01ac0f00: cipher_str = "WEP-40"; break;
        case 0x02ac0f00: cipher_str ="TKIP"; break;
        case 0x03ac0f00: cipher_str = "WRAP"; break;
        case 0x04ac0f00: cipher_str = "CCMP"; break;
        case 0x05ac0f00: cipher_str = "WEP-104"; break;
        default: cipher_str = "Unknown"; break;
    }
    return cipher_str;
}

char* print_auth_type(uint32_t auth){
    char* auth_str;
    switch(auth){
        case 0x01ac0f00: auth_str = "802.1X/WPA"; break;
        case 0x02ac0f00: auth_str = "PSK/WPA2"; break;
        case 0x03ac0f00: auth_str = "FT/802.1X"; break;
        case 0x04ac0f00: auth_str = "FT/PSK"; break;
        case 0x05ac0f00: auth_str = "802.1X/WPA2"; break;
        case 0x06ac0f00: auth_str = "PSK/WPA2"; break;
        default: auth_str = "Unknown/Unknown"; break;
    }
    return auth_str;
}

/*
void change_Mb_type(uint32_t mb){
    switch(mb){
        case 0x82: printf("1mb\n"); break;
        case 0x84: printf("2mb\n"); break;
        case 0x8b: printf("5.5mb\n"); break;
        case 0x96: printf("11mb\n"); break;
        case 0x0c: printf("6mb\n"); break;
        case 0x12: printf("9mb\n"); break;
        case 0x18: printf("12mb\n"); break;
        case 0x24: printf("18mb\n"); break;

        case 0x30: printf("24mb\n"); break;
        case 0x48: printf("36mb\n"); break;
        case 0x60: printf("48mb\n"); break;
        case 0x6c: printf("54mb\n"); break;
        default: printf("Unknown\n"); break;
    }
}

//최대값 출력 함수 -> MB찾는거에 쓰임
int findMax(uint8_t *arr, int n) {
    int max = arr[0]; // 배열의 첫 번째 요소를 최대값으로 초기화
    for (int i = 1; i < n; i++) {
        if (arr[i] > max) {
            max = arr[i]; // 새로운 최대값 발견
        }
    }
    return max; // 배열에서 찾은 최대값을 반환
}

*/


//RSN필드 여부 판별(Security 관련)
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


uint8_t find_wireless_dynamic(const struct pcap_pkthdr *header, const u_char *packet) 
{
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    uint8_t *wireless_tagged_frame = (uint8_t *)(packet + offset + 24 + 12);
    Tag_SSID * ssid = (Tag_SSID *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + ssid->tag_length);

    Tag_Supported_Rates * rates = (Tag_Supported_Rates *)wireless_tagged_frame;
    int supported_rates_length = rates->tag_length;
    uint8_t *new_array = (uint8_t *)malloc(supported_rates_length * sizeof(uint8_t));
    memcpy(new_array, rates->rates, supported_rates_length * sizeof(uint8_t));

    
    wireless_tagged_frame += (2 + rates->tag_length);

    Tag_DS * ds = (Tag_DS *)wireless_tagged_frame;
    uint8_t channel = ds->channel;
    printf("channel: %x\n", channel);
    return channel;
}

// security 정보 출력
uint8_t find_wireless_dynamic2(const struct pcap_pkthdr *header, const u_char *packet) 
{
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    uint8_t *wireless_tagged_frame = (uint8_t *)(packet + offset + 24 + 12);
    Tag_SSID * ssid = (Tag_SSID *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + ssid->tag_length);

    Tag_Supported_Rates * rates = (Tag_Supported_Rates *)wireless_tagged_frame;
    int supported_rates_length = rates->tag_length;
    uint8_t *new_array = (uint8_t *)malloc(supported_rates_length * sizeof(uint8_t));
    memcpy(new_array, rates->rates, supported_rates_length * sizeof(uint8_t));

    
    wireless_tagged_frame += (2 + rates->tag_length);

    Tag_DS * ds = (Tag_DS *)wireless_tagged_frame;
    uint8_t channel = ds->channel;

    wireless_tagged_frame += (2 + ds->tag_length);

    Tag_Traffic_Indication_Map * tim = (Tag_Traffic_Indication_Map *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + tim->tag_length);

    Tag_ERP_Information * erp = (Tag_ERP_Information *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + erp->tag_length);

    Tag_Extended_Supported_Rates * esr = (Tag_Extended_Supported_Rates *)wireless_tagged_frame;
    int extended_supported_rates_length = esr->tag_length;
    new_array = (uint8_t *)realloc(new_array, (supported_rates_length + extended_supported_rates_length) * sizeof(uint8_t));
    memcpy(new_array, esr->rates, extended_supported_rates_length * sizeof(uint8_t));

    
    wireless_tagged_frame += (2 + esr->tag_length);
    

    free(new_array);
    wireless_tagged_frame += 52;//고정길이

    if(Is_RSN(header, packet, wireless_tagged_frame)){
    // 맨첫번째
    Tag_RSN_Information_Front * rsn_f = (Tag_RSN_Information_Front *)wireless_tagged_frame;
    int pairwise_count = rsn_f->pairwise_cipher_count;
    uint32_t EncandCipher = rsn_f->group_cipher;
    print_cipher_type(EncandCipher);
    wireless_tagged_frame += 10;//고정길이

    //중간
    Tag_RSN_Information_Middle *rsn_m;
    rsn_m = (Tag_RSN_Information_Middle *)malloc(sizeof(Tag_RSN_Information_Middle));
    rsn_m->pairwise_cipher_list = (uint32_t *)malloc(sizeof(uint32_t) * pairwise_count);
    memcpy(rsn_m->pairwise_cipher_list, wireless_tagged_frame, sizeof(uint32_t) * pairwise_count);
    
    wireless_tagged_frame += (pairwise_count * 4); 

    memcpy(&rsn_m->auth_key_mngt_count, wireless_tagged_frame, sizeof(uint16_t));
    int auth_key_mngt_count = rsn_m->auth_key_mngt_count;
    wireless_tagged_frame += 2;

    //끝
    
    Tag_RSN_Information_Back *rsn_b;
    rsn_b = (Tag_RSN_Information_Back *)malloc(sizeof(Tag_RSN_Information_Back));
    rsn_b->auth_key_mngt_list = (uint32_t *)malloc(sizeof(uint32_t) * auth_key_mngt_count);
    memcpy(rsn_b->auth_key_mngt_list, wireless_tagged_frame, sizeof(uint32_t) * auth_key_mngt_count);

    for(int i=0; i<auth_key_mngt_count; i++){
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



int check_same_elements(uint8_t * bssid1, uint8_t * bssid2, int size) {
    return memcmp(bssid1, bssid2, size);
}


void printData(struct airodump_beacon *wlan_data, int start_num, struct airodump_probe *wlan_data1, int start_num2) {
    system("clear"); // 화면 클리어
    printf("BSSID             PWR  Beacons  CH   ESSID\n");
    printf("--------------------------------------------------\n");
    for(int i = 0; i < start_num; i++) {
        for(int j = 0; j < 6; j++) {
            printf("%02x", wlan_data[i].BSSID[j]);
            if (j != 5) printf(":");
        }
        printf("  %-3d    %-7d  %-3d   %s\n", wlan_data[i].PWR, wlan_data[i].BEACONS, wlan_data[i].CH, wlan_data[i].ESSID);
    }

    printf("\n\nBSSID             STATION         PWR  FRAMES  PROBES\n");
    printf("-------------------------------------------------------------\n");
    for(int i = 0; i < start_num2; i++) {
        for(int j = 0; j < 6; j++) {
            printf("%02x", wlan_data1[i].BSSID[j]);
            if (j != 5) printf(":");
        }
        printf("  ");
        for(int j = 0; j < 6; j++) {
            printf("%02x", wlan_data1[i].STATION[j]);
            if (j != 5) printf(":");
        }
        printf("  %-3d    %-6d  %s\n", wlan_data1[i].PWR, wlan_data1[i].Frames, wlan_data1[i].PROBE);
    }
}


int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 2;
    }

    // 사용자가 지정한 네트워크 인터페이스 열기
    // handle = pcap_open_offline("test_beacon.pcapng", errbuf); // 현재 디렉터리의 "test_beacon.pcap" 파일 열기
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file 'test_beacon.pcapng': %s\n", errbuf);
        return 2;
    }



    struct airodump_beacon * wlan_data=NULL; // 0으로 초기화
    // int size = sizeof(wlan_data) /sizeof(wlan_data[0]);

    int wlan_data_size = 0; // 추가: 할당된 배열의 크기를 추적하는 변수
    struct airodump_probe * wlan_data1=NULL; // 0으로 초기화
    // int size1 = sizeof(wlan_data1) /sizeof(wlan_data1[0]);

    int wlan_data_size2 = 0; // 추가: 할당된 배열의 크기를 추적하는 변수
    int start_num=0;
    int start_num2=0;
    
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
        if (IS_beacon==1) {
            wlan_data_size +=1;
            /*
            wlan_data = realloc(wlan_data, (wlan_data_size) * sizeof(struct airodump_beacon));
            wlan_data_size +=1;
            if (!wlan_data) {
                fprintf(stderr, "메모리 재할당 실패\n");
                exit(1);
            }
            */
            struct airodump_beacon *temp_wlan_data = realloc(wlan_data, wlan_data_size * sizeof(struct airodump_beacon));
            if (!temp_wlan_data) {
                fprintf(stderr, "메모리 재할당 실패\n");
                free(wlan_data);  // 기존 메모리 해제
                exit(1);
            }
            wlan_data = temp_wlan_data;

            char signal_strength = find_signal_strength(header, packet);
            int pwr = (int)signal_strength;
            printf("pwr %d\n", pwr);
            printf("%d 번쨰 입니다.\n", start_num);
            uint8_t bssid[6];
            find_bssid(header, packet, bssid);
            for(int j=0; j<6; j++) {
                    printf("%02x", bssid[j]);
                     if (j != 5) {
                        printf(":");
                    }
                }

            int ssid_length;
            uint8_t * essid = find_wireless_static(header, packet, &ssid_length);
            uint8_t channel = find_wireless_dynamic(header, packet);

            int found=0;
            for (int i=0; i<start_num; i++){
                
                // i값 증가
                if(check_same_elements(wlan_data[i].BSSID, bssid, 6)==0) {
                    printf("%d와 BSSID가 동일합니다. 따라서 업데이트 진행합니다.\n",i);
                    wlan_data[i].PWR = pwr;
                    wlan_data[i].BEACONS+=1;
                    wlan_data[i].CH=channel;
                    wlan_data[start_num].ESSID = (uint8_t*)malloc(ssid_length + 1);
                    if (wlan_data[start_num].ESSID == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                        }
                    memcpy(wlan_data[i].ESSID, essid, ssid_length);
                    wlan_data[start_num].ESSID[ssid_length] = '\0'; // 문자열의 끝에 널 문자 추가
                    found=1;
                    break;
                    
                }
            }

                // start_num 증가
                if (!found && start_num < wlan_data_size) {
                    printf("BSSID가 동일하지 않기에 새롭게 만듭니다.\n");
                    memcpy(wlan_data[start_num].BSSID, bssid, 6);
                    wlan_data[start_num].PWR = pwr;
                    wlan_data[start_num].BEACONS= 1;
                    wlan_data[start_num].CH=channel;
                    wlan_data[start_num].ESSID = (uint8_t*)malloc(ssid_length + 1);
                    if (wlan_data[start_num].ESSID == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                        }
                    memcpy(wlan_data[start_num].ESSID, essid, ssid_length);
                    wlan_data[start_num].ESSID[ssid_length] = '\0'; // 문자열의 끝에 널 문자 추가
                    start_num+=1;
                }
            

        }

        else if(IS_beacon==2 || IS_beacon==3)
        {
            /*
            wlan_data1 = realloc(wlan_data1, (wlan_data_size2) * sizeof(struct airodump_probe));
            wlan_data_size2 +=1;
            if (!wlan_data1) {
                fprintf(stderr, "메모리 재할당 실패\n");
                exit(1);
            }*/
            wlan_data_size2++;
            struct airodump_probe *temp_wlan_data2 = realloc(wlan_data1, wlan_data_size2 * sizeof(struct airodump_probe));
            if (!temp_wlan_data2) {
                fprintf(stderr, "메모리 재할당 실패\n");
                free(wlan_data1);  // 기존 메모리 해제
                exit(1);
            }
            wlan_data1 = temp_wlan_data2;

            char signal_strength = find_signal_strength(header, packet);
            int pwr = (int)signal_strength;
            printf("request: pwr %d\n", pwr);

            uint8_t bssid[6];
            find_bssid(header, packet, bssid);

            uint8_t station[6];

            if(IS_beacon==2){
                find_station_request(header, packet, station);
            }
            else if(IS_beacon==3){
                find_station_response(header, packet, station);
            }

            int probe_length;
            uint8_t * probe = find_wireless_static(header, packet, &probe_length);



            int found=0;
            for (int i=0; i<start_num2; i++){
                
                // i값 증가
                if(check_same_elements(wlan_data1[i].STATION, station, 6)==0) {
                    printf("%d와 STATION가 동일합니다. 따라서 업데이트 진행합니다.\n",i);
                    memcpy(wlan_data1[i].BSSID, bssid, 6);
                    wlan_data1[i].PWR = pwr;
                    wlan_data1[i].Frames+=1;
                    wlan_data1[start_num2].PROBE = (uint8_t*)malloc(probe_length + 1);
                    if (wlan_data1[start_num2].PROBE == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                    }
                    memcpy(wlan_data1[i].PROBE, probe, probe_length);
                    wlan_data1[start_num2].PROBE[probe_length] = '\0'; // 문자열의 끝에 널 문자 추가
                    found=1;
                    break;
                    
                }
            }

                // start_num 증가
                if (!found && start_num2 < wlan_data_size2) {
                    printf("STATION가 동일하지 않기에 새롭게 만듭니다.\n");
                    memcpy(wlan_data1[start_num2].STATION, station, 6);
                    memcpy(wlan_data1[start_num2].BSSID, bssid, 6);
                    wlan_data1[start_num2].PWR = pwr;
                    wlan_data1[start_num2].Frames= 1;
                    wlan_data1[start_num2].PROBE = (uint8_t*)malloc(probe_length + 1);
                    if (wlan_data1[start_num2].PROBE == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                        }
                    memcpy(wlan_data1[start_num2].PROBE, probe, probe_length);
                    wlan_data1[start_num2].PROBE[probe_length] = '\0'; // 문자열의 끝에 널 문자 추가
                    start_num2+=1;
                }


        }
        /*    
        printf("BSSID             PWR Beacons CH   ESSID\n");
        for(int i=0; i<start_num; i++){
                for(int j=0; j<6; j++) {
                    printf("%02x", wlan_data[i].BSSID[j]);
                     if (j != 5) {
                        printf(":");
                    }
                }
                printf(" %d", wlan_data[i].PWR);
                printf("   %d", wlan_data[i].BEACONS);
                printf("      %d", wlan_data[i].CH);
                printf("   %s\n", wlan_data[i].ESSID);
            
            }

            printf("\n\n\n");

            printf("BSSID             STATION PWR FRAMES   PROBES\n");
            for(int i=0; i<start_num2; i++){
                for(int j=0; j<6; j++) {
                    printf("%02x", wlan_data1[i].BSSID[j]);
                     if (j != 5) {
                        printf(":");
                    }
                }
                for(int j=0; j<6; j++) {
                    printf("%02x", wlan_data1[i].STATION[j]);
                     if (j != 5) {
                        printf(":");
                    }
                }
                printf(" %d", wlan_data1[i].PWR);
                printf("   %d", wlan_data1[i].Frames);
                printf("   %s\n", wlan_data1[i].PROBE);
            
            }
            
            
*/

    printData(wlan_data, start_num, wlan_data1, start_num2);

    sleep(1);// 실시간 업데이트를 위해 일정 시간 동안 대기
    }


    for (int i = 0; i < start_num; i++) {
        free(wlan_data[i].ESSID);
    }

    for (int i = 0; i < start_num2; i++) {
        free(wlan_data1[i].PROBE);
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