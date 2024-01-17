#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // sleep 함수를 위해 필요
#include <sys/types.h>
#include <sys/wait.h>
#include "airodump.h" // 내가 정의한 헤더파일

// 프레임 종류 판별
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
    memcpy(bssid, beacon_fr->bss_id, 6);
    
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

    Tag_SSID * SSID = &(wl_mg->SSID);
    uint8_t *ssid = SSID->ssid;
    *ssid_length = SSID->tag_length;

    return ssid;
}

/* Security 파트
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

int findMax(uint8_t *arr, int n) {
    int max = arr[0]; // 배열의 첫 번째 요소를 최대값으로 초기화
    for (int i = 1; i < n; i++) {
        if (arr[i] > max) {
            max = arr[i]; // 새로운 최대값 발견
        }
    }
    return max; // 배열에서 찾은 최대값을 반환
}




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

}
*/

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

// 각 파트의 프라이머리키를 보고 같은지 판별해줌
int check_same_elements(uint8_t * bssid1, uint8_t * bssid2, int size) {
    return memcmp(bssid1, bssid2, size);
}

// 출력함수
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

// 채널 옮기기 위한 함수
void set_channel(char *interface, int channel) {
    char command[100];

    sprintf(command, "iw dev %s set channel %d", interface, channel);
    system(command);
}

// 모니터 모드 자동 실행
void start_monitor_mode(char *interface) {
    char command[100];

    sprintf(command, "sudo gmon %s", interface);
    system(command);
}

// main함수
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 2;
    }
    start_monitor_mode(argv[1]);

    int current_channel = 1; // 시작 채널
    const int max_channel = 11; // 최대 채널 번호

    struct airodump_beacon * wlan_data=NULL; // 0으로 초기화
        // struct airodump_beacon * wlan_data=malloc(sizeof(struct airodump_beacon));
        // int size = sizeof(wlan_data) /sizeof(wlan_data[0]);

    int wlan_data_size = 0; // 추가: 할당된 배열의 크기를 추적하는 변수
    struct airodump_probe * wlan_data1=NULL; // 0으로 초기화
        // struct airodump_probe * wlan_data1=malloc(sizeof(struct airodump_probe));
        // int size1 = sizeof(wlan_data1) /sizeof(wlan_data1[0]);

    int wlan_data_size2 = 0; // 추가: 할당된 배열의 크기를 추적하는 변수
    int start_num=0;
    int start_num2=0;
    
    while (1) {
        set_channel(argv[1], current_channel);
        // 사용자가 지정한 네트워크 인터페이스 열기
        //handle = pcap_open_offline("dot11-sample.pcap", errbuf); // 현재 디렉터리의 "test_beacon.pcap" 파일 열기
        
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file 'test_beacon.pcapng': %s\n", errbuf);
            return 2;
        }
        const u_char *packet;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0)
            continue; // 타임아웃 발생
        if (res == -1 || res == -2) {
            fprintf(stderr, "End of pcap file or  pcap_next_ex failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            break;
        }

        int IS_beacon = process_packet(header, packet);
        if (IS_beacon==1) {
            struct airodump_beacon *temp_wlan_data = realloc(wlan_data, (wlan_data_size+1) * sizeof(struct airodump_beacon));
            
            if (!temp_wlan_data) {
                fprintf(stderr, "메모리 재할당 실패\n");
                if (wlan_data != NULL) {
                    free(wlan_data);  // 기존 메모리 해제
                    wlan_data = NULL;
                }
                exit(1);
            }
            wlan_data = temp_wlan_data;
            wlan_data_size +=1;

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
                    if(wlan_data[i].ESSID != NULL) {
                        free(wlan_data[i].ESSID); // 기존 ESSID 해제
                        wlan_data[i].ESSID = NULL;
                    }
                    wlan_data[i].ESSID = (uint8_t*)malloc(ssid_length + 1);
                    if (wlan_data[i].ESSID == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                        }
                    memcpy(wlan_data[i].ESSID, essid, ssid_length);
                    wlan_data[i].ESSID[ssid_length] = '\0'; // 문자열의 끝에 널 문자 추가
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
                    if(wlan_data[start_num].ESSID != NULL) { // 추가
                        free(wlan_data[start_num].ESSID); // 기존 ESSID 해제
                        wlan_data[start_num].ESSID = NULL;
                    }
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
            
            struct airodump_probe *temp_wlan_data2 = realloc(wlan_data1, (wlan_data_size2+1) * sizeof(struct airodump_probe));
            if (!temp_wlan_data2) {
                fprintf(stderr, "메모리 재할당 실패\n");
                free(wlan_data1);  // 기존 메모리 해제
                exit(1);
            }
            wlan_data1 = temp_wlan_data2;
            wlan_data_size2++;

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
                    if(wlan_data1[i].PROBE != NULL) {
                        free(wlan_data1[i].PROBE); // 기존 PROBE 해제
                        wlan_data1[i].PROBE = NULL;
                    }
                    wlan_data1[i].PROBE = (uint8_t*)malloc(probe_length + 1);
                    if (wlan_data1[i].PROBE == NULL) {
                        fprintf(stderr, "메모리 할당 실패\n");
                        return 1;
                    }
                    memcpy(wlan_data1[i].PROBE, probe, probe_length);
                    wlan_data1[i].PROBE[probe_length] = '\0'; // 문자열의 끝에 널 문자 추가
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
                    if(wlan_data1[start_num2].PROBE != NULL) { 
                        free(wlan_data1[start_num2].PROBE); // 기존 PROBE 해제
                        wlan_data1[start_num2].PROBE = NULL;
                    }
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

    printData(wlan_data, start_num, wlan_data1, start_num2);

    
    /*
    for (int i = 0; i < start_num; i++) {
        if (wlan_data[i].ESSID != NULL) {
            free(wlan_data[i].ESSID);
            wlan_data[i].ESSID = NULL;
        }
    }
    if (wlan_data != NULL) {
        free(wlan_data);
        wlan_data = NULL;
    }

    for (int i = 0; i < start_num2; i++) {
        if (wlan_data1[i].PROBE != NULL) {
        free(wlan_data1[i].PROBE);
        wlan_data1[i].PROBE = NULL;
    }
    }
    if (wlan_data1 != NULL) {
        free(wlan_data1);
        wlan_data1 = NULL;
    }
    */
    pcap_close(handle);

    current_channel++;
    if (current_channel > 13) { // 대부분의 지역에서 사용 가능한 와이파이 채널은 1~13번입니다.
            current_channel = 1;
    }
    sleep(1);
    }
    for (int i = 0; i < start_num; i++) {
        if (wlan_data[i].ESSID != NULL) {
            free(wlan_data[i].ESSID);
        }
    }
    free(wlan_data);

    for (int i = 0; i < start_num2; i++) {
        if (wlan_data1[i].PROBE != NULL) {
            free(wlan_data1[i].PROBE);
        }
    }
    free(wlan_data1);

    return 0;
}