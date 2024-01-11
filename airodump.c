#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

// radio 헤더 구조체
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
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
int convertSignalStrength(char signal_strength) {
    int result = (int)signal_strength;
    
    // 만약 signal_strength가 음수라면 2의 보수를 취해서 양수로 변환
    if (signal_strength < 0) {
        result = ~result + 1;
    }

    return result;
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