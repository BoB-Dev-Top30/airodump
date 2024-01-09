#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

//radio 헤더 구조체
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;

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

        }

    }

    // 종료
    pcap_close(handle);
    return 0;
}
