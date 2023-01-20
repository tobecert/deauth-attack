#ifndef _MAIN_H
#define _MAIN_H


#pragma pack(push, 1)

typedef struct _radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag1;
    uint32_t present_flag2;
} radiotap_header;

typedef struct _dot11_header {
    uint8_t frame_control_version : 2;
    uint8_t frame_control_type : 2;
    uint8_t frame_control_subtype : 4;
    uint8_t flags; 
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid_addr[6];
    uint16_t sequence_number;
} dot11_header;

typedef struct _deauth_fixed_parameter {
    uint16_t reason_code;
} deauth_f_param;

typedef struct _auth_fixed_parameter {
    uint16_t auth_algorithm;
    uint16_t auth_SEQ;
    uint16_t status_code;
} auth_f_param;

typedef struct _auth_tagged_parameter { // 필요없음
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t OUI[3];
    uint8_t VS_OUI_type;
    uint8_t VS_Data[6];
} auth_t_param;

// + add tag_num_value to input hex value in proper addr offset

enum tag_num_value {
		TagSsidParameterSet = 0,
		TagSupportedRated = 1,
		TagDsParameterSet = 3,
		TagTrafficIndicationMap = 5,
		TagCountryInformation = 7,
		TagQbssLoadElement = 11,
		TagHtCapabilities = 45,
		TagRsnInformation = 48,
		TagHtInformation = 61,
		TagVendorSpecific = 221
};


#pragma pack(pop)

#endif
