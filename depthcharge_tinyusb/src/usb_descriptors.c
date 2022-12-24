#include "tusb.h"

//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+

tusb_desc_device_t const desc_device =
{
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = 0xDEAD,
    .idProduct          = 0xB001,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

#define DEV_DESC_BUF_LEN (sizeof(desc_device))
uint8_t dev_desc_fs_buf[DEV_DESC_BUF_LEN];

// Invoked when received GET DEVICE DESCRIPTOR
// Application return pointer to descriptor
uint8_t const * tud_descriptor_device_cb(void) {
    printf("tud_descriptor_device_cb\n");
    memset(dev_desc_fs_buf, 0xBC, DEV_DESC_BUF_LEN);
    memcpy(dev_desc_fs_buf, &desc_device, sizeof(desc_device));
    return dev_desc_fs_buf;
}

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

enum
{
  ITF_NUM_MSC = 0,
  ITF_NUM_TOTAL = 1
};

#define CONFIG_MSC_DESC_LEN    (TUD_CONFIG_DESC_LEN + TUD_MSC_DESC_LEN)

#if CFG_TUSB_MCU == OPT_MCU_LPC175X_6X || CFG_TUSB_MCU == OPT_MCU_LPC177X_8X || CFG_TUSB_MCU == OPT_MCU_LPC40XX
  // LPC 17xx and 40xx endpoint type (bulk/interrupt/iso) are fixed by its number
  //  0 control, 1 In, 2 Bulk, 3 Iso, 4 In, 5 Bulk etc ...
  #define EPNUM_MSC_OUT   0x02
  #define EPNUM_MSC_IN    0x82

#elif CFG_TUSB_MCU == OPT_MCU_SAMG
  // SAMG doesn't support a same endpoint number with different direction IN and OUT
  //  e.g EP1 OUT & EP1 IN cannot exist together
  #define EPNUM_MSC_OUT   0x01
  #define EPNUM_MSC_IN    0x82

#else
  #define EPNUM_MSC_OUT   0x01
  #define EPNUM_MSC_IN    0x81

#endif  

#define EP_MSC(_ep) 7, TUSB_DESC_ENDPOINT, _ep, TUSB_XFER_BULK, U16_TO_U8S_LE(64), 0
#define EP_NUM 2

//The offset when config_desc is copied into main buffer
#define HBOOT_ENUMDESC_CONFIG_DESC_OFFSET 0x12
#define HBOOT_ENUMDESC_LEN 0xB4
#define HBOOT_MALLOC_OFFSET 0x4
#define HBOOT_TARGET_PTR 4
#define CONFIG_DESC_BUF_LEN (HBOOT_ENUMDESC_LEN - HBOOT_ENUMDESC_CONFIG_DESC_OFFSET + HBOOT_MALLOC_OFFSET + HBOOT_TARGET_PTR)

/*
 * 
// Interface number, string index, EP Out & EP In address, EP size
#define TUD_MSC_DESCRIPTOR(_itfnum, _stridx, _epout, _epin, _epsize) \
 
  9, TUSB_DESC_INTERFACE, _itfnum, 0, 2, TUSB_CLASS_MSC, MSC_SUBCLASS_SCSI, MSC_PROTOCOL_BOT, _stridx,\
  
  7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0,\
  
  7, TUSB_DESC_ENDPOINT, _epin, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0
 */

uint8_t const desc_fs_configuration[] = {
  // Config descriptor
  // 0x00 len, 0x01 type, 0x02-0x03 total length, 0x04 interface count,
  // 0x05 config number, 0x06 string index, 0x07 attribute, 0x08 power in mA
  TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_MSC_DESC_LEN, 0x00, 100),
  // 0x09 len, 0x0A type, 0x0B Interface number, 0x0C ?, 0x0D EP count,
  9, TUSB_DESC_INTERFACE, 0, 0, EP_NUM,

  // Interface descriptor
  // 0x0E Class, 0x0F Subclass, 0x10 Protocol, 0x11 string index,
  TUSB_CLASS_MSC, MSC_SUBCLASS_SCSI, MSC_PROTOCOL_BOT, 0,
  
  //Endpoint Descriptors
  // 0x12 len, 0x13 type, 0x14 EP Out addr, 0x15 bmAttributes, 0x16-0x17 EP size, 0x18 ?
  EP_MSC(EPNUM_MSC_OUT),
  // 0x19 len, 0x1A type, 0x1B EP In addr, 0x1C bmAttributes, 0x1D-0x1E EP size, 0x1F bInterval
  EP_MSC(EPNUM_MSC_IN),
};
TU_VERIFY_STATIC(sizeof(desc_fs_configuration) == CONFIG_MSC_DESC_LEN, "size is not correct");

uint8_t config_desc_fs_buf[CONFIG_DESC_BUF_LEN];

// Invoked when received GET CONFIGURATION DESCRIPTOR
// Application return pointer to descriptor
// Descriptor contents must exist long enough for transfer to complete
uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
    (void) index; // for multiple configurations
    printf("tud_descriptor_configuration_cb: %d\n", index);

    memset(config_desc_fs_buf, 0x0, CONFIG_DESC_BUF_LEN);
    memcpy(config_desc_fs_buf, &desc_fs_configuration, sizeof(desc_fs_configuration));

    //0xB4 buffer content    
    config_desc_fs_buf[0x9A] = 0x10;
    config_desc_fs_buf[0x9B] = 0x26;
    config_desc_fs_buf[0x9C] = 0x2;
    config_desc_fs_buf[0x9D] = 0x40;
    config_desc_fs_buf[0x9E] = 0x1;
    //0xB4 buffer end    

    //0xC buffer metadata?
    config_desc_fs_buf[0xA2] = 0x13;
    config_desc_fs_buf[0xA3] = 0x1F;
    config_desc_fs_buf[0xA4] = 0x0;
    config_desc_fs_buf[0xA5] = 0x0;
    //0xC buffer content
    *(uint32_t*) &config_desc_fs_buf[0xA6] = DEPTHCHARGE_POINTER_VALUE;
    
    //Fix desc len
    uint16_t len = CONFIG_DESC_BUF_LEN;
    config_desc_fs_buf[0x2] = TU_U16_LOW(len);
    config_desc_fs_buf[0x3] = TU_U16_HIGH(len);
    
    return config_desc_fs_buf;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

// 0: is supported language is English (0x0409)
const char string_desc_langid[] = { 0x09, 0x04 };

#define MAX_STRING_LEN_DESC 20
#define MAX_STRING_LEN_HEADER 2
//UTF16 so 2 bytes per char + 2 header bytes
static uint16_t desc_str_buf[MAX_STRING_LEN_DESC + MAX_STRING_LEN_HEADER];

// Invoked when received GET STRING DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;
    printf("tud_descriptor_string_cb: %d %d\n", index, langid);

    if ( index == 0) {
        memcpy(&desc_str_buf[1], string_desc_langid, sizeof(string_desc_langid));
        desc_str_buf[0] = MAX_STRING_LEN_HEADER + sizeof(string_desc_langid);
    } else {
        // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors
        if (index > 3) return NULL;
    
        // Add UTF-16 "chars"
        const char* text = "DepthCharge " DEPTHCHARGE_VERSION;
        desc_str_buf[0] = (uint16_t) strlen(text);

        for(size_t i=1; i < MAX_STRING_LEN_DESC - MAX_STRING_LEN_HEADER; i++) {
            desc_str_buf[i] = text[i-1];
            if (i-1 >= desc_str_buf[0]) break;
        }

        desc_str_buf[0] = (uint16_t) (desc_str_buf[0] * 2 + MAX_STRING_LEN_HEADER);
    }
  
    //second byte is string type
    desc_str_buf[0] = desc_str_buf[0] | (TUSB_DESC_STRING << 8);

    return desc_str_buf;
}
