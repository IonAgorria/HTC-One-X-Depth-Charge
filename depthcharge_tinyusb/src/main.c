#include <stdio.h>

#include "bsp/board.h"
#include "tusb.h"
#include "device/usbd_pvt.h"
#include "pico/bootrom.h"


//--------------------------------------------------------------------+
// TASKS
//--------------------------------------------------------------------+

static uint32_t led_start_ms = 0;
static uint32_t led_interval_ms = 0;

void led_set(bool state, uint32_t time) {
    if (state) {
        led_start_ms = board_millis();
        led_interval_ms = time;
    } else {
        led_start_ms = 0;
        led_interval_ms = 0;
    }

    board_led_write(state);
}


void led_task() {
    if (led_start_ms && led_interval_ms && board_millis() - led_start_ms > led_interval_ms) {
        led_start_ms = 0;
        led_interval_ms = 0;
        board_led_write(false);
    }
}

void bootloader_task() {
    if (board_button_read()) {
        printf("Pressed button\n");
        led_set(true, 600);
        sleep_ms(200);
#if CFG_TUSB_MCU == OPT_MCU_RP2040
        //Enter BOOTSEL mode
        reset_usb_boot(0, 0);
#endif
    }
}

/*------------- MAIN -------------*/
int main(void)
{
  board_init();

  led_set(true, 500);
  printf("DepthCharge " DEPTHCHARGE_VERSION "\n\n");

  // init device stack on configured roothub port
  tud_init(BOARD_TUD_RHPORT);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
  while (1)
  {
    bootloader_task();
    tud_task(); // tinyusb device task
    led_task();
  }
#pragma clang diagnostic pop

  return 0;
}

//--------------------------------------------------------------------+
// Device callbacks
//--------------------------------------------------------------------+

// Invoked when device is mounted
void tud_mount_cb() {
}

// Invoked when device is unmounted
void tud_umount_cb() {
}

// Invoked when usb bus is suspended
// remote_wakeup_en : if host allow us  to perform remote wakeup
// Within 7ms, device must draw an average of current less than 2.5 mA from bus
void tud_suspend_cb(bool remote_wakeup_en) {
  (void) remote_wakeup_en;
}

// Invoked when usb bus is resumed
void tud_resume_cb() {
}