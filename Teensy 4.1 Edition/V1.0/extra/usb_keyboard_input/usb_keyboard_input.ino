/*
Hash Latch
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://github.com/Northstrix/Hash_Latch
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/arduino-libraries/Servo
*/
#include "USBHost_t36.h"
#define SHOW_KEYBOARD_DATA

String keyboard_input;
int curr_key;
int prsd_key;
bool finish_input;
bool usb_keyb_inp;

USBHost myusb;
USBHub hub1(myusb);
KeyboardController keyboard1(myusb);

USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);

uint8_t keyboard_modifiers = 0;  // try to keep a reasonable value
#ifdef KEYBOARD_INTERFACE
uint8_t keyboard_last_leds = 0;
#endif

void OnPress(int key) {
  prsd_key = key;
  usb_keyb_inp = true;
}

void get_input() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        Serial.println(keyboard_input);
      }

      if (prsd_key == 10) {
        finish_input = true;
      }
    }
    delayMicroseconds(400);
  }
}

void setup() {
  myusb.begin();
  keyboard1.attachPress(OnPress);
  Serial.begin(115200);
  Serial.println("Input Test:");
}

void loop() {
  keyboard_input = "";
  get_input();
  if (finish_input == true) {
    Serial.println("Continue");
    Serial.println(keyboard_input);
  }
}
