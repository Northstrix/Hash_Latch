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
#include <PS2KeyAdvanced.h>
#define SHOW_KEYBOARD_DATA

#define DATAPIN 16
#define IRQPIN 17

uint16_t c;
String keyboard_input;
int curr_key;
int prsd_key;
bool finish_input;
bool usb_keyb_inp;

PS2KeyAdvanced keyboard;

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

void setup() {
  myusb.begin();
  keyboard1.attachPress(OnPress);
  keyboard.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect.
  }
  Serial.println("Input Test:");
}

void loop() {
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
    
    if (prsd_key == 10) { // Enter
      Serial.println("Enter");
      keyboard_input = "";
    }
    
  }
  delayMicroseconds(400);
  if (keyboard.available()) {
    // read the next key
    c = keyboard.read();
    if (c > 0 && ((c & 0xFF) != 6)) {
      /*
      if (c & PS2_BREAK) Serial.print("break ~ ");
      if (!(c & PS2_BREAK)) Serial.print("make  ~ ");
      Serial.print( "Value " );
      Serial.print( c, HEX );
      Serial.print( " - Status Bits " );
      Serial.print( c >> 8, HEX );
      Serial.print( "  Code " );
      Serial.println( c & 0xFF, HEX );
      if (!(c & PS2_BREAK))
        Serial.println(char(c & 0xFF));
      */

      if (c >> 8 == 192 && (c & PS2_BREAK)) {
        if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Capital letters
          keyboard_input += (char(c & 0xFF));

        if ((c & 0xFF) == 93)
          keyboard_input += ("{");

        if ((c & 0xFF) == 94)
          keyboard_input += ("}");

        if ((c & 0xFF) == 91)
          keyboard_input += (":");

        if ((c & 0xFF) == 58)
          keyboard_input += (char(34)); // "

        if ((c & 0xFF) == 92)
          keyboard_input += ("|");

        if ((c & 0xFF) == 59)
          keyboard_input += ("<");

        if ((c & 0xFF) == 61)
          keyboard_input += (">");

        if ((c & 0xFF) == 62)
          keyboard_input += ("?");

        if ((c & 0xFF) == 64)
          keyboard_input += ("~");

        if ((c & 0xFF) == 60)
          keyboard_input += ("_");

        if ((c & 0xFF) == 95)
          keyboard_input += ("+");

        if ((c & 0xFF) == 49)
          keyboard_input += ("!");

        if ((c & 0xFF) == 50)
          keyboard_input += ("@");

        if ((c & 0xFF) == 51)
          keyboard_input += ("#");

        if ((c & 0xFF) == 52)
          keyboard_input += ("$");

        if ((c & 0xFF) == 53)
          keyboard_input += ("%");

        if ((c & 0xFF) == 54)
          keyboard_input += ("^");

        if ((c & 0xFF) == 55)
          keyboard_input += ("&");

        if ((c & 0xFF) == 56)
          keyboard_input += ("*");

        if ((c & 0xFF) == 57)
          keyboard_input += ("(");

        if ((c & 0xFF) == 48)
          keyboard_input += (")");

      }
      if (c >> 8 == 129 && (c & PS2_BREAK)) {

        if ((c & 0xFF) == 30){ // Enter
          Serial.println("Enter");
        }

        if ((c & 0xFF) == 27)
          Serial.println("Escape");

        if (c == 33047)
          Serial.println("UP");

        if (c == 33046)
          Serial.println("RIGHT");

        if (c == 33048)
          Serial.println("DOWN");

        if (c == 33045)
          Serial.println("LEFT");
          
        if (c == 33053)
          Serial.println("TAB");

        if (c == 33055)
          keyboard_input += (" "); // Space

        if (c == 33052) { // Backspace
          if (keyboard_input.length() > 0)
            keyboard_input.remove(keyboard_input.length() - 1, 1);
        }
      }
      if (c >> 8 == 128 && (c & PS2_BREAK)) {

        if ((c & 0xFF) > 48 && (c & 0xFF) < 58) // Digits
          keyboard_input += (char((c & 0xFF)));

        if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
          keyboard_input += (char((c & 0xFF) + 32));

        if ((c & 0xFF) == 93)
          keyboard_input += ("[");

        if ((c & 0xFF) == 94)
          keyboard_input += ("]");

        if ((c & 0xFF) == 91)
          keyboard_input += (";");

        if ((c & 0xFF) == 58)
          keyboard_input += ("'");

        if ((c & 0xFF) == 92)
          keyboard_input += ("\\");

        if ((c & 0xFF) == 59)
          keyboard_input += (",");

        if ((c & 0xFF) == 61)
          keyboard_input += (".");

        if ((c & 0xFF) == 62)
          keyboard_input += ("/");

        if ((c & 0xFF) == 64)
          keyboard_input += ("`");

        if ((c & 0xFF) == 60)
          keyboard_input += ("-");

        if ((c & 0xFF) == 95)
          keyboard_input += ("=");

      }
      Serial.println(keyboard_input);
    }
  }
  delayMicroseconds(400);
}
