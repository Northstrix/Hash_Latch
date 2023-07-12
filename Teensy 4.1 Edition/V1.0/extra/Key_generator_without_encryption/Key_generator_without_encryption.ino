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
#include <EEPROM.h>
#include "sha512.h"

#define GREEN_LED 20
#define RED_LED 19
#define MODE_BUTTON_PIN 22
#define EXIT_KEY_GEN_MODE_DELAY 300

String spart = "Some random stuff here";

const char right_prefix[5] = {'0', '0', '0', '0', '0'};

void GenToken(){
  Serial.println("Generating keys...");
  String tkn;
  int a = EEPROM.read(0);
  int b = EEPROM.read(1);
  int c = EEPROM.read(2);
  int d = EEPROM.read(3);
  int e = EEPROM.read(4);
  int f = EEPROM.read(5);
  int g = EEPROM.read(6);
  int j = EEPROM.read(7);
  int k = EEPROM.read(8);
  int l = EEPROM.read(9);
  
  Serial.println();
  Serial.print(a);
  Serial.print(" ");
  Serial.print(b);
  Serial.print(" ");
  Serial.print(c);
  Serial.print(" ");
  Serial.print(d);
  Serial.print(" ");
  Serial.print(e);
  Serial.print(" ");
  Serial.print(f);
  Serial.print(" ");
  Serial.print(g);
  Serial.print(" ");
  Serial.print(j);
  Serial.print(" ");
  Serial.print(k);
  Serial.print(" ");
  Serial.println(l);
  
  while(1){
    tkn = "";
    if (a > 31)
      tkn += char(a);
    if (b > 31)
      tkn += char(b);
    if (c > 31)
      tkn += char(c);
    if (d > 31)
      tkn += char(d);
    if (e > 31)
      tkn += char(e);
    if (f > 31)
      tkn += char(f);
    if (g > 31)
      tkn += char(g);
    if (j > 31)
      tkn += char(j);
    if (k > 31)
      tkn += char(k);
    if (l > 31)
      tkn += char(l);
    tkn += spart;
    int str_len = tkn.length() + 1;
    char input_arr[str_len];
    tkn.toCharArray(input_arr, str_len);
    std::string str = "";
    if(str_len > 1){
      for(int i = 0; i<str_len-1; i++){
        str += input_arr[i];
      }
    }
    String h = sha512( str ).c_str();
    char h_arr[129];
    h.toCharArray(h_arr, 129);
    if (h_arr[0] == right_prefix[0] && h_arr[1] == right_prefix[1] && h_arr[2] == right_prefix[2] && h_arr[3] == right_prefix[3] && h_arr[4] == right_prefix[4]){
      digitalWrite(GREEN_LED, HIGH);
      digitalWrite(RED_LED, LOW);
      Serial.println();
      Serial.println("Got a key:");
      Serial.println(tkn);
      Serial.println();
      
      for (int i = 0; i<128; i++){
        Serial.print(h_arr[i]);
      }
      Serial.println();
      
    }
    a++;
    if (a > 126){
      a = 32;
      b++;
    }
    if (b > 126){
      b = 32;
      c++;
    }
    if (c > 126){
      c = 32;
      d++;
    }
    if (d > 126){
      d = 32;
      e++;
    }
    if (e > 126){
      e = 32;
      f++;
    }
    if (f > 126){
      f = 32;
      g++;
    }
    if (g > 126){
      g = 32;
      j++;
    }
    if (j > 126){
      j = 32;
      k++;
    }
    if (k > 126){
      k = 32;
      l++;
    }
    if (l > 126){
      Serial.println("No more combinations to try!");
      EEPROM.write(0, a);
      EEPROM.write(1, b);
      EEPROM.write(2, c);
      EEPROM.write(3, d);
      EEPROM.write(4, e);
      EEPROM.write(5, f);
      EEPROM.write(6, g);
      EEPROM.write(7, j);
      EEPROM.write(8, k);
      EEPROM.write(9, l);
      break;
    }
    if (digitalRead(MODE_BUTTON_PIN) == LOW){
      delay(EXIT_KEY_GEN_MODE_DELAY);
      if (digitalRead(MODE_BUTTON_PIN) == LOW){
        Serial.println("Key generation process ended by user.");
        Serial.print(a);
        Serial.print(" ");
        Serial.print(b);
        Serial.print(" ");
        Serial.print(c);
        Serial.print(" ");
        Serial.print(d);
        Serial.print(" ");
        Serial.print(e);
        Serial.print(" ");
        Serial.print(f);
        Serial.print(" ");
        Serial.print(g);
        Serial.print(" ");
        Serial.print(j);
        Serial.print(" ");
        Serial.print(k);
        Serial.print(" ");
        Serial.println(l);
        
        EEPROM.write(0, a);
        EEPROM.write(1, b);
        EEPROM.write(2, c);
        EEPROM.write(3, d);
        EEPROM.write(4, e);
        EEPROM.write(5, f);
        EEPROM.write(6, g);
        EEPROM.write(7, j);
        EEPROM.write(8, k);
        EEPROM.write(9, l);
        break;
      }
    }
  }
}

void setup()
{
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(MODE_BUTTON_PIN, INPUT);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, HIGH);
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect.
  }
  GenToken();
}

void loop() { } 
