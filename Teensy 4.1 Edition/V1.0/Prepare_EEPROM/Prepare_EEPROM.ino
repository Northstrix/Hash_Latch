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

#define GREEN_LED 20
#define RED_LED 19

void setup()
{
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, HIGH);
  for ( unsigned int i = 0 ; i < EEPROM.length() ; i++ )
    EEPROM.write(i, 0);

  for ( unsigned int i = 0 ; i < 10 ; i++ )
    EEPROM.write(i, 31);

  String check_data;

  for (int i = 0; i < 10; i++){
    check_data += char (EEPROM.read(i) + 18);
  }

  if (check_data.equals("1111111111")){
    digitalWrite(GREEN_LED, HIGH);
    digitalWrite(RED_LED, LOW);
  }
  else{
    digitalWrite(GREEN_LED, LOW);
    digitalWrite(RED_LED, HIGH);
  }
}

void loop() { } 
