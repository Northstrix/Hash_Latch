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
#include <Servo.h> 
 
Servo Latch;

#define LATCH_PIN 23
#define OPEN_ANGLE 0
#define CLSD_ANGLE 180

void open_latch(){
  Latch.write(OPEN_ANGLE);
}

void close_latch(){
  Latch.write(CLSD_ANGLE); 
}
 
void setup() 
{ 
  Latch.attach(LATCH_PIN);
  close_latch();
} 
 
void loop() 
{ 
  close_latch();
  delay(1000);
  open_latch();
  delay(1000);
} 
