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

#define NUMBER_OF_SLOTS_FOR_BLACKLIST 100
int read_data[10];
int read_val;

String get_content_of_a_slot(int slot_num){
  for (int i = 0; i < 10; i++){
    read_data[i] = EEPROM.read((10 *  slot_num) + i);
  }
  if (read_data[0] == 0 && read_data[1] == 0 && read_data[2] == 0 && read_data[3] == 0 && read_data[4] == 0 && read_data[5] == 0 && read_data[6] == 0 && read_data[7] == 0 && read_data[8] == 0 && read_data[9] == 0)
  {
    return "Empty";
  }
  else{
    String data_in_the_slot = "\"";
    for (int i = 0; i < 10; i++){
      read_val = read_data[i];
      if (read_val > 31){
        data_in_the_slot += char(read_val);
      }
    }
    data_in_the_slot += "\"";
    return data_in_the_slot;
  }
}

void print_content_of_all_slots_to_serial(){
  Serial.println();
  for (int i = 0; i < NUMBER_OF_SLOTS_FOR_BLACKLIST; i++){
    Serial.print(i + 1);
    Serial.print(".");
    Serial.println(get_content_of_a_slot(i + 1)); // Slot numeration starts from one
  }
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect.
  }
  print_content_of_all_slots_to_serial();
}

void loop() { } 
