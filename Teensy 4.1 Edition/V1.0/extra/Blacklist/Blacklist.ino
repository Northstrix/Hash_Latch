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

void blacklist_key(int slot_num, String blkey){
  if (slot_num < 1 || slot_num > NUMBER_OF_SLOTS_FOR_BLACKLIST){
    Serial.print("Incorrect number. Enter the number between 1 and ");
    Serial.println(NUMBER_OF_SLOTS_FOR_BLACKLIST);
  }
  else{
    int data_to_write[10];
    for (int i = 0; i < 10; i++){
       data_to_write[i] = 0;
    }
    int key_len = blkey.length();
    for (int i = 0; i < key_len; i++){
      int chr_at_i = int(blkey.charAt(i)); 
      if (chr_at_i > 31 && chr_at_i < 127)
        data_to_write[i] = chr_at_i;
    }
    for (int i = 0; i < 10; i++){
      EEPROM.write((10 *  slot_num) + i, data_to_write[i]);
    }
  }
}

void add_key_to_slot_in_the_blacklist(String blkey){
  Serial.println("\nChoose the slot to put the blacklisted key into. Enter 'c' to cancel.");
  print_content_of_all_slots_to_serial();
  while (!Serial.available()) {}
  String slot = Serial.readString();
  if (slot.charAt(0) == 'c' || slot.charAt(0) == 'C'){
    Serial.println("Operation was canceled by user. No key was blacklisted.");
  }
  else{
    blacklist_key(slot.toInt(), blkey);
  }
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect.
  }
  add_key_to_slot_in_the_blacklist("abc");
}

void loop() { } 
