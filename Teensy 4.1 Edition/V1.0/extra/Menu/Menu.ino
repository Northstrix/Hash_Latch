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
void setup() {
  Serial.begin(115200);

}

void loop() {
  Serial.println();
  Serial.println("What do you want to do?");
  Serial.println("1.Generate keys");
  Serial.println("2.Blacklist the key");
  Serial.println("3.Test a key");
  Serial.println("4.Encrypt string with 3DES + AES-256 + Blowfish + Serpent in CBC mode");
  Serial.println("5.Decrypt string with 3DES + AES-256 + Blowfish + Serpent in CBC mode");
  Serial.println("6.Close lock");
  Serial.println("7.Open lock");
  while (!Serial.available()) {}
  int x = Serial.parseInt();

}
