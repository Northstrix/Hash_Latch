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
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include <Servo.h>
#include "USBHost_t36.h"
#include <PS2KeyAdvanced.h>
#define SHOW_KEYBOARD_DATA

#define DATAPIN 16
#define IRQPIN 17

Servo Latch;

#define GREEN_LED 20
#define RED_LED 19
#define MODE_BUTTON_PIN 22
#define UNLOCK_BUTTON_PIN 21
#define EXIT_KEY_GEN_MODE_DELAY 300
#define TRNG_ENT_COUNT 16
#define LATCH_PIN 23
#define OPEN_ANGLE 0
#define CLSD_ANGLE 180
#define OPEN_FOR 7000
#define TYPE_DELAY 17
#define NUMBER_OF_SLOTS_FOR_BLACKLIST 100

uint16_t c;
String keyboard_input;
int curr_key;
int prsd_key;
bool finish_input;
bool usb_keyb_inp;

DES des;
Blowfish blowfish;

int m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
bool decrypt_tag;
static uint32_t rng_index;
bool chsn_md;
int read_data[10];
int read_val;

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

// Keys (Below)

String spart = "R45XQHo6H73SlFy0803XQg72I2eVPU";
const char right_prefix[5] = {'0', '0', '0', '0', '0'};
byte hmackey[] = {"TlAX0Jo0L24J6t2hTZh39i18U1aJ8yRV0ozJuph6BaI0O05gH9pEhsx06Uj8T88D2R1fLNAsm7N46U5n1N9CFJ284904epY1ONor7Z025"};
byte des_key[] = {
0xa8,0x40,0xfe,0xae,0x50,0x01,0xf5,0xe7,
0xc5,0xe4,0x73,0xa2,0xc5,0x90,0xad,0x68,
0xfd,0x41,0x7d,0xfe,0xcd,0x9e,0xeb,0xe8
};
uint8_t AES_key[32] = {
0xcf,0xa0,0x38,0xfb,
0x8b,0x3d,0x74,0x83,
0xcf,0x7b,0x5b,0x1b,
0x14,0xbd,0xbe,0xf1,
0xf2,0x6a,0xb0,0xfc,
0xe9,0xd4,0xd9,0xd5,
0xd0,0x83,0x24,0xff,
0x63,0xfd,0xe5,0xf6
};
unsigned char Blwfsh_key[] = {
0x75,0xca,0xa2,0x1e,
0x13,0x4f,0xfb,0xfa,
0xac,0x86,0x6b,0x1b,
0x7a,0x9b,0xb0,0xf0,
0x5e,0x3a,0x0b,0xb8,
0xe4,0xa6,0xad,0xcc
};
uint8_t serp_key[32] = {
0x1e,0x42,0x35,0x9a,
0x6b,0x0c,0x75,0xb6,
0xf8,0x7a,0x6a,0x5d,
0x7b,0xff,0xf3,0x69,
0x7f,0x5f,0x0f,0x93,
0x43,0xcd,0xff,0xf7,
0xce,0x4e,0x36,0xeb,
0x47,0x03,0x5b,0x20
};

// Keys (Above)

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

void OnPress(int key) {
  prsd_key = key;
  usb_keyb_inp = true;
}

void trng_init() {
  CCM_CCGR6 |= CCM_CCGR6_TRNG(CCM_CCGR_ON);
  TRNG_MCTL = TRNG_MCTL_RST_DEF | TRNG_MCTL_PRGM; // reset to program mode
  TRNG_MCTL = TRNG_MCTL_SAMP_MODE(2); // start run mode, vonneumann
  TRNG_ENT15; // discard any stale data, start gen cycle
}

uint32_t trng_word() {
  uint32_t r;
  while ((TRNG_MCTL & TRNG_MCTL_ENT_VAL) == 0 &
         (TRNG_MCTL & TRNG_MCTL_ERR) == 0) ; // wait for entropy ready
  r = *(&TRNG_ENT0 + rng_index++);
  if (rng_index >= TRNG_ENT_COUNT) rng_index = 0;
  return r;
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
}

void clear_variables() {
  keyboard_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 10; i++){
    array_for_CBC_mode[i] = trng_word() % 256;
  }
  
  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = trng_word() % 256;
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
     if (decract > 0){
        if (i < 10){
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }  
     }
     if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }
  
  if (br == false) {
    if(decract > 10){
      for (int i = 0; i < 10; i++){
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        //if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
      int c = int(rh[i]);
      cipher_text[i + 8] = c;
    }
    /*
    for (int i=0; i<16; i++) {
      if(cipher_text[i]<16)
        Serial.print("0");
      Serial.print(cipher_text[i],HEX);
    }
    Serial.println();
    */
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (int i = 0; i < 8; i++){
        out[i] ^= array_for_CBC_mode[i];
      }
      
      for (int i = 0; i < 2; i++){
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false){
      
      for (i = 0; i < 8; ++i) {
        if (out[i] > 0)
          dec_st += char(out[i]);
      }

      for (i = 0; i < 2; ++i) {
        if (out2[i] > 0)
          dec_st += char(out2[i]);
      }

      }

      else{
      for (i = 0; i < 8; ++i) {
        if (out[i] < 0x10)
          dec_tag += "0";
        dec_tag += String(out[i], HEX);
      }

      for (i = 0; i < 2; ++i) {
        if (out2[i] < 0x10)
          dec_tag += "0";
        dec_tag += String(out2[i], HEX);
      }
      }
    }

    if (decract == -1){
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encr_hash_for_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i+=32){
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
  
  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

void GenToken(){
  Serial.println("");
  Serial.println("Generating keys...");
  Serial.println("It might take a while");
  Serial.println("Press the \"Mode Button\" to stop the key generation process.");
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
  /*
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
  */
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
      //digitalWrite(GREEN_LED, HIGH);
      //digitalWrite(RED_LED, LOW);
      Serial.println();
      encrypt_string_with_tdes_aes_blf_srp(tkn);
      Serial.println(dec_st);
      /*
      Serial.print("Decrypted:\"");
      decrypt_string_with_TDES_AES_Blowfish_Serp(dec_st);
      Serial.print(dec_st);
      Serial.println("\"");
      */
      /*
      for (int i = 0; i<128; i++){
        Serial.print(h_arr[i]);
      }
      Serial.println();
      */
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
        /*
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
        */
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

void add_key_to_slot_in_the_blacklist(){
  Serial.println("\nPaste the key you'd like to blacklist");
  while (!Serial.available()) {}
  String blkey = Serial.readString();
  decrypt_string_with_TDES_AES_Blowfish_Serp(blkey);
  int spart_len = spart.length();
  int diffrn = dec_st.length() - spart_len;
  String extr_pref;
  for (int i = 0; i < diffrn; i++){
     extr_pref += dec_st.charAt(i);
  }
  Serial.println("Choose the slot to put the blacklisted key into. Enter 'c' to cancel.");
  print_content_of_all_slots_to_serial();
  while (!Serial.available()) {}
  String slot = Serial.readString();
  if (slot.charAt(0) == 'c' || slot.charAt(0) == 'C'){
    Serial.println("Operation was canceled by user. No key was blacklisted.");
  }
  else{
    blacklist_key(slot.toInt(), extr_pref);
  }
}

void type_on_virtual_keyboard(String data_to_type){
  int lng = data_to_type.length();
  for (int i = 0; i < lng; i++){
    Keyboard.print(data_to_type.charAt(i));
    delay(TYPE_DELAY);
  }
}

void open_the_latch(String ct){
  decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
  String tkn = dec_st;
  bool plt_integr = verify_integrity();
  if (plt_integr == true){ // Integrity of the decrypted key (plaintext) verified successfully
    //Serial.println(dec_st);
    int spart_len = spart.length();
    int diffrn = dec_st.length() - spart_len;
    if (diffrn > 10){
      type_inscription_with_date("The key is too long. Failed to open the lock with the invalid key");
    }
    else{
      int crct = 1;
      for (int i = 0; i < spart_len; i++) {
        if (spart.charAt(i) == dec_st.charAt(i + diffrn)){
          crct *= 1;
        }
        else{
          crct = -1;
        }
      }
      if (crct == -1){ // Incorrect second part of the key 
        type_inscription_with_date("Incorrect second part of the key. Failed to open the lock with the invalid key");
      }
      else{
        String extr_pref;
        for (int i = 0; i < diffrn; i++){
          extr_pref += dec_st.charAt(i);
        }
        //Serial.println(extr_pref);
        bool blcklstd = check_blacklist(extr_pref); // Check if the key is blacklisted
        if (blcklstd == true){ // The key is blacklisted
          String fld_to_open = "Failed to open the lock with the blacklisted key \"" + extr_pref + "\"";
          type_inscription_with_date(fld_to_open);
        }
        else{
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
            String opened_with_s = "The lock opened successfully with the key \"" + extr_pref + "\"";
            type_inscription_with_date(opened_with_s);
            open_latch_for_a_while();
          }
          else{
            type_inscription_with_date("Incorrect leading part of the hash. Failed to open the lock with the invalid key");
          }
        }
      }
    }
  }
  else{ // Failed to verify the integrity of the decrypted key (plaintext)
    //Serial.println("Integrity Verification failed!!!");
    type_inscription_with_date("Failed to open the lock with the broken key");
  }
  clear_variables();
  return;
}

bool check_blacklist(String suspect_key){
  bool blacklisted = false;
  for (int i = 0; i < NUMBER_OF_SLOTS_FOR_BLACKLIST; i++){
    //Serial.println(i + 1);
    String extr_key = get_content_of_a_slot_for_bl(i + 1);
    if (suspect_key.equals(extr_key)){
      blacklisted = true;
      break;
    }
  }
  return blacklisted;
}

String get_content_of_a_slot_for_bl(int slot_num){
  for (int i = 0; i < 10; i++){
    read_data[i] = EEPROM.read((10 *  slot_num) + i);
  }
  String data_in_the_slot;
  for (int i = 0; i < 10; i++){
    read_val = read_data[i];
    if (read_val > 31){
      data_in_the_slot += char(read_val);
    }
  }
  return data_in_the_slot;
}

void type_inscription_with_date(String inscr){
  type_on_virtual_keyboard(inscr);
  type_on_virtual_keyboard( + " at ");
  Keyboard.set_modifier(MODIFIERKEY_SHIFT | MODIFIERKEY_ALT);
  Keyboard.set_key1(KEY_T);
  Keyboard.send_now();
  delay(17);
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now();
  delay(17);
  type_on_virtual_keyboard(" on ");
  Keyboard.set_modifier(MODIFIERKEY_SHIFT | MODIFIERKEY_ALT);
  Keyboard.set_key1(KEY_D);
  Keyboard.send_now();
  delay(17);
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now();
  delay(17);
  Keyboard.set_key1(KEY_ENTER);
  Keyboard.send_now();
  delay(17);
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now(); 
}

void open_latch(){
  Latch.write(OPEN_ANGLE);
}

void close_latch(){
  Latch.write(CLSD_ANGLE); 
}

void open_latch_for_a_while(){
  open_latch();
  digitalWrite(GREEN_LED, HIGH);
  digitalWrite(RED_LED, LOW);
  delay(OPEN_FOR);
  close_latch();
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, HIGH);
}

void test_key(){
   Serial.println("\nPaste the encrypted key here:");
   while (!Serial.available()) {
  }
  String ct = Serial.readString();
  decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
  String tkn = dec_st;
  bool plt_integr = verify_integrity();
  if (plt_integr == true){ // Integrity of the decrypted key (plaintext) verified successfully
    //Serial.println(dec_st);
    int spart_len = spart.length();
    int diffrn = dec_st.length() - spart_len;
    if (diffrn > 10){
      Serial.println("The key is too long. The lock won't open with that key.");
    }
    else{
      int crct = 1;
      for (int i = 0; i < spart_len; i++) {
        if (spart.charAt(i) == dec_st.charAt(i + diffrn)){
          crct *= 1;
        }
        else{
          crct = -1;
        }
      }
      if (crct == -1){ // Incorrect second part of the key 
        Serial.println("Incorrect second part of the key. The lock won't open with that key.");
      }
      else{
        String extr_pref;
        for (int i = 0; i < diffrn; i++){
          extr_pref += dec_st.charAt(i);
        }
        //Serial.println(extr_pref);
        bool blcklstd = check_blacklist(extr_pref); // Check if the key is blacklisted
        if (blcklstd == true){ // The key is blacklisted
          String fld_to_open = "The lock won't open with the blacklisted key \"" + extr_pref + "\"";
          Serial.println(fld_to_open);
        }
        else{
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
            String opened_with_s = "The key \"" + extr_pref + "\" is valid. You should be able to open the lock with that key.";
            Serial.println(opened_with_s);
          }
          else{
            Serial.println("Incorrect leading part of the hash. The lock won't open with that key.");
          }
        }
      }
    }
  }
  else{ // Failed to verify the integrity of the decrypted key (plaintext)
    Serial.println("Integrity Verification failed!!! The lock won't open with that key.");
  }
  clear_variables();
  return;
}

void lock_mode(){
  myusb.Task();
  if (usb_keyb_inp == true) {
    usb_keyb_inp = false;
    if (prsd_key == 127) {
      keyboard_input = "";
    }

    if (prsd_key > 31 && prsd_key < 127) {
      curr_key = prsd_key;
      keyboard_input += char(curr_key);
    }
    
    if (prsd_key == 10) { // Enter
      //Serial.println(keyboard_input);
      open_the_latch(keyboard_input);
      keyboard_input = "";
    }
    
  }
  delayMicroseconds(200);
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
          //Serial.println(keyboard_input);
          open_the_latch(keyboard_input);
          keyboard_input = "";
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
          keyboard_input = "";
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

    }
  }
  delayMicroseconds(200);
  if (digitalRead(UNLOCK_BUTTON_PIN) == LOW){
    open_latch();
    digitalWrite(GREEN_LED, HIGH);
    digitalWrite(RED_LED, LOW);
    type_inscription_with_date("Lock opened with the key press");
    delay(OPEN_FOR);
    close_latch();
    digitalWrite(GREEN_LED, LOW);
    digitalWrite(RED_LED, HIGH);
  }
  delayMicroseconds(200);
}

void encr_TDES_AES_BLF_Serp_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the string you want to encrypt here:");
    while (!Serial.available()) {
    }
    String plt = Serial.readString();
    encrypt_string_with_tdes_aes_blf_srp(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    clear_variables();
    return;
  }
}

void decr_TDES_AES_BLF_Serp() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    while (!Serial.available()) {
    }
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    Serial.println("Plaintext:");
    Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    if (plt_integr == true)
      Serial.println("Integrity verified successfully!");
    else
      Serial.println("Integrity Verification failed!!!");
    clear_variables();
    return;
  }
}

void setup()
{
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(MODE_BUTTON_PIN, INPUT);
  pinMode(UNLOCK_BUTTON_PIN, INPUT);
  m = 2; // Set AES to 256-bit mode
  chsn_md = false; // Lock Mode
  trng_init();
  if (digitalRead(MODE_BUTTON_PIN) == LOW){
    delay(500);
    if (digitalRead(MODE_BUTTON_PIN) == LOW){
      chsn_md = true;
    }
  }
  if (chsn_md == true){ // Service Mode
    digitalWrite(GREEN_LED, HIGH);
    digitalWrite(RED_LED, HIGH);
    Serial.begin(115200);
    while (!Serial) {
      ; // wait for serial port to connect.
    }
  }
   else{ // Lock Mode
    digitalWrite(GREEN_LED, LOW);
    digitalWrite(RED_LED, HIGH);
    Latch.attach(LATCH_PIN);
    close_latch();
    myusb.begin();
    keyboard1.attachPress(OnPress);
    keyboard.begin(DATAPIN, IRQPIN);
  }
}

void loop() {
  if (chsn_md == true){ // Service Mode
    Serial.println();
    Serial.println("What do you want to do?");
    Serial.println("1.Generate keys");
    Serial.println("2.Blacklist the key");
    Serial.println("3.Test a key");
    Serial.println("4.Encrypt string with 3DES + AES-256 + Blowfish + Serpent in CBC mode");
    Serial.println("5.Decrypt string with 3DES + AES-256 + Blowfish + Serpent in CBC mode");
    while (!Serial.available()) {}
    int x = Serial.parseInt();
    if (x == 1)
      GenToken();
    if (x == 2)
      add_key_to_slot_in_the_blacklist();
    if (x == 3)
      test_key();
    if (x == 4)
      encr_TDES_AES_BLF_Serp_from_Serial();
    if (x == 5)
      decr_TDES_AES_BLF_Serp();
  }
  else{ // Lock Mode
    lock_mode();
  }
} 
