/**
* \file aes_gcm.ino
*
* \brief   Example of using the AES_GCM class
*
*/

/*  Copyright (C) 2019, Jidesh Veeramachaneni, All Rights Reserved.
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*/
#include "AES_GCM.h"

void printHex(const size_t length, const unsigned char* data) {
  for (int i = 0; i < length; i++) {
    if (i > 0) Serial.print(',');
    Serial.printf("%02X", data[i]);
  }
}

void setup() {
  Serial.begin();
}

// delay_time defines how long to wait before running
// the tests one time.
unsigned long delay_time = 10000;
bool ran_once = false;

void loop() {
  if (!ran_once && millis() > delay_time) {
    const unsigned char key[32] = {
      0xd6, 0xbe, 0x3b, 0x12, 0x08, 0xc7, 0x1f, 0x98, 0xff, 0x2e, 0x9e, 0x9b,
      0x9d, 0x4f, 0x7e, 0xff, 0x70, 0xdc, 0xcc, 0xd2, 0x76, 0x05, 0x99, 0xbc,
      0x89, 0xb0, 0x3d, 0x63, 0xd4, 0xac, 0xce, 0x63
    };

    AES_GCM aes_gcm (key, 256);

    const size_t input_length = 14;
    const unsigned char input[input_length] = {
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
      0x21, 0x00};
    unsigned char output[input_length];
    unsigned char dec_output[input_length];
    const size_t iv_length = 12;
    unsigned char iv[iv_length];
    aes_gcm.FillRandomBytes(iv_length, iv);
    const size_t aad_length = 4;
    unsigned char aad[aad_length] = {0x01, 0x03, 0x01, 0x04};
    const size_t tag_length = 16;
    unsigned char tag[tag_length];

    Serial.print("Plain Text: ");
    Serial.println((char*)&input);

    if (aes_gcm.Encrypt(input_length, input, output, tag_length, tag, iv_length, iv, aad_length, aad)) {
      Serial.print("Encrypted Data: ");
      printHex(input_length, output);
      Serial.println("");
      Serial.print("Tag: ");
      printHex(tag_length, tag);
      Serial.println("");
    }

    if (aes_gcm.Decrypt(input_length, output, dec_output, tag_length, tag, iv_length, iv, aad_length, aad)) {
      Serial.print("Decrypted Data: ");
      Serial.println((char*)&dec_output);
    }

    aad[0] = 0;
    if (!aes_gcm.Decrypt(input_length, output, dec_output, tag_length, tag, iv_length, iv, aad_length, aad)) {
      Serial.println("Invalid AAD Failed to Authenticate Correctly!");
    }

    tag[0] = 0;
    if (!aes_gcm.Decrypt(input_length, output, dec_output, tag_length, tag, iv_length, iv, aad_length, aad)) {
      Serial.println("Invalid TAG Failed to Authenticate Correctly!");
    }
    ran_once = true;
  }
}
