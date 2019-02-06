/**
* \file mbedtls_self_tests.ino
*
* \brief   Runs the mbedtls self tests for AES and GCM
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

#include "aes.h"
#include "gcm.h"
#include "platform.h"

// assuming all of the tests produce strings smaller
// than 10000 bytes.
char g_buffer[10000];

// the self tests use printf we will override that
// later using mbedtls_platform_set_printf and use
// the serial output over USB on Particle platforms
int serial_printf (const char* format_string, ...) {
  va_list args;
  va_start(args, format_string);
  vsprintf(g_buffer, format_string, args);
  va_end(args);
  Serial.print(g_buffer);
  return 1;
}

void setup() {
  Serial.begin();

  // override the printf calls for the self tests
  mbedtls_platform_set_printf(serial_printf);
}

// delay_time defines how long to wait before running
// the tests one time.
unsigned long delay_time = 10000;
bool ran_once = false;

void loop() {
  if (!ran_once && millis() > delay_time) {
    mbedtls_aes_self_test(1);
    mbedtls_gcm_self_test(1);
    ran_once = true;
  }
}
