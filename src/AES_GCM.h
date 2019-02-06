/**
 * \file AES_GCM.h
 *
 * \brief   AES_GCM class which uses mbedtls
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
 #ifndef AES_GCM_H
 #define AES_GCM_H

 #include "gcm.h"

class AES_GCM {
public:
  AES_GCM() = delete;
  AES_GCM(AES_GCM&) = delete;
  AES_GCM(AES_GCM&&) = delete;
  AES_GCM(const unsigned char* key, const size_t key_length_bits);
  ~AES_GCM() {}

  bool Encrypt(const size_t length, const unsigned char* input, unsigned char* output,
               const size_t tag_length, unsigned char* tag, const size_t iv_length,
               unsigned char* iv, const size_t aad_length, const unsigned char* aad);

  bool Decrypt(const size_t length, const unsigned char* input, unsigned char* output,
               const size_t tag_length, unsigned char* tag, const size_t iv_length,
               unsigned char* iv, const size_t aad_length, const unsigned char* aad);

  void FillRandomBytes(const size_t length, unsigned char* output);

private:
  mbedtls_gcm_context m_ctx;
  unsigned char m_key[32];
  size_t m_key_length_bits;
};

#endif //AES_GCM_H
