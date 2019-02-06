/**
 * \file AES_GCM.cpp
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
#include "Particle.h"
#include "AES_GCM.h"
#include <string.h>

AES_GCM::AES_GCM(const unsigned char* key, const size_t key_length_bits) {
  m_key_length_bits = key_length_bits > 256 ? 256 : key_length_bits;
  memcpy (m_key, key, m_key_length_bits/8);
}

bool AES_GCM::Encrypt(const size_t length, const unsigned char* input, unsigned char* output,
                      const size_t tag_length, unsigned char* tag, const size_t iv_length,
                      unsigned char* iv, const size_t aad_length, const unsigned char* aad) {
  mbedtls_gcm_init(&m_ctx);

  if (0 != mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, m_key, m_key_length_bits)) {
    return false;
  }

  if (0 != mbedtls_gcm_crypt_and_tag(&m_ctx, MBEDTLS_GCM_ENCRYPT, length, iv, iv_length, aad, aad_length, input, output, tag_length, tag)) {
    return false;
  }
  mbedtls_gcm_free(&m_ctx);
}

bool AES_GCM::Decrypt(const size_t length, const unsigned char* input, unsigned char* output,
                      const size_t tag_length, unsigned char* tag, const size_t iv_length,
                      unsigned char* iv, const size_t aad_length, const unsigned char* aad) {
  mbedtls_gcm_init(&m_ctx);

  if (0 != mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, m_key, m_key_length_bits)) {
    return false;
  }

  if (0 != mbedtls_gcm_auth_decrypt(&m_ctx, length, iv, iv_length, aad, aad_length, tag, tag_length, input, output)) {
    return false;
  }
  mbedtls_gcm_free(&m_ctx);
}

void AES_GCM::FillRandomBytes(const size_t length, unsigned char* output) {
  for (int i = 0; i < length; i++) {
    output[i] = (unsigned char) random(255);
  }
}
