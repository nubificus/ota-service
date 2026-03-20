// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This is an implementation of DiceGenerateCertificate and the crypto
// operations that uses mbedtls. The algorithms used are SHA512, HKDF-SHA512,
// and deterministic ECDSA-P256-SHA512.

#ifdef OTA_SECURE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/utils.h"
/* IDF v6.0 / mbedtls 4.x: allow access to private struct members and expose
 * internal declarations (pk_internal.h, hmac_drbg private fields, etc.). */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "pk_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/private/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/private/pk_private.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/base64.h"
#include "psa/crypto.h"

#define DICE_MAX_CERTIFICATE_SIZE 2048
#define DICE_MAX_EXTENSION_SIZE 2048
#define DICE_MAX_KEY_ID_SIZE 40

void print_base64_encoded(uint8_t *data, size_t len) {
    size_t output_len;
    size_t encoded_len = 4 * ((len + 2) / 3);

    char *encoded = (char *)malloc(encoded_len + 1);
    if (encoded == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    if (mbedtls_base64_encode((unsigned char *) encoded,
			      encoded_len + 1, &output_len,
			      data, len) != 0) {
        printf("Base64 encoding failed\n");
        free(encoded);
        return;
    }

    encoded[output_len] = '\0';
    printf("%s\n\n", encoded);
    free(encoded);
}

static DiceResult SetupKeyPair(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    mbedtls_pk_context* context) {
  // In mbedtls 4.x (IDF v6.0) EC keys are backed by PSA; pk_ctx is always
  // NULL and mbedtls_pk_ec() always returns NULL.  Generate the key
  // deterministically in a standalone keypair, export the raw private scalar,
  // then load it into the pk_context via the internal PSA-import helpers.
  if (0 != mbedtls_pk_setup(context,
                             mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) {
    return kDiceResultPlatformError;
  }
  if (0 != mbedtls_pk_ecc_set_group(context, MBEDTLS_ECP_DP_SECP256R1)) {
    return kDiceResultPlatformError;
  }

  DiceResult result = kDiceResultOk;
  mbedtls_ecp_keypair keypair;
  mbedtls_ecp_keypair_init(&keypair);
  mbedtls_hmac_drbg_context rng_context;
  mbedtls_hmac_drbg_init(&rng_context);

  // Use the |private_key_seed| directly to seed a PRNG which is then in turn
  // used to generate the private key. This implementation uses HMAC_DRBG in a
  // loop with no reduction, like RFC6979.
  if (0 != mbedtls_hmac_drbg_seed_buf(
               &rng_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
               private_key_seed, DICE_PRIVATE_KEY_SEED_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair,
                               mbedtls_hmac_drbg_random, &rng_context)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // Export raw 32-byte private scalar and import into the PSA-backed context.
  {
    uint8_t priv_key[32];
    if (0 != mbedtls_mpi_write_binary(&keypair.MBEDTLS_PRIVATE(d),
                                      priv_key, sizeof(priv_key))) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (0 != mbedtls_pk_ecc_set_key(context, priv_key, sizeof(priv_key))) {
      result = kDiceResultPlatformError;
      goto out;
    }
    // Populate pub_raw from the PSA key so that pk_write_ec_pubkey can read it.
    // For MBEDTLS_PK_ECKEY (non-OPAQUE), pkwrite.c reads pub_raw directly.
    if (0 != mbedtls_pk_ecc_set_pubkey_from_prv(context, priv_key,
                                                 sizeof(priv_key))) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }

out:
  mbedtls_ecp_keypair_free(&keypair);
  mbedtls_hmac_drbg_free(&rng_context);
  return result;
}

static DiceResult GetIdFromKey(void* context,
                               const mbedtls_pk_context* pk_context,
                               uint8_t id[DICE_ID_SIZE]) {
  // In mbedtls 4.x EC keys are stored as PSA keys; export the public key via
  // PSA (returns 65-byte uncompressed secp256r1 point: 0x04 || X || Y), then
  // compress to the 33-byte form (0x02/0x03 || X) expected by DICE.
  uint8_t pub_raw[65];
  size_t pub_raw_len = 0;
  if (PSA_SUCCESS != psa_export_public_key(
          pk_context->MBEDTLS_PRIVATE(priv_id),
          pub_raw, sizeof(pub_raw), &pub_raw_len) ||
      pub_raw_len != 65 || pub_raw[0] != 0x04) {
    return kDiceResultPlatformError;
  }
  uint8_t compressed[33];
  compressed[0] = (pub_raw[64] & 1) ? 0x03 : 0x02;
  memcpy(compressed + 1, pub_raw + 1, 32);
  return DiceDeriveCdiCertificateId(context, compressed, sizeof(compressed), id);
}

// 54 byte name is prefix (13), hex id (40), and a null terminator.
static void GetNameFromId(const uint8_t id[DICE_ID_SIZE], char name[54]) {
  strcpy(name, "serialNumber=");
  DiceHexEncode(id, /*num_bytes=*/DICE_ID_SIZE, (uint8_t*)&name[13],
                /*out_size=*/40);
  name[53] = '\0';
}

static DiceResult GetSubjectKeyIdFromId(const uint8_t id[DICE_ID_SIZE],
                                        size_t buffer_size, uint8_t* buffer,
                                        size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error =
      mbedtls_asn1_write_octet_string(&pos, buffer, id, DICE_ID_SIZE);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

static int AddAuthorityKeyIdEncoding(uint8_t** pos, uint8_t* start,
                                     int length) {
  // From RFC 5280 4.2.1.1.
  const int kKeyIdentifierTag = 0;

  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(
          pos, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | kKeyIdentifierTag));

  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(pos, start,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  return length;
}

static DiceResult GetAuthorityKeyIdFromId(const uint8_t id[DICE_ID_SIZE],
                                          size_t buffer_size, uint8_t* buffer,
                                          size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error =
      mbedtls_asn1_write_raw_buffer(&pos, buffer, id, DICE_ID_SIZE);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  length_or_error = AddAuthorityKeyIdEncoding(&pos, buffer, length_or_error);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

static uint8_t GetFieldTag(uint8_t tag) {
  return MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitModeField(uint8_t tag, int value, uint8_t** pos,
                                  uint8_t* start) {
  // ASN.1 constants not defined by mbedtls.
  const uint8_t kEnumTypeTag = 10;

  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int field_length = 0;
  MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_int(pos, start, value));
  // Overwrite the 'int' type.
  ++(*pos);
  --field_length;
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_tag(pos, start, kEnumTypeTag));

  // Explicitly tagged, so add the field tag too.
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_len(pos, start, field_length));
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
  return field_length;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitUtf8StringField(uint8_t tag, const void* value,
                                        size_t value_size, uint8_t** pos,
                                        uint8_t* start) {
  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int field_length = 0;
  MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_utf8_string(
                                         pos, start, value, value_size));
  // Explicitly tagged, so add the field tag too.
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_len(pos, start, field_length));
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
  return field_length;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitOctetStringField(uint8_t tag, const uint8_t* value,
                                         size_t value_size, uint8_t** pos,
                                         uint8_t* start) {
  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int field_length = 0;
  MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_octet_string(
                                         pos, start, value, value_size));
  // Explicitly tagged, so add the field tag too.
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_len(pos, start, field_length));
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
  return field_length;
}

static int GetDiceExtensionDataHelper(const DiceInputValues* input_values,
                                      uint8_t** pos, uint8_t* start) {
  // ASN.1 tags for extension fields.
  const uint8_t kDiceFieldCodeHash = 0;
  const uint8_t kDiceFieldCodeDescriptor = 1;
  const uint8_t kDiceFieldConfigHash = 2;
  const uint8_t kDiceFieldConfigDescriptor = 3;
  const uint8_t kDiceFieldAuthorityHash = 4;
  const uint8_t kDiceFieldAuthorityDescriptor = 5;
  const uint8_t kDiceFieldMode = 6;
  const uint8_t kDiceFieldProfileName = 7;

  // Build up the extension ASN.1 in reverse order.
  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int length = 0;

  // Add the profile name field.
  if (DICE_PROFILE_NAME) {
    MBEDTLS_ASN1_CHK_ADD(length, WriteExplicitUtf8StringField(
                                     kDiceFieldProfileName, DICE_PROFILE_NAME,
                                     strlen(DICE_PROFILE_NAME), pos, start));
  }

  // Add the mode field.
  MBEDTLS_ASN1_CHK_ADD(
      length,
      WriteExplicitModeField(kDiceFieldMode, input_values->mode, pos, start));

  // Add the authorityDescriptor field, if applicable.
  if (input_values->authority_descriptor_size > 0) {
    MBEDTLS_ASN1_CHK_ADD(
        length,
        WriteExplicitOctetStringField(
            kDiceFieldAuthorityDescriptor, input_values->authority_descriptor,
            input_values->authority_descriptor_size, pos, start));
  }

  // Add the authorityHash field.
  MBEDTLS_ASN1_CHK_ADD(
      length, WriteExplicitOctetStringField(kDiceFieldAuthorityHash,
                                            input_values->authority_hash,
                                            DICE_HASH_SIZE, pos, start));

  // Add the configurationDescriptor field (and configurationHash field, if
  // applicable).
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    uint8_t hash[DICE_HASH_SIZE];
    int result = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                            input_values->config_descriptor,
                            input_values->config_descriptor_size, hash);
    if (result) {
      return result;
    }
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldConfigDescriptor, input_values->config_descriptor,
                    input_values->config_descriptor_size, pos, start));
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(kDiceFieldConfigHash, hash,
                                              DICE_HASH_SIZE, pos, start));
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldConfigDescriptor, input_values->config_value,
                    DICE_INLINE_CONFIG_SIZE, pos, start));
  }

  // Add the code descriptor field, if applicable.
  if (input_values->code_descriptor_size > 0) {
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldCodeDescriptor, input_values->code_descriptor,
                    input_values->code_descriptor_size, pos, start));
  }

  // Add the code hash field.
  MBEDTLS_ASN1_CHK_ADD(length, WriteExplicitOctetStringField(
                                   kDiceFieldCodeHash, input_values->code_hash,
                                   DICE_HASH_SIZE, pos, start));

  // Add the sequence length and tag.
  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(pos, start,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  return length;
}

static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
                                       size_t buffer_size, uint8_t* buffer,
                                       size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error = GetDiceExtensionDataHelper(input_values, &pos, buffer);
  if (length_or_error == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
    return kDiceResultBufferTooSmall;
  } else if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

DiceResult DiceHash(void* context_not_used, const uint8_t* input,
                    size_t input_size, uint8_t output[DICE_HASH_SIZE]) {
  (void)context_not_used;
  if (0 != mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), input,
                      input_size, output)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceKdf(void* context_not_used, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output) {
  (void)context_not_used;
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key;
  psa_status_t status;

  psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
  psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_512));
  status = psa_import_key(&attr, ikm, ikm_size, &key);
  if (status != PSA_SUCCESS) return kDiceResultPlatformError;

  status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_512));
  if (status != PSA_SUCCESS) goto cleanup;

  if (salt_size > 0) {
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_size);
    if (status != PSA_SUCCESS) goto cleanup;
  }
  status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        key);
  if (status != PSA_SUCCESS) goto cleanup;

  status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                          info, info_size);
  if (status != PSA_SUCCESS) goto cleanup;

  status = psa_key_derivation_output_bytes(&op, output, length);
cleanup:
  psa_key_derivation_abort(&op);
  psa_destroy_key(key);
  return (status == PSA_SUCCESS) ? kDiceResultOk : kDiceResultPlatformError;
}

DiceResult DiceGenerateCertificate(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  // 1.3.6.1.4.1.11129.2.1.24
  // iso.org.dod.internet.private.enterprise.
  //   google.googleSecurity.certificateExtensions.diceAttestationData
  const char* kDiceExtensionOid =
      MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_DOD
      "\x01\x04\x01\xd6\x79\x02\x01\x18";
  const size_t kDiceExtensionOidLength = 10;

  DiceResult result = kDiceResultOk;

  // Initialize variables cleaned up on 'goto out'.
  mbedtls_pk_context authority_key_context;
  mbedtls_pk_init(&authority_key_context);
  mbedtls_pk_context subject_key_context;
  mbedtls_pk_init(&subject_key_context);
  mbedtls_x509write_cert cert_context;
  mbedtls_x509write_crt_init(&cert_context);
  mbedtls_mpi serial_number;
  mbedtls_mpi_init(&serial_number);

  // Derive key pairs and IDs.
  result = SetupKeyPair(authority_private_key_seed, &authority_key_context);
  if (result != kDiceResultOk) {
    goto out;
  }

  unsigned char buf[512] = {0};
  if (mbedtls_pk_write_key_pem(&authority_key_context,
			       buf, sizeof(buf) - 1)) {
    printf("mbedtls_pk_write_key_pem() did not work\n");
    goto out;
  }
  /* printf("Authority Key Context:\n%s\n", buf); */

  uint8_t authority_id[DICE_ID_SIZE];
  result = GetIdFromKey(context, &authority_key_context, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }

  char authority_name[54];
  GetNameFromId(authority_id, authority_name);

  uint8_t authority_key_id[DICE_MAX_KEY_ID_SIZE];
  size_t authority_key_id_size = 0;
  result = GetAuthorityKeyIdFromId(authority_id, sizeof(authority_key_id),
                                   authority_key_id, &authority_key_id_size);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = SetupKeyPair(subject_private_key_seed, &subject_key_context);
  if (result != kDiceResultOk) {
    goto out;
  }

  memset(buf, 0, sizeof(memset));
  if (mbedtls_pk_write_key_pem(&subject_key_context,
			       buf, sizeof(buf) - 1)) {
    printf("mbedtls_pk_write_key_pem() did not work\n");
    goto out;
  }
  /* printf("Subject Key Context:\n%s\n", buf); */

  uint8_t subject_id[DICE_ID_SIZE];
  result = GetIdFromKey(context, &subject_key_context, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }

  char subject_name[54];
  GetNameFromId(subject_id, subject_name);

  uint8_t subject_key_id[DICE_MAX_KEY_ID_SIZE];
  size_t subject_key_id_size = 0;
  result = GetSubjectKeyIdFromId(subject_id, sizeof(subject_key_id),
                                 subject_key_id, &subject_key_id_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t dice_extension[DICE_MAX_EXTENSION_SIZE];
  size_t dice_extension_size = 0;
  result = GetDiceExtensionData(input_values, sizeof(dice_extension),
                                dice_extension, &dice_extension_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Construct the certificate.
  mbedtls_x509write_crt_set_version(&cert_context, MBEDTLS_X509_CRT_VERSION_3);
  if (0 !=
      mbedtls_mpi_read_binary(&serial_number, subject_id, sizeof(subject_id))) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_serial_raw(&cert_context, subject_id,
      sizeof(subject_id))) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // '20180322235959' is the date of publication of the DICE specification. Here
  // it's used as a somewhat arbitrary backstop. '99991231235959' is suggested
  // by RFC 5280 in cases where expiry is not meaningful. Basically, the
  // certificate never expires.
  if (0 != mbedtls_x509write_crt_set_validity(&cert_context, "20180322235959",
                                              "99991231235959")) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 !=
      mbedtls_x509write_crt_set_issuer_name(&cert_context, authority_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 !=
      mbedtls_x509write_crt_set_subject_name(&cert_context, subject_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  mbedtls_x509write_crt_set_subject_key(&cert_context, &subject_key_context);
  mbedtls_x509write_crt_set_issuer_key(&cert_context, &authority_key_context);
  mbedtls_x509write_crt_set_md_alg(&cert_context, MBEDTLS_MD_SHA512);
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
               MBEDTLS_OID_SIZE(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER),
               /*critical=*/0, authority_key_id, authority_key_id_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
               MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER),
               /*critical=*/0, subject_key_id, subject_key_id_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_key_usage(&cert_context,
                                               MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_basic_constraints(&cert_context,
                                                       /*is_ca=*/1,
                                                       /*max_pathlen=*/-1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, kDiceExtensionOid, kDiceExtensionOidLength,
               /*critical=*/1, dice_extension, dice_extension_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  /* In mbedtls 4.x (IDF v6.0) RNG is handled internally via PSA Crypto. */
  uint8_t tmp_buffer[DICE_MAX_CERTIFICATE_SIZE];
  int length_or_error =
      mbedtls_x509write_crt_der(&cert_context, tmp_buffer, sizeof(tmp_buffer));
  if (length_or_error < 0) {
    result = kDiceResultPlatformError;
    goto out;
  }
  *certificate_actual_size = length_or_error;
  if (*certificate_actual_size > certificate_buffer_size) {
    result = kDiceResultBufferTooSmall;
    goto out;
  }
  // The certificate has been written to the end of tmp_buffer. Skip unused
  // buffer when copying.
  memcpy(certificate,
         &tmp_buffer[sizeof(tmp_buffer) - *certificate_actual_size],
         *certificate_actual_size);

/*
  *printf("Certificate - Base64:\n");
  print_base64_encoded(certificate,
		      *certificate_actual_size);
  printf("\n");

  printf("Subject Private Key:\n");
  print_base64_encoded(subject_private_key_seed,
		       DICE_PRIVATE_KEY_SEED_SIZE);
  printf("\n");

  printf("Authority Private Key:\n");
  print_base64_encoded(authority_private_key_seed,
		       DICE_PRIVATE_KEY_SEED_SIZE);
*/
out:
  mbedtls_mpi_free(&serial_number);
  mbedtls_x509write_crt_free(&cert_context);
  mbedtls_pk_free(&authority_key_context);
  mbedtls_pk_free(&subject_key_context);
  return result;
}

#endif
