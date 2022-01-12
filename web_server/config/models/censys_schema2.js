'use strict';

/**
 * Copyright 2022 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema;

// Censys Schema
// - The core is based on a variety.js dump of data collected in the database.
// - In theory it should match: https://github.com/zmap/zgrab/blob/master/zgrab_schema.py
// - A few manual fields have been added to the variety.js dump such as "zones" and "aws".
var censysSchema = new Schema(
  {
    autonomous_system: {
      asn: Number,
      country_code: String,
      description: String,
      name: String,
      organization: String,
      path: [],
      routed_prefix: String,
    },
    createdAt: Date,
    ip: String,
    ipint: Number,
    zones: [],
    domains: [],
    aws: Boolean,
    azure: Boolean,
    location: {
      city: String,
      continent: String,
      country: String,
      country_code: String,
      latitude: Number,
      longitude: Number,
      postal_code: String,
      province: String,
      registered_country: String,
      registered_country_code: String,
      timezone: String,
    },
    metadata: {
      description: String,
      device_type: String,
      manufacturer: String,
      os: String,
      product: String
    },
    p110: {
      pop3: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                subject_key_id: String
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              validity: {
                end: String,
                start: String
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,
            name: String
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean
        },
        starttls: {
          banner: String,
          metadata: {
            description: String,
            product: String
          },
          starttls: String,
          tls: {
            certificate: {
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: [],
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    content_commitment: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validity: {
                  end: String,
                  start: String
                },
                version: Number
              },
            },
            chain: [{
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                    max_path_len: Number
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    certificate_sign: Boolean,
                    crl_sign: Boolean,
                    digital_signature: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validity: {
                  end: String,
                  start: String
                },
                version: Number
              }
            }],
            cipher_suite: {
              id: String,
              name: String
            },
            ocsp_stapling: Boolean,
            server_key_exchange: {
              ecdh_params: {
                curve_id: {
                  id: Number,
                  name: String
                },
              },
            },
            signature: {
              hash_algorithm: String,
              signature_algorithm: String,
              valid: Boolean
            },
            validation: {
              browser_error: String,
              browser_trusted: Boolean
            },
            version: String
          },
        },
      },
    },
    p143: {
      imap: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              validity: {
                end: String,
                start: String
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,
            name: String
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean
        },
        starttls: {
          banner: String,
          metadata: {
            description: String,
            product: String
          },
          starttls: String,
          tls: {
            certificate: {
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    content_commitment: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String,
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  postal_code: [],
                  province: [],
                  street_address: []
                },
                subject_dn: String,
                subject_key_info: {
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validity: {
                  end: String,
                  start: String
                },
                version: Number
              },
            },
            chain: [{
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                    max_path_len: Number
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    certificate_sign: Boolean,
                    crl_sign: Boolean,
                    digital_signature: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String,
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validity: {
                  end: String,
                  start: String
                },
                version: Number
              }
            }],
            cipher_suite: {
              id: String,
              name: String
            },
            ocsp_stapling: Boolean,
            server_key_exchange: {
              ecdh_params: {
                curve_id: {
                  id: Number,
                  name: String
                },
              },
            },
            signature: {
              hash_algorithm: String,
              signature_algorithm: String,
              valid: Boolean
            },
            validation: {
              browser_error: String,
              browser_trusted: Boolean
            },
            version: String
          },
        },
      },
    },
    p21: {
      ftp: {
        banner: {
          banner: String,
          metadata: {
            description: String,
            product: String,
            revision: String,
            version: String
          },
        },
      },
    },
    p22: {
      ssh: {
        banner: {
          timestamp: String,
          raw_banner: String,
          protocol_version: String,
          software_version: String,
          metadata: {
            protocol_version: String,
            raw_banner: String,
            software_version: String
          },
        },
      },
    },
    p23: {
      telnet: {
        banner: {
          banner: String,
          do: [{
            name: String,
            value: Number
          }],
          metadata: {
            support: Boolean,
            will: [{
              name: String,
              value: Number
            }],
          },
        },
      },
    },
    p25: {
      smtp: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_info_access: {
                  issuer_urls: [],
                  ocsp_urls: []
                },
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                crl_distribution_points: [],
                extended_key_usage: [],
                key_usage: {
                  digital_signature: Boolean,
                  key_encipherment: Boolean,
                  value: Number
                },
                subject_alt_name: {
                  dns_names: []
                },
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validity: {
                end: String,
                start: String
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,

            name: String,
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean,
        },
        starttls: {
          banner: String,
          ehlo: String,
          metadata: {
            description: String,
            manufacturer: String,
            product: String
          },
          starttls: String,
          tls: {
            certificate: {
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: [],
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    content_commitment: Boolean,
                    digital_signature: Boolean,
                    key_encipherment: Boolean,
                    value: Number,
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,

                    signature: String,

                    timestamp: Number,

                    version: Number,
                  }],
                  subject_alt_name: {
                    dns_names: [],
                  },
                  subject_key_id: String,
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: [],
                  serial_number: [],
                },
                issuer_dn: String,
                names: [],
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String,
                  },
                  valid: Boolean,
                  value: String,
                },
                signature_algorithm: {
                  name: String,
                  oid: String,
                },
                spki_fingerprint: String,
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: [],
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String,
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String,
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,

                  id: String,

                  value: String,
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String,
                },
                version: Number,
              },
            },
            chain: [{
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: [],
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                    max_path_len: Number
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    certificate_sign: Boolean,
                    crl_sign: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number,
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                names: Array,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_fingerprint: String,
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: [],
                  serial_number: []
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String,
                },
                version: Number
              },
              //},
            }],
            cipher_suite: {
              id: String,
              name: String
            },
            ocsp_stapling: Boolean,
            server_key_exchange: {
              ecdh_params: {
                curve_id: {
                  id: Number,
                  name: String
                },
              },
            },
            signature: {
              hash_algorithm: String,
              signature_algorithm: String,
              valid: Boolean
            },
            validation: {
              browser_error: String,
              browser_trusted: Boolean
            },
            version: String
          },
        },
      },
    },
    p443: {
      https: {
        dhe: {
          dh_params: {
            generator: {
              length: Number,
              value: String
            },
            prime: {
              length: Number,
              value: String
            },
          },
          metadata: {},
          support: Boolean
        },
        dhe_export: {
          dh_params: {
            generator: {
              length: Number,
              value: String
            },
            prime: {
              length: Number,
              value: String
            },
          },
          metadata: {},
          support: Boolean
        },
        heartbleed: {
          heartbeat_enabled: Boolean,
          heartbleed_vulnerable: Boolean,
          metadata: {},
        },
        rsa_export: {
          metadata: {},
          rsa_params: {
            exponent: Number,
            length: Number,
            modulus: String
          },
          support: Boolean
        },
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_info_access: {
                  issuer_urls: [],
                  ocsp_urls: []
                },
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                crl_distribution_points: [],
                extended_key_usage: [],
                key_usage: {
                  data_encipherment: Boolean,
                  digital_signature: Boolean,
                  key_encipherment: Boolean,
                  value: Number
                },
                subject_alt_name: {
                  dns_names: []
                },
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: [],
                serial_number: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validity: {
                end: String,
                start: String
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,
            name: String
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean
        },
        ssl_3: {
          metadata: {},
          support: Boolean
        },
        tls: {
          certificate: {
            parsed: {
              extensions: {
                authority_info_access: {
                  issuer_urls: [],
                  ocsp_urls: []
                },
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean,
                  max_path_len: Number
                },
                certificate_policies: [],
                crl_distribution_points: [],
                extended_key_usage: [],
                key_usage: {
                  certificate_sign: Boolean,
                  content_commitment: Boolean,
                  crl_sign: Boolean,
                  data_encipherment: Boolean,
                  digital_signature: Boolean,
                  key_agreement: Boolean,
                  key_encipherment: Boolean,
                  value: Number
                },
                signed_certificate_timestamps: [{
                  log_id: String,
                  signature: String,
                  timestamp: Number,
                  version: Number
                }],
                subject_alt_name: {
                  dns_names: [],
                  email_addresses: [],
                  ip_addresses: []
                },
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                domain_component: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: [],
                serial_number: []
              },
              issuer_dn: String,
              names: Array,
              redacted: Boolean,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              spki_subject_fingerprint: String,
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                postal_code: [],
                province: [],
                serial_number: [],
                street_address: []
              },
              subject_dn: String,
              subject_key_info: {
                fingerprint_sha256: String,
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              tbs_fingerprint: String,
              tbs_noct_fingerprint: String,
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validation_level: String,
              validity: {
                end: String,
                length: Number,
                start: String
              },
              version: Number
            },
          },
          chain: [{
            parsed: {
              extensions: {
                authority_info_access: {
                  issuer_urls: [],
                  ocsp_urls: []
                },
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean,
                  max_path_len: Number
                },
                certificate_policies: [],
                crl_distribution_points: [],
                extended_key_usage: [],
                key_usage: {
                  certificate_sign: Boolean,
                  crl_sign: Boolean,
                  data_encipherment: Boolean,
                  digital_signature: Boolean,
                  key_agreement: Boolean,
                  key_encipherment: Boolean,
                  value: Number
                },
                name_constraints: {
                  critical: Boolean,
                  excluded_email_addresses: []
                },
                signed_certificate_timestamps: [{
                  log_id: String,
                  signature: String,
                  timestamp: Number,
                  version: Number
                }],
                subject_alt_name: {
                  dns_names: []
                },
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                domain_component: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              names: Array,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              spki_subject_fingerprint: String,
              subject: {
                common_name: [],
                country: [],
                domain_component: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: [],
                serial_number: []
              },
              subject_dn: String,
              subject_key_info: {
                fingerprint_sha256: String,
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              tbs_fingerprint: String,
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validation_level: String,
              validity: {
                end: String,
                length: Number,
                start: String
              },
              version: Number
            },
            //},
          }],
          cipher_suite: {
            id: String,
            name: String
          },
          metadata: {},
          ocsp_stapling: Boolean,
          server_key_exchange: {
            dh_params: {
              generator: {
                length: Number,
                value: String
              },
              prime: {
                length: Number,
                value: String
              },
            },
            ecdh_params: {
              curve_id: {
                id: Number,
                name: String
              },
            },
          },
          signature: {
            hash_algorithm: String,
            signature_algorithm: String,
            valid: Boolean
          },
          validation: {
            browser_error: String,
            browser_trusted: Boolean
          },
          version: String
        },
      },
    },
    p465: {
      smtps: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_info_access: {
                  issuer_urls: [],
                  ocsp_urls: [],
                },
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean,
                },
                certificate_policies: [],
                crl_distribution_points: [],
                extended_key_usage: [],
                key_usage: {
                  digital_signature: Boolean,
                  key_encipherment: Boolean,
                  value: Number,
                },
                subject_alt_name: {
                  dns_names: [],
                },
                subject_key_id: String,
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: [],
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String,
                },
                valid: Boolean,
                value: String,
              },
              signature_algorithm: {
                name: String,
                oid: String,
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: [],
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String,
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String,
                },
              },
              unknown_extensions: [{
                critical: Boolean,

                id: String,

                value: String,
              }],
              validity: {
                end: String,
                start: String,
              },
              version: Number,
            },
          },
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean,
        },
      },
    },
    p47808: {
      bacnet: {
        device_id: {
          application_software_revision: String,
          description: String,
          firmware_revision: String,
          instance_number: Number,
          metadata: {},
          model_name: String,
          object_name: String,
          support: Boolean,
          vendor: {
            id: Number,
            official_name: String,
            reported_name: String,
          },
        },
      },
    },
    p502: {
      modbus: {
        device_id: {
          function_code: Number,
          metadata: {},
          support: Boolean
        },
      },
    },
    p53: {
      dns: {
        lookup: {
          additionals: [{
            name: String,
            response: String,
            type: String
          }],
          answers: [{
            name: String,
            response: String,
            type: String
          }],
          authorities: [{
            name: String,
            response: String,
            type: String
          }],
          errors: Boolean,
          metadata: {},
          open_resolver: Boolean,
          questions: [{
            name: String,
            type: String
          }],
          resolves_correctly: Boolean,
          support: Boolean
        },
      },
    },
    p7547: {
      cwmp: {
        get: {
          headers: {
            content_length: [],
            content_type: [],
            server: [],
            unknown: [{
              key: String,
              value: []
            }],
            x_powered_by: []
          },
          metadata: {},
          status_code: Number,
          status_line: String
        },
      },
    },
    p80: {
      http: {
        get: {
          body: String,
          body_sha256: String,
          headers: {
            accept_ranges: String,
            access_control_allow_origin: String,
            age: String,
            alternate_protocol: String,
            cache_control: String,
            connection: String,
            content_language: String,
            content_length: String,
            content_location: String,
            content_security_policy: String,
            content_type: String,
            expires: String,
            last_modified: String,
            link: String,
            p3p: String,
            pragma: String,
            refresh: String,
            retry_after: String,
            server: String,
            status: String,
            strict_transport_security: String,
            unknown: [{
              key: String,
              value: String,
            }],
            vary: String,
            via: String,
            www_authenticate: String,
            x_content_security_policy: String,
            x_content_type_options: String,
            x_frame_options: String,
            x_powered_by: String,
            x_ua_compatible: String,
            x_webkit_csp: String,
            x_xss_protection: String,
          },
          metadata: {
            description: String,
            manufacturer: String,
            product: String,
            version: String,
          },
          status_code: Number,
          status_line: String,
          title: String,
          timestamp: String
        },
      },
    },
    p993: {
      imaps: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                subject_key_id: String
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validity: {
                end: String,
                start: String,
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,
            name: String
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean
        },
        tls: {
          banner: String,
          metadata: {},
          tls: {
            certificate: {
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    content_commitment: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                names: Array,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String
                },
                version: Number
              },
            },
            chain: [{
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                    max_path_len: Number
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    certificate_sign: Boolean,
                    crl_sign: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                names: Array,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String,
                },
                version: Number,
              },
            }],
            cipher_suite: {
              id: String,
              name: String,
            },
            ocsp_stapling: Boolean,
            server_key_exchange: {
              ecdh_params: {
                curve_id: {
                  id: Number,
                  name: String,
                },
              },
            },
            signature: {
              hash_algorithm: String,
              signature_algorithm: String,
              valid: Boolean,
            },
            validation: {
              browser_error: String,
              browser_trusted: Boolean,
            },
            version: String,
          },
        }
      }
    },
    p995: {
      pop3s: {
        ssl_2: {
          certificate: {
            parsed: {
              extensions: {
                authority_key_id: String,
                basic_constraints: {
                  is_ca: Boolean
                },
                certificate_policies: [],
                subject_key_id: String
              },
              fingerprint_md5: String,
              fingerprint_sha1: String,
              fingerprint_sha256: String,
              issuer: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              issuer_dn: String,
              serial_number: String,
              signature: {
                self_signed: Boolean,
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                valid: Boolean,
                value: String
              },
              signature_algorithm: {
                name: String,
                oid: String
              },
              subject: {
                common_name: [],
                country: [],
                locality: [],
                organization: [],
                organizational_unit: [],
                province: []
              },
              subject_dn: String,
              subject_key_info: {
                key_algorithm: {
                  name: String,
                  oid: String
                },
                rsa_public_key: {
                  exponent: Number,
                  length: Number,
                  modulus: String
                },
              },
              unknown_extensions: [{
                critical: Boolean,
                id: String,
                value: String
              }],
              validity: {
                end: String,
                start: String
              },
              version: Number
            },
          },
          ciphers: [{
            id: Number,
            name: String
          }],
          export: Boolean,
          extra_clear: Boolean,
          metadata: {},
          support: Boolean
        },
        tls: {
          banner: String,
          metadata: {},
          tls: {
            certificate: {
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    content_commitment: Boolean,
                    digital_signature: Boolean,
                    key_agreement: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                names: Array,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String
                },
                version: Number
              },
            },
            chain: [{
              parsed: {
                extensions: {
                  authority_info_access: {
                    issuer_urls: [],
                    ocsp_urls: []
                  },
                  authority_key_id: String,
                  basic_constraints: {
                    is_ca: Boolean,
                    max_path_len: Number
                  },
                  certificate_policies: [],
                  crl_distribution_points: [],
                  extended_key_usage: [],
                  key_usage: {
                    certificate_sign: Boolean,
                    crl_sign: Boolean,
                    digital_signature: Boolean,
                    key_encipherment: Boolean,
                    value: Number
                  },
                  signed_certificate_timestamps: [{
                    log_id: String,
                    signature: String,
                    timestamp: Number,
                    version: Number
                  }],
                  subject_alt_name: {
                    dns_names: []
                  },
                  subject_key_id: String
                },
                fingerprint_md5: String,
                fingerprint_sha1: String,
                fingerprint_sha256: String,
                issuer: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                issuer_dn: String,
                names: Array,
                serial_number: String,
                signature: {
                  self_signed: Boolean,
                  signature_algorithm: {
                    name: String,
                    oid: String
                  },
                  valid: Boolean,
                  value: String
                },
                signature_algorithm: {
                  name: String,
                  oid: String
                },
                spki_subject_fingerprint: String,
                subject: {
                  common_name: [],
                  country: [],
                  locality: [],
                  organization: [],
                  organizational_unit: [],
                  province: []
                },
                subject_dn: String,
                subject_key_info: {
                  fingerprint_sha256: String,
                  key_algorithm: {
                    name: String,
                    oid: String
                  },
                  rsa_public_key: {
                    exponent: Number,
                    length: Number,
                    modulus: String
                  },
                },
                tbs_fingerprint: String,
                unknown_extensions: [{
                  critical: Boolean,
                  id: String,
                  value: String
                }],
                validation_level: String,
                validity: {
                  end: String,
                  length: Number,
                  start: String
                },
                version: Number
              }
            }],
            cipher_suite: {
              id: String,
              name: String
            },
            ocsp_stapling: Boolean,
            server_key_exchange: {
              ecdh_params: {
                curve_id: {
                  id: Number,
                  name: String
                },
              },
            },
            signature: {
              hash_algorithm: String,
              signature_algorithm: String,
              valid: Boolean
            },
            validation: {
              browser_error: String,
              browser_trusted: Boolean
            },
            version: String
          },
        },
      }
    },
    tags: []
  }, { collection: 'censys' });

var censysModel = mongoose.model('censysModel', censysSchema);

module.exports = { censysModel: censysModel }
