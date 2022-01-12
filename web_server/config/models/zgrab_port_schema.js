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

// Zgrab Port Schema
// - The core is based on a variety.js dump of data collected in the database.
// - In theory, it should roughly match: https://github.com/zmap/zgrab/blob/master/zgrab_schema.py.
var zgrabPortSchema = new Schema(
      {
            '_id': 'ObjectId',
            'aws': 'Boolean',
            'azure': 'Boolean',
            'data': {
                  'smtp': {
                        'banner': 'String',
                        'ehlo': 'String',
                        'starttls': 'String',
                        'timestamp': 'Date',
                        'tls': {
                              'server_certificates': {
                                    'certificate': {
                                          'parsed': {
                                                'extensions': {
                                                      'authority_info_access': {
                                                            'issuer_urls': [],
                                                            'ocsp_urls': []
                                                      },
                                                      'authority_key_id': 'String',
                                                      'basic_constraints': { 'is_ca': 'Boolean' },
                                                      'certificate_policies': [{
                                                            'cps': [],
                                                            'id': 'String'
                                                      }],
                                                      'crl_distribution_points': [],
                                                      'extended_key_usage': {
                                                            'client_auth': 'Boolean',
                                                            'server_auth': 'Boolean'
                                                      },
                                                      'key_usage': {
                                                            'digital_signature': 'Boolean',
                                                            'key_encipherment': 'Boolean',
                                                            'value': 'Number'
                                                      },
                                                      'signed_certificate_timestamps': [{
                                                            'log_id': 'String',
                                                            'signature': 'String',
                                                            'timestamp': 'Number',
                                                            'version': 'Number'
                                                      }],
                                                      'subject_alt_name': { 'dns_names': [] },
                                                      'subject_key_id': 'String'
                                                },
                                                'fingerprint_md5': 'String',
                                                'fingerprint_sha1': 'String',
                                                'fingerprint_sha256': 'String',
                                                'issuer': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'email_address': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'issuer_dn': 'String',
                                                'names': [],
                                                'redacted': 'Boolean',
                                                'serial_number': 'String',
                                                'signature': {
                                                      'self_signed': 'Boolean',
                                                      'signature_algorithm': {
                                                            'name': 'String',
                                                            'oid': 'String'
                                                      },
                                                      'valid': 'Boolean',
                                                      'value': 'String'
                                                },
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'spki_subject_fingerprint': 'String',
                                                'subject': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'email_address': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'subject_dn': 'String',
                                                'subject_key_info': {
                                                      'fingerprint_sha256': 'String',
                                                      'key_algorithm': { 'name': 'String' },
                                                      'rsa_public_key': {
                                                            'exponent': 'Number',
                                                            'length': 'Number',
                                                            'modulus': 'String'
                                                      }
                                                },
                                                'tbs_fingerprint': 'String',
                                                'tbs_noct_fingerprint': 'String',
                                                'validation_level': 'String',
                                                'validity': {
                                                      'end': 'String',
                                                      'length': 'Number',
                                                      'start': 'String'
                                                },
                                                'version': 'Number'
                                          },
                                          'raw': 'String'
                                    },
                                    'chain': [{
                                          'parsed': {
                                                'extensions': {
                                                      'authority_info_access': {
                                                            'issuer_urls': [],
                                                            'ocsp_urls': []
                                                      },
                                                      'authority_key_id': 'String',
                                                      'basic_constraints': {
                                                            'is_ca': 'Boolean',
                                                            'max_path_len': 'Number'
                                                      },
                                                      'certificate_policies': [{
                                                            'cps': [],
                                                            'id': 'String'
                                                      }],
                                                      'crl_distribution_points': [],
                                                      'extended_key_usage': {
                                                            'client_auth': 'Boolean',
                                                            'server_auth': 'Boolean'
                                                      },
                                                      'key_usage': {
                                                            'certificate_sign': 'Boolean',
                                                            'crl_sign': 'Boolean',
                                                            'digital_signature': 'Boolean',
                                                            'value': 'Number'
                                                      },
                                                      'subject_key_id': 'String'
                                                },
                                                'fingerprint_md5': 'String',
                                                'fingerprint_sha1': 'String',
                                                'fingerprint_sha256': 'String',
                                                'issuer': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'issuer_dn': 'String',
                                                'redacted': 'Boolean',
                                                'serial_number': 'String',
                                                'signature': {
                                                      'self_signed': 'Boolean',
                                                      'signature_algorithm': {
                                                            'name': 'String',
                                                            'oid': 'String'
                                                      },
                                                      'valid': 'Boolean',
                                                      'value': 'String'
                                                },
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'spki_subject_fingerprint': 'String',
                                                'subject': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'subject_dn': 'String',
                                                'subject_key_info': {
                                                      'fingerprint_sha256': 'String',
                                                      'key_algorithm': { 'name': 'String' },
                                                      'rsa_public_key': {
                                                            'exponent': 'Number',
                                                            'length': 'Number',
                                                            'modulus': 'String'
                                                      }
                                                },
                                                'tbs_fingerprint': 'String',
                                                'tbs_noct_fingerprint': 'String',
                                                'validation_level': 'String',
                                                'validity': {
                                                      'end': 'String',
                                                      'length': 'Number',
                                                      'start': 'String'
                                                },
                                                'version': 'Number'
                                          },
                                          'raw': 'String'
                                    }],
                                    'validation': {
                                          'browser_error': 'String',
                                          'browser_trusted': 'Boolean'
                                    }
                              },
                              'server_finished': { 'verify_data': 'String' },
                              'server_hello': {
                                    'cipher_suite': {
                                          'hex': 'String',
                                          'name': 'String',
                                          'value': 'Number'
                                    },
                                    'compression_method': 'Number',
                                    'extended_master_secret': 'Boolean',
                                    'heartbeat': 'Boolean',
                                    'ocsp_stapling': 'Boolean',
                                    'random': 'String',
                                    'secure_renegotiation': 'Boolean',
                                    'session_id': 'String',
                                    'ticket': 'Boolean',
                                    'version': {
                                          'name': 'String',
                                          'value': 'Number'
                                    }
                              },
                              'server_key_exchange': {
                                    'digest': 'String',
                                    'ecdh_params': {
                                          'curve_id': {
                                                'id': 'Number',
                                                'name': 'String'
                                          },
                                          'server_public': {
                                                'x': {
                                                      'length': 'Number',
                                                      'value': 'String'
                                                },
                                                'y': {
                                                      'length': 'Number',
                                                      'value': 'String'
                                                }
                                          }
                                    },
                                    'signature': {
                                          'raw': 'String',
                                          'signature_and_hash_type': {
                                                'hash_algorithm': 'String',
                                                'signature_algorithm': 'String'
                                          },
                                          'tls_version': {
                                                'name': 'String',
                                                'value': 'Number'
                                          },
                                          'type': 'String',
                                          'valid': 'Boolean'
                                    }
                              }
                        }
                  },
                  'smtps': {
                        'banner': 'String',
                        'ehlo': 'String',
                        'timestamp': 'Date',
                        'tls': {
                              'server_certificates': {
                                    'certificate': {
                                          'parsed': {
                                                'extensions': {
                                                      'authority_info_access': {
                                                            'issuer_urls': [],
                                                            'ocsp_urls': []
                                                      },
                                                      'authority_key_id': 'String',
                                                      'basic_constraints': { 'is_ca': 'Boolean' },
                                                      'certificate_policies': [{
                                                            'cps': [],
                                                            'id': 'String'
                                                      }],
                                                      'crl_distribution_points': [],
                                                      'extended_key_usage': {
                                                            'client_auth': 'Boolean',
                                                            'server_auth': 'Boolean'
                                                      },
                                                      'key_usage': {
                                                            'digital_signature': 'Boolean',
                                                            'key_encipherment': 'Boolean',
                                                            'value': 'Number'
                                                      },
                                                      'signed_certificate_timestamps': [{
                                                            'log_id': 'String',
                                                            'signature': 'String',
                                                            'timestamp': 'Number',
                                                            'version': 'Number'
                                                      }],
                                                      'subject_alt_name': { 'dns_names': [] },
                                                      'subject_key_id': 'String'
                                                },
                                                'fingerprint_md5': 'String',
                                                'fingerprint_sha1': 'String',
                                                'fingerprint_sha256': 'String',
                                                'issuer': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'email_address': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'issuer_dn': 'String',
                                                'names': [],
                                                'redacted': 'Boolean',
                                                'serial_number': 'String',
                                                'signature': {
                                                      'self_signed': 'Boolean',
                                                      'signature_algorithm': {
                                                            'name': 'String',
                                                            'oid': 'String'
                                                      },
                                                      'valid': 'Boolean',
                                                      'value': 'String'
                                                },
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'spki_subject_fingerprint': 'String',
                                                'subject': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'email_address': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'subject_dn': 'String',
                                                'subject_key_info': {
                                                      'fingerprint_sha256': 'String',
                                                      'key_algorithm': { 'name': 'String' },
                                                      'rsa_public_key': {
                                                            'exponent': 'Number',
                                                            'length': 'Number',
                                                            'modulus': 'String'
                                                      }
                                                },
                                                'tbs_fingerprint': 'String',
                                                'tbs_noct_fingerprint': 'String',
                                                'validation_level': 'String',
                                                'validity': {
                                                      'end': 'String',
                                                      'length': 'Number',
                                                      'start': 'String'
                                                },
                                                'version': 'Number'
                                          },
                                          'raw': 'String'
                                    },
                                    'chain': [{
                                          'parsed': {
                                                'extensions': {
                                                      'authority_info_access': {
                                                            'issuer_urls': [],
                                                            'ocsp_urls': []
                                                      },
                                                      'authority_key_id': 'String',
                                                      'basic_constraints': {
                                                            'is_ca': 'Boolean',
                                                            'max_path_len': 'Number'
                                                      },
                                                      'certificate_policies': [{
                                                            'cps': [],
                                                            'id': 'String'
                                                      }],
                                                      'crl_distribution_points': [],
                                                      'extended_key_usage': {
                                                            'client_auth': 'Boolean',
                                                            'server_auth': 'Boolean'
                                                      },
                                                      'key_usage': {
                                                            'certificate_sign': 'Boolean',
                                                            'crl_sign': 'Boolean',
                                                            'digital_signature': 'Boolean',
                                                            'value': 'Number'
                                                      },
                                                      'subject_key_id': 'String'
                                                },
                                                'fingerprint_md5': 'String',
                                                'fingerprint_sha1': 'String',
                                                'fingerprint_sha256': 'String',
                                                'issuer': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'issuer_dn': 'String',
                                                'redacted': 'Boolean',
                                                'serial_number': 'String',
                                                'signature': {
                                                      'self_signed': 'Boolean',
                                                      'signature_algorithm': {
                                                            'name': 'String',
                                                            'oid': 'String'
                                                      },
                                                      'valid': 'Boolean',
                                                      'value': 'String'
                                                },
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'spki_subject_fingerprint': 'String',
                                                'subject': {
                                                      'common_name': [],
                                                      'country': [],
                                                      'locality': [],
                                                      'organization': [],
                                                      'organizational_unit': [],
                                                      'province': []
                                                },
                                                'subject_dn': 'String',
                                                'subject_key_info': {
                                                      'fingerprint_sha256': 'String',
                                                      'key_algorithm': { 'name': 'String' },
                                                      'rsa_public_key': {
                                                            'exponent': 'Number',
                                                            'length': 'Number',
                                                            'modulus': 'String'
                                                      }
                                                },
                                                'tbs_fingerprint': 'String',
                                                'tbs_noct_fingerprint': 'String',
                                                'validation_level': 'String',
                                                'validity': {
                                                      'end': 'String',
                                                      'length': 'Number',
                                                      'start': 'String'
                                                },
                                                'version': 'Number'
                                          },
                                          'raw': 'String'
                                    }],
                                    'validation': {
                                          'browser_error': 'String',
                                          'browser_trusted': 'Boolean'
                                    }
                              },
                              'server_finished': { 'verify_data': 'String' },
                              'server_hello': {
                                    'cipher_suite': {
                                          'hex': 'String',
                                          'name': 'String',
                                          'value': 'Number'
                                    },
                                    'compression_method': 'Number',
                                    'extended_master_secret': 'Boolean',
                                    'heartbeat': 'Boolean',
                                    'ocsp_stapling': 'Boolean',
                                    'random': 'String',
                                    'secure_renegotiation': 'Boolean',
                                    'session_id': 'String',
                                    'ticket': 'Boolean',
                                    'version': {
                                          'name': 'String',
                                          'value': 'Number'
                                    }
                              },
                              'server_key_exchange': {
                                    'digest': 'String',
                                    'ecdh_params': {
                                          'curve_id': {
                                                'id': 'Number',
                                                'name': 'String'
                                          },
                                          'server_public': {
                                                'x': {
                                                      'length': 'Number',
                                                      'value': 'String'
                                                },
                                                'y': {
                                                      'length': 'Number',
                                                      'value': 'String'
                                                }
                                          }
                                    },
                                    'signature': {
                                          'raw': 'String',
                                          'signature_and_hash_type': {
                                                'hash_algorithm': 'String',
                                                'signature_algorithm': 'String'
                                          },
                                          'tls_version': {
                                                'name': 'String',
                                                'value': 'Number'
                                          },
                                          'type': 'String',
                                          'valid': 'Boolean'
                                    }
                              }
                        }
                  },
                  'tls': {
                        'server_certificates': {
                              'certificate': {
                                    'parsed': {
                                          'extensions': {
                                                'authority_info_access': {
                                                      'issuer_urls': [],
                                                      'ocsp_urls': []
                                                },
                                                'authority_key_id': 'String',
                                                'basic_constraints': { 'is_ca': 'Boolean' },
                                                'certificate_policies': [{
                                                      'cps': [],
                                                      'id': 'String',
                                                      'user_notice': [{ 'explicit_text': 'String' }]
                                                }],
                                                'crl_distribution_points': [],
                                                'extended_key_usage': {
                                                      'client_auth': 'Boolean',
                                                      'email_protection': 'Boolean',
                                                      'ipsec_end_system': 'Boolean',
                                                      'ipsec_tunnel': 'Boolean',
                                                      'ipsec_user': 'Boolean',
                                                      'microsoft_server_gated_crypto': 'Boolean',
                                                      'netscape_server_gated_crypto': 'Boolean',
                                                      'server_auth': 'Boolean',
                                                      'unknown': []
                                                },
                                                'issuer_alt_name': {
                                                      'email_addresses': [],
                                                      'uniform_resource_identifiers': []
                                                },
                                                'key_usage': {
                                                      'certificate_sign': 'Boolean',
                                                      'content_commitment': 'Boolean',
                                                      'crl_sign': 'Boolean',
                                                      'data_encipherment': 'Boolean',
                                                      'digital_signature': 'Boolean',
                                                      'key_agreement': 'Boolean',
                                                      'key_encipherment': 'Boolean',
                                                      'value': 'Number'
                                                },
                                                'signed_certificate_timestamps': [{
                                                      'log_id': 'String',
                                                      'signature': 'String',
                                                      'timestamp': 'Number',
                                                      'version': 'Number'
                                                }],
                                                'subject_alt_name': {
                                                      'dns_names': [],
                                                      'email_addresses': [],
                                                      'ip_addresses': [],
                                                      'uniform_resource_identifiers': []
                                                },
                                                'subject_key_id': 'String'
                                          },
                                          'fingerprint_md5': 'String',
                                          'fingerprint_sha1': 'String',
                                          'fingerprint_sha256': 'String',
                                          'issuer': {
                                                'common_name': [],
                                                'country': [],
                                                'domain_component': [],
                                                'email_address': [],
                                                'locality': [],
                                                'organization': [],
                                                'organizational_unit': [],
                                                'postal_code': [],
                                                'province': [],
                                                'serial_number': []
                                          },
                                          'issuer_dn': 'String',
                                          'names': [],
                                          'redacted': 'Boolean',
                                          'serial_number': 'String',
                                          'signature': {
                                                'self_signed': 'Boolean',
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'valid': 'Boolean',
                                                'value': 'String'
                                          },
                                          'signature_algorithm': {
                                                'name': 'String',
                                                'oid': 'String'
                                          },
                                          'spki_subject_fingerprint': 'String',
                                          'subject': {
                                                'common_name': [],
                                                'country': [],
                                                'domain_component': [],
                                                'email_address': [],
                                                'jurisdiction_country': [],
                                                'jurisdiction_locality': [],
                                                'jurisdiction_province': [],
                                                'locality': [],
                                                'organization': [],
                                                'organizational_unit': [],
                                                'postal_code': [],
                                                'province': [],
                                                'serial_number': [],
                                                'street_address': []
                                          },
                                          'subject_dn': 'String',
                                          'subject_key_info': {
                                                'ecdsa_public_key': {
                                                      'b': 'String',
                                                      'curve': 'String',
                                                      'gx': 'String',
                                                      'gy': 'String',
                                                      'length': 'Number',
                                                      'n': 'String',
                                                      'p': 'String',
                                                      'pub': 'String',
                                                      'x': 'String',
                                                      'y': 'String'
                                                },
                                                'fingerprint_sha256': 'String',
                                                'key_algorithm': { 'name': 'String' },
                                                'rsa_public_key': {
                                                      'exponent': 'Number',
                                                      'length': 'Number',
                                                      'modulus': 'String'
                                                }
                                          },
                                          'tbs_fingerprint': 'String',
                                          'tbs_noct_fingerprint': 'String',
                                          'unknown_extensions': [{
                                                'critical': 'Boolean',
                                                'id': 'String',
                                                'value': 'String'
                                          }],
                                          'validation_level': 'String',
                                          'validity': {
                                                'end': 'String',
                                                'length': 'Number',
                                                'start': 'String'
                                          },
                                          'version': 'Number'
                                    },
                                    'raw': 'String'
                              },
                              'chain': [{
                                    'parsed': {
                                          'extensions': {
                                                'authority_info_access': {
                                                      'issuer_urls': [],
                                                      'ocsp_urls': []
                                                },
                                                'authority_key_id': 'String',
                                                'basic_constraints': {
                                                      'is_ca': 'Boolean',
                                                      'max_path_len': 'Number'
                                                },
                                                'certificate_policies': [{
                                                      'cps': [],
                                                      'id': 'String',
                                                      'user_notice': [{
                                                            'explicit_text': 'String',
                                                            'notice_reference': [{ 'organization': 'String' }]
                                                      }]
                                                }],
                                                'crl_distribution_points': [],
                                                'extended_key_usage': {
                                                      'client_auth': 'Boolean',
                                                      'code_signing': 'Boolean',
                                                      'email_protection': 'Boolean',
                                                      'ipsec_end_system': 'Boolean',
                                                      'ipsec_tunnel': 'Boolean',
                                                      'ipsec_user': 'Boolean',
                                                      'microsoft_ca_exchange': 'Boolean',
                                                      'microsoft_server_gated_crypto': 'Boolean',
                                                      'netscape_server_gated_crypto': 'Boolean',
                                                      'ocsp_signing': 'Boolean',
                                                      'server_auth': 'Boolean',
                                                      'unknown': []
                                                },
                                                'issuer_alt_name': { 'email_addresses': [] },
                                                'key_usage': {
                                                      'certificate_sign': 'Boolean',
                                                      'content_commitment': 'Boolean',
                                                      'crl_sign': 'Boolean',
                                                      'data_encipherment': 'Boolean',
                                                      'digital_signature': 'Boolean',
                                                      'key_encipherment': 'Boolean',
                                                      'value': 'Number'
                                                },
                                                'name_constraints': {
                                                      'critical': 'Boolean',
                                                      'excluded_ip_addresses': [{
                                                            'begin': 'String',
                                                            'cidr': 'String',
                                                            'end': 'String',
                                                            'mask': 'String'
                                                      }],
                                                      'permitted_directory_names': [{
                                                            'country': [],
                                                            'domain_component': [],
                                                            'locality': [],
                                                            'organization': [],
                                                            'province': []
                                                      }],
                                                      'permitted_email_addresses': [],
                                                      'permitted_names': []
                                                },
                                                'signed_certificate_timestamps': [{
                                                      'log_id': 'String',
                                                      'signature': 'String',
                                                      'timestamp': 'Number',
                                                      'version': 'Number'
                                                }],
                                                'subject_alt_name': {
                                                      'directory_names': [{ 'common_name': [] }],
                                                      'dns_names': [],
                                                      'email_addresses': [],
                                                      'uniform_resource_identifiers': []
                                                },
                                                'subject_key_id': 'String'
                                          },
                                          'fingerprint_md5': 'String',
                                          'fingerprint_sha1': 'String',
                                          'fingerprint_sha256': 'String',
                                          'issuer': {
                                                'common_name': [],
                                                'country': [],
                                                'domain_component': [],
                                                'email_address': [],
                                                'locality': [],
                                                'organization': [],
                                                'organizational_unit': [],
                                                'province': []
                                          },
                                          'issuer_dn': 'String',
                                          'names': [],
                                          'redacted': 'Boolean',
                                          'serial_number': 'String',
                                          'signature': {
                                                'self_signed': 'Boolean',
                                                'signature_algorithm': {
                                                      'name': 'String',
                                                      'oid': 'String'
                                                },
                                                'valid': 'Boolean',
                                                'value': 'String'
                                          },
                                          'signature_algorithm': {
                                                'name': 'String',
                                                'oid': 'String'
                                          },
                                          'spki_subject_fingerprint': 'String',
                                          'subject': {
                                                'common_name': [],
                                                'country': [],
                                                'domain_component': [],
                                                'email_address': [],
                                                'jurisdiction_country': [],
                                                'jurisdiction_province': [],
                                                'locality': [],
                                                'organization': [],
                                                'organizational_unit': [],
                                                'postal_code': [],
                                                'province': [],
                                                'serial_number': [],
                                                'street_address': []
                                          },
                                          'subject_dn': 'String',
                                          'subject_key_info': {
                                                'ecdsa_public_key': {
                                                      'b': 'String',
                                                      'curve': 'String',
                                                      'gx': 'String',
                                                      'gy': 'String',
                                                      'length': 'Number',
                                                      'n': 'String',
                                                      'p': 'String',
                                                      'pub': 'String',
                                                      'x': 'String',
                                                      'y': 'String'
                                                },
                                                'fingerprint_sha256': 'String',
                                                'key_algorithm': { 'name': 'String' },
                                                'rsa_public_key': {
                                                      'exponent': 'Number',
                                                      'length': 'Number',
                                                      'modulus': 'String'
                                                }
                                          },
                                          'tbs_fingerprint': 'String',
                                          'tbs_noct_fingerprint': 'String',
                                          'unknown_extensions': [{
                                                'critical': 'Boolean',
                                                'id': 'String',
                                                'value': 'String'
                                          }],
                                          'validation_level': 'String',
                                          'validity': {
                                                'end': 'String',
                                                'length': 'Number',
                                                'start': 'String'
                                          },
                                          'version': 'Number'
                                    },
                                    'raw': 'String'
                              }],
                              'validation': {
                                    'browser_error': 'String',
                                    'browser_trusted': 'Boolean'
                              }
                        },
                        'server_finished': { 'verify_data': 'String' },
                        'server_hello': {
                              'cipher_suite': {
                                    'hex': 'String',
                                    'name': 'String',
                                    'value': 'Number'
                              },
                              'compression_method': 'Number',
                              'extended_master_secret': 'Boolean',
                              'heartbeat': 'Boolean',
                              'ocsp_stapling': 'Boolean',
                              'random': 'String',
                              'scts': [{
                                    'parsed': {
                                          'log_id': 'String',
                                          'signature': 'String',
                                          'timestamp': 'Number',
                                          'version': 'Number'
                                    },
                                    'raw': 'String'
                              }],
                              'secure_renegotiation': 'Boolean',
                              'session_id': 'String',
                              'ticket': 'Boolean',
                              'version': {
                                    'name': 'String',
                                    'value': 'Number'
                              }
                        },
                        'server_key_exchange': {
                              'dh_params': {
                                    'generator': {
                                          'length': 'Number',
                                          'value': 'String'
                                    },
                                    'prime': {
                                          'length': 'Number',
                                          'value': 'String'
                                    },
                                    'server_public': {
                                          'length': 'Number',
                                          'value': 'String'
                                    }
                              },
                              'digest': 'String',
                              'ecdh_params': {
                                    'curve_id': {
                                          'id': 'Number',
                                          'name': 'String'
                                    },
                                    'server_public': {
                                          'x': {
                                                'length': 'Number',
                                                'value': 'String'
                                          },
                                          'y': {
                                                'length': 'Number',
                                                'value': 'String'
                                          }
                                    }
                              },
                              'signature': {
                                    'raw': 'String',
                                    'signature_and_hash_type': {
                                          'hash_algorithm': 'String',
                                          'signature_algorithm': 'String'
                                    },
                                    'tls_version': {
                                          'name': 'String',
                                          'value': 'Number'
                                    },
                                    'type': 'String',
                                    'valid': 'Boolean'
                              }
                        },
                        'timestamp': 'Date'
                  }
            },
            'ip': 'String',
            'timestamp': 'Date',
            'tracked': 'Boolean',
            'zones': [],
      }, { collection: 'zgrab_port_data' });

var zgrabPortModel = mongoose.model('zgrabPortModel', zgrabPortSchema);

module.exports = { zgrabPortModel: zgrabPortModel };
