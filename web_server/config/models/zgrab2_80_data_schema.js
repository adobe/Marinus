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

// Zgrab 2.0 80 Schema
// - The definition is based on a variety.js dump of data collected in the database.
// - In theory it should match: https://github.com/zmap/zgrab2/blob/master/zgrab2_schemas/zgrab2/http.py.
var zgrab2_80_schema = new Schema(
      {
            '_id': 'ObjectId',
            'aws': Boolean,
            'azure': Boolean,
            'data': {
                  'http': {
                        'protocol': String,
                        'result': {
                              'redirect_response_chain': [{
                                    'body': String,
                                    'body_sha256': String,
                                    'content_length': Number,
                                    'headers': {
                                          'accept_ranges': [],
                                          'access_control_allow_origin': [],
                                          'age': [],
                                          'cache_control': [],
                                          'connection': [],
                                          'content_encoding': [],
                                          'content_language': [],
                                          'content_length': [],
                                          'content_location': [],
                                          'content_security_policy': [],
                                          'content_type': [],
                                          'date': [],
                                          'etag': [],
                                          'expires': [],
                                          'last_modified': [],
                                          'link': [],
                                          'location': [],
                                          'p3p': [],
                                          'pragma': [],
                                          'retry_after': [],
                                          'server': [],
                                          'set_cookie': [],
                                          'status': [],
                                          'strict_transport_security': [],
                                          'unknown': [{
                                                'key': String,
                                                'value': []
                                          }],
                                          'upgrade': [],
                                          'vary': [],
                                          'via': [],
                                          'x_content_security_policy': [],
                                          'x_content_type_options': [],
                                          'x_frame_options': [],
                                          'x_powered_by': [],
                                          'x_ua_compatible': [],
                                          'x_webkit_csp': [],
                                          'x_xss_protection': []
                                    },
                                    'protocol': {
                                          'major': Number,
                                          'minor': Number,
                                          'name': String
                                    },
                                    'request': {
                                          'headers': {
                                                'accept': [],
                                                'referer': [],
                                                'user_agent': []
                                          },
                                          'host': String,
                                          'method': String,
                                          'tls_log': {
                                                'handshake_log': {
                                                      'client_finished': { 'verify_data': String },
                                                      'client_key_exchange': {
                                                            'ecdh_params': {
                                                                  'client_private': {
                                                                        'length': Number,
                                                                        'value': String
                                                                  },
                                                                  'client_public': {
                                                                        'x': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        },
                                                                        'y': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        }
                                                                  },
                                                                  'curve_id': {
                                                                        'id': Number,
                                                                        'name': String
                                                                  }
                                                            },
                                                            'rsa_params': {
                                                                  'encrypted_pre_master_secret': String,
                                                                  'length': Number
                                                            }
                                                      },
                                                      'key_material': {
                                                            'master_secret': {
                                                                  'length': Number,
                                                                  'value': String
                                                            },
                                                            'pre_master_secret': {
                                                                  'length': Number,
                                                                  'value': String
                                                            }
                                                      },
                                                      'server_certificates': {
                                                            'certificate': {
                                                                  'parsed': {
                                                                        'extensions': {
                                                                              'authority_info_access': {
                                                                                    'issuer_urls': [],
                                                                                    'ocsp_urls': []
                                                                              },
                                                                              'authority_key_id': String,
                                                                              'basic_constraints': { 'is_ca': Boolean },
                                                                              'certificate_policies': [{
                                                                                    'cps': [],
                                                                                    'id': String,
                                                                                    'user_notice': [{ 'explicit_text': String }]
                                                                              }],
                                                                              'crl_distribution_points': [],
                                                                              'extended_key_usage': {
                                                                                    'client_auth': Boolean,
                                                                                    'server_auth': Boolean
                                                                              },
                                                                              'key_usage': {
                                                                                    'content_commitment': Boolean,
                                                                                    'data_encipherment': Boolean,
                                                                                    'digital_signature': Boolean,
                                                                                    'key_encipherment': Boolean,
                                                                                    'value': Number
                                                                              },
                                                                              'signed_certificate_timestamps': [{
                                                                                    'log_id': String,
                                                                                    'signature': String,
                                                                                    'timestamp': Number,
                                                                                    'version': Number
                                                                              }],
                                                                              'subject_alt_name': { 'dns_names': [] },
                                                                              'subject_key_id': String
                                                                        },
                                                                        'fingerprint_md5': String,
                                                                        'fingerprint_sha1': String,
                                                                        'fingerprint_sha256': String,
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
                                                                        'issuer_dn': String,
                                                                        'names': [],
                                                                        'redacted': Boolean,
                                                                        'serial_number': String,
                                                                        'signature': {
                                                                              'self_signed': Boolean,
                                                                              'signature_algorithm': {
                                                                                    'name': String,
                                                                                    'oid': String
                                                                              },
                                                                              'valid': Boolean,
                                                                              'value': String
                                                                        },
                                                                        'signature_algorithm': {
                                                                              'name': String,
                                                                              'oid': String
                                                                        },
                                                                        'spki_subject_fingerprint': String,
                                                                        'subject': {
                                                                              'common_name': [],
                                                                              'country': [],
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
                                                                        'subject_dn': String,
                                                                        'subject_key_info': {
                                                                              'ecdsa_public_key': {
                                                                                    'b': String,
                                                                                    'curve': String,
                                                                                    'gx': String,
                                                                                    'gy': String,
                                                                                    'length': Number,
                                                                                    'n': String,
                                                                                    'p': String,
                                                                                    'pub': String,
                                                                                    'x': String,
                                                                                    'y': String
                                                                              },
                                                                              'fingerprint_sha256': String,
                                                                              'key_algorithm': { 'name': String },
                                                                              'rsa_public_key': {
                                                                                    'exponent': Number,
                                                                                    'length': Number,
                                                                                    'modulus': String
                                                                              }
                                                                        },
                                                                        'tbs_fingerprint': String,
                                                                        'tbs_noct_fingerprint': String,
                                                                        'unknown_extensions': [{
                                                                              'critical': Boolean,
                                                                              'id': String,
                                                                              'value': String
                                                                        }],
                                                                        'validation_level': String,
                                                                        'validity': {
                                                                              'end': String,
                                                                              'length': Number,
                                                                              'start': String
                                                                        },
                                                                        'version': Number
                                                                  },
                                                                  'raw': String
                                                            },
                                                            'chain': [{
                                                                  'parsed': {
                                                                        'extensions': {
                                                                              'authority_info_access': {
                                                                                    'issuer_urls': [],
                                                                                    'ocsp_urls': []
                                                                              },
                                                                              'authority_key_id': String,
                                                                              'basic_constraints': {
                                                                                    'is_ca': Boolean,
                                                                                    'max_path_len': Number
                                                                              },
                                                                              'certificate_policies': [{
                                                                                    'cps': [],
                                                                                    'id': String,
                                                                                    'user_notice': [{ 'explicit_text': String }]
                                                                              }],
                                                                              'crl_distribution_points': [],
                                                                              'extended_key_usage': {
                                                                                    'client_auth': Boolean,
                                                                                    'ocsp_signing': Boolean,
                                                                                    'server_auth': Boolean
                                                                              },
                                                                              'key_usage': {
                                                                                    'certificate_sign': Boolean,
                                                                                    'crl_sign': Boolean,
                                                                                    'digital_signature': Boolean,
                                                                                    'key_encipherment': Boolean,
                                                                                    'value': Number
                                                                              },
                                                                              'signed_certificate_timestamps': [{
                                                                                    'log_id': String,
                                                                                    'signature': String,
                                                                                    'timestamp': Number,
                                                                                    'version': Number
                                                                              }],
                                                                              'subject_alt_name': {
                                                                                    'directory_names': [{ 'common_name': [] }],
                                                                                    'dns_names': []
                                                                              },
                                                                              'subject_key_id': String
                                                                        },
                                                                        'fingerprint_md5': String,
                                                                        'fingerprint_sha1': String,
                                                                        'fingerprint_sha256': String,
                                                                        'issuer': {
                                                                              'common_name': [],
                                                                              'country': [],
                                                                              'locality': [],
                                                                              'organization': [],
                                                                              'organizational_unit': [],
                                                                              'province': []
                                                                        },
                                                                        'issuer_dn': String,
                                                                        'names': [],
                                                                        'redacted': Boolean,
                                                                        'serial_number': String,
                                                                        'signature': {
                                                                              'self_signed': Boolean,
                                                                              'signature_algorithm': {
                                                                                    'name': String,
                                                                                    'oid': String
                                                                              },
                                                                              'valid': Boolean,
                                                                              'value': String
                                                                        },
                                                                        'signature_algorithm': {
                                                                              'name': String,
                                                                              'oid': String
                                                                        },
                                                                        'spki_subject_fingerprint': String,
                                                                        'subject': {
                                                                              'common_name': [],
                                                                              'country': [],
                                                                              'domain_component': [],
                                                                              'locality': [],
                                                                              'organization': [],
                                                                              'organizational_unit': [],
                                                                              'province': []
                                                                        },
                                                                        'subject_dn': String,
                                                                        'subject_key_info': {
                                                                              'ecdsa_public_key': {
                                                                                    'b': String,
                                                                                    'curve': String,
                                                                                    'gx': String,
                                                                                    'gy': String,
                                                                                    'length': Number,
                                                                                    'n': String,
                                                                                    'p': String,
                                                                                    'pub': String,
                                                                                    'x': String,
                                                                                    'y': String
                                                                              },
                                                                              'fingerprint_sha256': String,
                                                                              'key_algorithm': { 'name': String },
                                                                              'rsa_public_key': {
                                                                                    'exponent': Number,
                                                                                    'length': Number,
                                                                                    'modulus': String
                                                                              }
                                                                        },
                                                                        'tbs_fingerprint': String,
                                                                        'tbs_noct_fingerprint': String,
                                                                        'unknown_extensions': [{
                                                                              'critical': Boolean,
                                                                              'id': String,
                                                                              'value': String
                                                                        }],
                                                                        'validation_level': String,
                                                                        'validity': {
                                                                              'end': String,
                                                                              'length': Number,
                                                                              'start': String
                                                                        },
                                                                        'version': Number
                                                                  },
                                                                  'raw': String
                                                            }],
                                                            'validation': {
                                                                  'browser_error': String,
                                                                  'browser_trusted': Boolean
                                                            }
                                                      },
                                                      'server_finished': { 'verify_data': String },
                                                      'server_hello': {
                                                            'cipher_suite': {
                                                                  'hex': String,
                                                                  'name': String,
                                                                  'value': Number
                                                            },
                                                            'compression_method': Number,
                                                            'extended_master_secret': Boolean,
                                                            'heartbeat': Boolean,
                                                            'ocsp_stapling': Boolean,
                                                            'random': String,
                                                            'secure_renegotiation': Boolean,
                                                            'session_id': String,
                                                            'ticket': Boolean,
                                                            'version': {
                                                                  'name': String,
                                                                  'value': Number
                                                            }
                                                      },
                                                      'server_key_exchange': {
                                                            'digest': String,
                                                            'ecdh_params': {
                                                                  'curve_id': {
                                                                        'id': Number,
                                                                        'name': String
                                                                  },
                                                                  'server_public': {
                                                                        'x': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        },
                                                                        'y': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        }
                                                                  }
                                                            },
                                                            'signature': {
                                                                  'raw': String,
                                                                  'signature_and_hash_type': {
                                                                        'hash_algorithm': String,
                                                                        'signature_algorithm': String
                                                                  },
                                                                  'tls_version': {
                                                                        'name': String,
                                                                        'value': Number
                                                                  },
                                                                  'type': String,
                                                                  'valid': Boolean
                                                            }
                                                      }
                                                }
                                          },
                                          'url': {
                                                'fragment': String,
                                                'host': String,
                                                'path': String,
                                                'raw_path': String,
                                                'raw_query': String,
                                                'scheme': String
                                          }
                                    },
                                    'status_code': Number,
                                    'status_line': String,
                                    'transfer_encoding': []
                              }],
                              'response': {
                                    'body': String,
                                    'body_sha256': String,
                                    'content_length': Number,
                                    'headers': {
                                          'accept': [],
                                          'accept_charset': [],
                                          'accept_encoding': [],
                                          'accept_ranges': [],
                                          'access_control_allow_origin': [],
                                          'age': [],
                                          'allow': [],
                                          'alt_svc': [],
                                          'cache_control': [],
                                          'connection': [],
                                          'content_disposition': [],
                                          'content_language': [],
                                          'content_length': [],
                                          'content_location': [],
                                          'content_md5': [],
                                          'content_security_policy': [],
                                          'content_type': [],
                                          'date': [],
                                          'etag': [],
                                          'expires': [],
                                          'host': [],
                                          'if_modified_since': [],
                                          'last_modified': [],
                                          'link': [],
                                          'location': [],
                                          'p3p': [],
                                          'pragma': [],
                                          'public_key_pins': [],
                                          'referer': [],
                                          'refresh': [],
                                          'retry_after': [],
                                          'server': [],
                                          'set_cookie': [],
                                          'status': [],
                                          'strict_transport_security': [],
                                          'unknown': [{
                                                'key': String,
                                                'value': []
                                          }],
                                          'upgrade': [],
                                          'user_agent': [],
                                          'vary': [],
                                          'via': [],
                                          'www_authenticate': [],
                                          'x_content_security_policy': [],
                                          'x_content_type_options': [],
                                          'x_forwarded_for': [],
                                          'x_frame_options': [],
                                          'x_powered_by': [],
                                          'x_real_ip': [],
                                          'x_ua_compatible': [],
                                          'x_webkit_csp': [],
                                          'x_xss_protection': []
                                    },
                                    'protocol': {
                                          'major': Number,
                                          'minor': Number,
                                          'name': String
                                    },
                                    'request': {
                                          'headers': {
                                                'accept': [],
                                                'referer': [],
                                                'user_agent': []
                                          },
                                          'host': String,
                                          'method': String,
                                          'tls_log': {
                                                'handshake_log': {
                                                      'client_finished': { 'verify_data': String },
                                                      'client_key_exchange': {
                                                            'ecdh_params': {
                                                                  'client_private': {
                                                                        'length': Number,
                                                                        'value': String
                                                                  },
                                                                  'client_public': {
                                                                        'x': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        },
                                                                        'y': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        }
                                                                  },
                                                                  'curve_id': {
                                                                        'id': Number,
                                                                        'name': String
                                                                  }
                                                            },
                                                            'rsa_params': {
                                                                  'encrypted_pre_master_secret': String,
                                                                  'length': Number
                                                            }
                                                      },
                                                      'key_material': {
                                                            'master_secret': {
                                                                  'length': Number,
                                                                  'value': String
                                                            },
                                                            'pre_master_secret': {
                                                                  'length': Number,
                                                                  'value': String
                                                            }
                                                      },
                                                      'server_certificates': {
                                                            'certificate': {
                                                                  'parsed': {
                                                                        'extensions': {
                                                                              'authority_info_access': {
                                                                                    'issuer_urls': [],
                                                                                    'ocsp_urls': []
                                                                              },
                                                                              'authority_key_id': String,
                                                                              'basic_constraints': { 'is_ca': Boolean },
                                                                              'certificate_policies': [{
                                                                                    'cps': [],
                                                                                    'id': String,
                                                                                    'user_notice': [{ 'explicit_text': String }]
                                                                              }],
                                                                              'crl_distribution_points': [],
                                                                              'extended_key_usage': {
                                                                                    'client_auth': Boolean,
                                                                                    'ipsec_end_system': Boolean,
                                                                                    'ipsec_tunnel': Boolean,
                                                                                    'ipsec_user': Boolean,
                                                                                    'server_auth': Boolean
                                                                              },
                                                                              'key_usage': {
                                                                                    'certificate_sign': Boolean,
                                                                                    'content_commitment': Boolean,
                                                                                    'data_encipherment': Boolean,
                                                                                    'digital_signature': Boolean,
                                                                                    'key_encipherment': Boolean,
                                                                                    'value': Number
                                                                              },
                                                                              'signed_certificate_timestamps': [{
                                                                                    'log_id': String,
                                                                                    'signature': String,
                                                                                    'timestamp': Number,
                                                                                    'version': Number
                                                                              }],
                                                                              'subject_alt_name': { 'dns_names': [] },
                                                                              'subject_key_id': String
                                                                        },
                                                                        'fingerprint_md5': String,
                                                                        'fingerprint_sha1': String,
                                                                        'fingerprint_sha256': String,
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
                                                                        'issuer_dn': String,
                                                                        'names': [],
                                                                        'redacted': Boolean,
                                                                        'serial_number': String,
                                                                        'signature': {
                                                                              'self_signed': Boolean,
                                                                              'signature_algorithm': {
                                                                                    'name': String,
                                                                                    'oid': String
                                                                              },
                                                                              'valid': Boolean,
                                                                              'value': String
                                                                        },
                                                                        'signature_algorithm': {
                                                                              'name': String,
                                                                              'oid': String
                                                                        },
                                                                        'spki_subject_fingerprint': String,
                                                                        'subject': {
                                                                              'common_name': [],
                                                                              'country': [],
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
                                                                        'subject_dn': String,
                                                                        'subject_key_info': {
                                                                              'ecdsa_public_key': {
                                                                                    'b': String,
                                                                                    'curve': String,
                                                                                    'gx': String,
                                                                                    'gy': String,
                                                                                    'length': Number,
                                                                                    'n': String,
                                                                                    'p': String,
                                                                                    'pub': String,
                                                                                    'x': String,
                                                                                    'y': String
                                                                              },
                                                                              'fingerprint_sha256': String,
                                                                              'key_algorithm': { 'name': String },
                                                                              'rsa_public_key': {
                                                                                    'exponent': Number,
                                                                                    'length': Number,
                                                                                    'modulus': String
                                                                              }
                                                                        },
                                                                        'tbs_fingerprint': String,
                                                                        'tbs_noct_fingerprint': String,
                                                                        'unknown_extensions': [{
                                                                              'critical': Boolean,
                                                                              'id': String,
                                                                              'value': String
                                                                        }],
                                                                        'validation_level': String,
                                                                        'validity': {
                                                                              'end': String,
                                                                              'length': Number,
                                                                              'start': String
                                                                        },
                                                                        'version': Number
                                                                  },
                                                                  'raw': String
                                                            },
                                                            'chain': [{
                                                                  'parsed': {
                                                                        'extensions': {
                                                                              'authority_info_access': {
                                                                                    'issuer_urls': [],
                                                                                    'ocsp_urls': []
                                                                              },
                                                                              'authority_key_id': String,
                                                                              'basic_constraints': {
                                                                                    'is_ca': Boolean,
                                                                                    'max_path_len': Number
                                                                              },
                                                                              'certificate_policies': [{
                                                                                    'cps': [],
                                                                                    'id': String,
                                                                                    'user_notice': [{ 'explicit_text': String }]
                                                                              }],
                                                                              'crl_distribution_points': [],
                                                                              'extended_key_usage': {
                                                                                    'client_auth': Boolean,
                                                                                    'ocsp_signing': Boolean,
                                                                                    'server_auth': Boolean
                                                                              },
                                                                              'key_usage': {
                                                                                    'certificate_sign': Boolean,
                                                                                    'content_commitment': Boolean,
                                                                                    'crl_sign': Boolean,
                                                                                    'digital_signature': Boolean,
                                                                                    'key_encipherment': Boolean,
                                                                                    'value': Number
                                                                              },
                                                                              'signed_certificate_timestamps': [{
                                                                                    'log_id': String,
                                                                                    'signature': String,
                                                                                    'timestamp': Number,
                                                                                    'version': Number
                                                                              }],
                                                                              'subject_alt_name': {
                                                                                    'directory_names': [{ 'common_name': [] }],
                                                                                    'dns_names': [],
                                                                                    'email_addresses': []
                                                                              },
                                                                              'subject_key_id': String
                                                                        },
                                                                        'fingerprint_md5': String,
                                                                        'fingerprint_sha1': String,
                                                                        'fingerprint_sha256': String,
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
                                                                        'issuer_dn': String,
                                                                        'names': [],
                                                                        'redacted': Boolean,
                                                                        'serial_number': String,
                                                                        'signature': {
                                                                              'self_signed': Boolean,
                                                                              'signature_algorithm': {
                                                                                    'name': String,
                                                                                    'oid': String
                                                                              },
                                                                              'valid': Boolean,
                                                                              'value': String
                                                                        },
                                                                        'signature_algorithm': {
                                                                              'name': String,
                                                                              'oid': String
                                                                        },
                                                                        'spki_subject_fingerprint': String,
                                                                        'subject': {
                                                                              'common_name': [],
                                                                              'country': [],
                                                                              'domain_component': [],
                                                                              'email_address': [],
                                                                              'locality': [],
                                                                              'organization': [],
                                                                              'organizational_unit': [],
                                                                              'province': []
                                                                        },
                                                                        'subject_dn': String,
                                                                        'subject_key_info': {
                                                                              'ecdsa_public_key': {
                                                                                    'b': String,
                                                                                    'curve': String,
                                                                                    'gx': String,
                                                                                    'gy': String,
                                                                                    'length': Number,
                                                                                    'n': String,
                                                                                    'p': String,
                                                                                    'pub': String,
                                                                                    'x': String,
                                                                                    'y': String
                                                                              },
                                                                              'fingerprint_sha256': String,
                                                                              'key_algorithm': { 'name': String },
                                                                              'rsa_public_key': {
                                                                                    'exponent': Number,
                                                                                    'length': Number,
                                                                                    'modulus': String
                                                                              }
                                                                        },
                                                                        'tbs_fingerprint': String,
                                                                        'tbs_noct_fingerprint': String,
                                                                        'unknown_extensions': [{
                                                                              'critical': Boolean,
                                                                              'id': String,
                                                                              'value': String
                                                                        }],
                                                                        'validation_level': String,
                                                                        'validity': {
                                                                              'end': String,
                                                                              'length': Number,
                                                                              'start': String
                                                                        },
                                                                        'version': Number
                                                                  },
                                                                  'raw': String
                                                            }],
                                                            'validation': {
                                                                  'browser_error': String,
                                                                  'browser_trusted': Boolean
                                                            }
                                                      },
                                                      'server_finished': { 'verify_data': String },
                                                      'server_hello': {
                                                            'cipher_suite': {
                                                                  'hex': String,
                                                                  'name': String,
                                                                  'value': Number
                                                            },
                                                            'compression_method': Number,
                                                            'extended_master_secret': Boolean,
                                                            'heartbeat': Boolean,
                                                            'ocsp_stapling': Boolean,
                                                            'random': String,
                                                            'secure_renegotiation': Boolean,
                                                            'session_id': String,
                                                            'ticket': Boolean,
                                                            'version': {
                                                                  'name': String,
                                                                  'value': Number
                                                            }
                                                      },
                                                      'server_key_exchange': {
                                                            'digest': String,
                                                            'ecdh_params': {
                                                                  'curve_id': {
                                                                        'id': Number,
                                                                        'name': String
                                                                  },
                                                                  'server_public': {
                                                                        'x': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        },
                                                                        'y': {
                                                                              'length': Number,
                                                                              'value': String
                                                                        }
                                                                  }
                                                            },
                                                            'signature': {
                                                                  'raw': String,
                                                                  'signature_and_hash_type': {
                                                                        'hash_algorithm': String,
                                                                        'signature_algorithm': String
                                                                  },
                                                                  'tls_version': {
                                                                        'name': String,
                                                                        'value': Number
                                                                  },
                                                                  'type': String,
                                                                  'valid': Boolean
                                                            }
                                                      }
                                                }
                                          },
                                          'url': {
                                                'fragment': String,
                                                'host': String,
                                                'path': String,
                                                'raw_path': String,
                                                'raw_query': String,
                                                'scheme': String
                                          }
                                    },
                                    'status_code': Number,
                                    'status_line': String,
                                    'transfer_encoding': []
                              }
                        },
                        'status': String,
                        'timestamp': Date
                  }
            },
            'domain': String,
            'ip': String,
            'timestamp': Date,
            'tracked': Boolean,
            'zones': [],
      }, { collection: 'zgrab_80_data' });

var zgrab2_80_model = mongoose.model('zgrab2_80_model', zgrab2_80_schema);

module.exports = { zgrab2_80_model: zgrab2_80_model };

