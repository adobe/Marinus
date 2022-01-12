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

// Zgrab 2.0 Port Schema
// - The core is based on a variety.js dump of data collected in the database.
// - In theory it should match: https://github.com/zmap/zgrab2/tree/master/zgrab2_schemas/zgrab2
var zgrab2PortSchema = new Schema(
      {
            '_id': 'ObjectId',
            'aws': Boolean,
            'azure': Boolean,
            'data': {
                  'smtp': {
                        'protocol': String,
                        'result': {
                              'banner': String,
                              'starttls': String,
                              'tls': {
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
                                                                        'id': String
                                                                  }],
                                                                  'crl_distribution_points': [],
                                                                  'extended_key_usage': {
                                                                        'client_auth': Boolean,
                                                                        'server_auth': Boolean
                                                                  },
                                                                  'key_usage': {
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
                                                                  'email_address': [],
                                                                  'locality': [],
                                                                  'organization': [],
                                                                  'organizational_unit': []
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
                                                                  'locality': [],
                                                                  'organization': [],
                                                                  'province': []
                                                            },
                                                            'subject_dn': String,
                                                            'subject_key_info': {
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
                                                                  'authority_info_access': { 'ocsp_urls': [] },
                                                                  'authority_key_id': String,
                                                                  'basic_constraints': {
                                                                        'is_ca': Boolean,
                                                                        'max_path_len': Number
                                                                  },
                                                                  'certificate_policies': [{
                                                                        'cps': [],
                                                                        'id': String
                                                                  }],
                                                                  'crl_distribution_points': [],
                                                                  'extended_key_usage': {
                                                                        'client_auth': Boolean,
                                                                        'server_auth': Boolean
                                                                  },
                                                                  'key_usage': {
                                                                        'certificate_sign': Boolean,
                                                                        'crl_sign': Boolean,
                                                                        'digital_signature': Boolean,
                                                                        'value': Number
                                                                  },
                                                                  'subject_key_id': String
                                                            },
                                                            'fingerprint_md5': String,
                                                            'fingerprint_sha1': String,
                                                            'fingerprint_sha256': String,
                                                            'issuer': {
                                                                  'common_name': [],
                                                                  'country': [],
                                                                  'organization': [],
                                                                  'organizational_unit': []
                                                            },
                                                            'issuer_dn': String,
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
                                                                  'organization': [],
                                                                  'organizational_unit': []
                                                            },
                                                            'subject_dn': String,
                                                            'subject_key_info': {
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
                              }
                        },
                        'status': String,
                        'timestamp': Date
                  },
                  'smtps': {
                        'protocol': String,
                        'result': {
                              'banner': String,
                              'tls': {
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
                                                                        'id': String
                                                                  }],
                                                                  'crl_distribution_points': [],
                                                                  'extended_key_usage': {
                                                                        'client_auth': Boolean,
                                                                        'server_auth': Boolean
                                                                  },
                                                                  'key_usage': {
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
                                                                  'email_address': [],
                                                                  'locality': [],
                                                                  'organization': [],
                                                                  'organizational_unit': []
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
                                                                  'locality': [],
                                                                  'organization': [],
                                                                  'province': []
                                                            },
                                                            'subject_dn': String,
                                                            'subject_key_info': {
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
                                                                        'id': String
                                                                  }],
                                                                  'crl_distribution_points': [],
                                                                  'extended_key_usage': {
                                                                        'client_auth': Boolean,
                                                                        'server_auth': Boolean
                                                                  },
                                                                  'key_usage': {
                                                                        'certificate_sign': Boolean,
                                                                        'crl_sign': Boolean,
                                                                        'digital_signature': Boolean,
                                                                        'value': Number
                                                                  },
                                                                  'subject_key_id': String
                                                            },
                                                            'fingerprint_md5': String,
                                                            'fingerprint_sha1': String,
                                                            'fingerprint_sha256': String,
                                                            'issuer': {
                                                                  'common_name': [],
                                                                  'country': [],
                                                                  'organization': [],
                                                                  'organizational_unit': []
                                                            },
                                                            'issuer_dn': String,
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
                                                                  'organization': [],
                                                                  'organizational_unit': []
                                                            },
                                                            'subject_dn': String,
                                                            'subject_key_info': {
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
                              }
                        },
                        'status': String,
                        'timestamp': Date
                  },
                  'ssh': {
                        'protocol': String,
                        'result': {
                              'algorithm_selection': {
                                    'client_to_server_alg_group': {
                                          'cipher': String,
                                          'compression': String,
                                          'mac': String
                                    },
                                    'dh_kex_algorithm': String,
                                    'host_key_algorithm': String,
                                    'server_to_client_alg_group': {
                                          'cipher': String,
                                          'compression': String,
                                          'mac': String
                                    }
                              },
                              'client_id': {
                                    'raw': String,
                                    'software': String,
                                    'version': String
                              },
                              'client_key_exchange': {
                                    'client_to_server_ciphers': [],
                                    'client_to_server_compression': [],
                                    'client_to_server_macs': [],
                                    'cookie': String,
                                    'first_kex_follows': Boolean,
                                    'host_key_algorithms': [],
                                    'kex_algorithms': [],
                                    'reserved': Number,
                                    'server_to_client_ciphers': [],
                                    'server_to_client_compression': [],
                                    'server_to_client_macs': []
                              },
                              'crypto': {
                                    'H': String,
                                    'K': String,
                                    'session_id': String
                              },
                              'key_exchange': {
                                    'curve25519_sha256_params': {
                                          'client_private': String,
                                          'client_public': String,
                                          'server_public': String
                                    },
                                    'dh_params': {
                                          'client_private': {
                                                'length': Number,
                                                'value': String
                                          },
                                          'client_public': {
                                                'length': Number,
                                                'value': String
                                          },
                                          'generator': {
                                                'length': Number,
                                                'value': String
                                          },
                                          'prime': {
                                                'length': Number,
                                                'value': String
                                          },
                                          'server_public': {
                                                'length': Number,
                                                'value': String
                                          }
                                    },
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
                                    'server_host_key': {
                                          'algorithm': String,
                                          'ecdsa_public_key': {
                                                'b': String,
                                                'curve': String,
                                                'gx': String,
                                                'gy': String,
                                                'length': Number,
                                                'n': String,
                                                'p': String,
                                                'x': String,
                                                'y': String
                                          },
                                          'fingerprint_sha256': String,
                                          'raw': String,
                                          'rsa_public_key': {
                                                'exponent': Number,
                                                'length': Number,
                                                'modulus': String
                                          }
                                    },
                                    'server_signature': {
                                          'h': String,
                                          'parsed': {
                                                'algorithm': String,
                                                'value': String
                                          },
                                          'raw': String
                                    }
                              },
                              'server_id': {
                                    'comment': String,
                                    'raw': String,
                                    'software': String,
                                    'version': String
                              },
                              'server_key_exchange': {
                                    'client_to_server_ciphers': [],
                                    'client_to_server_compression': [],
                                    'client_to_server_macs': [],
                                    'cookie': String,
                                    'first_kex_follows': Boolean,
                                    'host_key_algorithms': [],
                                    'kex_algorithms': [],
                                    'reserved': Number,
                                    'server_to_client_ciphers': [],
                                    'server_to_client_compression': [],
                                    'server_to_client_macs': []
                              }
                        },
                        'status': String,
                        'timestamp': Date
                  },
                  'tls': {
                        'protocol': String,
                        'result': {
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
                                                            'basic_constraints': {
                                                                  'is_ca': Boolean,
                                                                  'max_path_len': Number
                                                            },
                                                            'certificate_policies': [{
                                                                  'cps': [],
                                                                  'id': String,
                                                                  'user_notice': [{
                                                                        'explicit_text': String,
                                                                        'notice_reference': [{
                                                                              'notice_numbers': [],
                                                                              'organization': String
                                                                        }]
                                                                  }]
                                                            }],
                                                            'crl_distribution_points': [],
                                                            'extended_key_usage': {
                                                                  'client_auth': Boolean,
                                                                  'email_protection': Boolean,
                                                                  'ipsec_end_system': Boolean,
                                                                  'ipsec_tunnel': Boolean,
                                                                  'ipsec_user': Boolean,
                                                                  'netscape_server_gated_crypto': Boolean,
                                                                  'server_auth': Boolean,
                                                                  'time_stamping': Boolean,
                                                                  'unknown': []
                                                            },
                                                            'issuer_alt_name': {
                                                                  'email_addresses': [],
                                                                  'uniform_resource_identifiers': []
                                                            },
                                                            'key_usage': {
                                                                  'certificate_sign': Boolean,
                                                                  'content_commitment': Boolean,
                                                                  'crl_sign': Boolean,
                                                                  'data_encipherment': Boolean,
                                                                  'decipher_only': Boolean,
                                                                  'digital_signature': Boolean,
                                                                  'encipher_only': Boolean,
                                                                  'key_agreement': Boolean,
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
                                                                  'dns_names': [],
                                                                  'email_addresses': [],
                                                                  'ip_addresses': []
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
                                                            'postal_code': [],
                                                            'province': [],
                                                            'serial_number': []
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
                                                                  'user_notice': [{
                                                                        'explicit_text': String,
                                                                        'notice_reference': [{ 'organization': String }]
                                                                  }]
                                                            }],
                                                            'crl_distribution_points': [],
                                                            'extended_key_usage': {
                                                                  'client_auth': Boolean,
                                                                  'code_signing': Boolean,
                                                                  'email_protection': Boolean,
                                                                  'ipsec_end_system': Boolean,
                                                                  'ipsec_tunnel': Boolean,
                                                                  'ipsec_user': Boolean,
                                                                  'microsoft_ca_exchange': Boolean,
                                                                  'microsoft_server_gated_crypto': Boolean,
                                                                  'netscape_server_gated_crypto': Boolean,
                                                                  'ocsp_signing': Boolean,
                                                                  'server_auth': Boolean,
                                                                  'unknown': []
                                                            },
                                                            'key_usage': {
                                                                  'certificate_sign': Boolean,
                                                                  'content_commitment': Boolean,
                                                                  'crl_sign': Boolean,
                                                                  'data_encipherment': Boolean,
                                                                  'digital_signature': Boolean,
                                                                  'key_encipherment': Boolean,
                                                                  'value': Number
                                                            },
                                                            'name_constraints': {
                                                                  'critical': Boolean,
                                                                  'excluded_ip_addresses': [{
                                                                        'begin': String,
                                                                        'cidr': String,
                                                                        'end': String,
                                                                        'mask': String
                                                                  }],
                                                                  'permitted_directory_names': [{
                                                                        'country': [],
                                                                        'locality': [],
                                                                        'organization': [],
                                                                        'province': []
                                                                  }],
                                                                  'permitted_names': []
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
                                                            'jurisdiction_country': [],
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
                        'status': String,
                        'timestamp': Date
                  }
            },
            'domains': [],
            'ip': String,
            'timestamp': Date,
            'tracked': Boolean,
            'zones': [],
      }, { collection: 'zgrab_port_data' });

var zgrab2PortModel = mongoose.model('zgrab2PortModel', zgrab2PortSchema);

module.exports = { zgrab2PortModel: zgrab2PortModel };
