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

/**
 * This file is for defining custom error handlers
 */

/**
 * An error class for bad request parameters. This will capture the stack trace in Error.stack.
 *
 * An example usage:
 *   const custom_errors = require('../config/error');
 *   ...
 *   return Promise.reject(new custom_errors.IncorrectOrMissingRequestParameter('YourErrorMessage'));
 */
class IncorrectOrMissingRequestParameter extends Error {
    constructor(message) {
        super();
        Error.captureStackTrace(this, this.constructor);
        this.name = 'IncorrectOrMissingRequestParameter';
        this.message = message;
    }
}

module.exports = { IncorrectOrMissingRequestParameter };
