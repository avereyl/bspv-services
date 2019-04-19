/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bspv.lib.security.exception;

import org.bspv.lib.security.BspvSecurityConstant;
import org.springframework.http.HttpStatus;

import lombok.Getter;

public class BspvAuthJWTError extends BspvAuthError {

    /**
    *
    */
    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    private static final String INVALID_TOKEN = "invalid_token";
    private static final String UNSUPPORTED_TOKEN = "unsupported_token";
    private static final String UNSUPPORTED_ALGORITHM = "unsupported_algorithm";

    @Getter
    private final HttpStatus httpStatus;

    public BspvAuthJWTError(final String errorCode, final HttpStatus httpStatus) {
        super(errorCode);
        this.httpStatus = httpStatus;
    }

    public BspvAuthJWTError(final String errorCode, final HttpStatus httpStatus, final String description) {
        super(errorCode, description);
        this.httpStatus = httpStatus;
    }

    public static BspvAuthJWTError invalidToken() {
        return new BspvAuthJWTError(INVALID_TOKEN, HttpStatus.BAD_REQUEST, "Bearer token is malformed.");
    }

    public static BspvAuthJWTError invalidToken(final String message) {
        return new BspvAuthJWTError(INVALID_TOKEN, HttpStatus.BAD_REQUEST, message);
    }

    public static BspvAuthJWTError unsupportedToken() {
        return new BspvAuthJWTError(UNSUPPORTED_TOKEN, HttpStatus.BAD_REQUEST,
                "Bearer token is not supported.");
    }

    public static BspvAuthJWTError unsupportedAlgorithm() {
        return new BspvAuthJWTError(UNSUPPORTED_ALGORITHM, HttpStatus.BAD_REQUEST,
                "Bearer token algorithm is not supported.");
    }

}
