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

import java.util.Optional;

import org.bspv.lib.security.BspvSecurityConstant;
import org.springframework.security.core.AuthenticationException;

public class BspvAuthException extends AuthenticationException {

    /**
     *
     */
    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    private final BspvAuthError error;

    /**
     * Constructs an {@code BspvAuthenticationException} using the provided parameters.
     *
     * @param error
     *            the {@link BspvAuthError error}
     */
    public BspvAuthException(final BspvAuthError error) {
        this(error, error.getDescription());
    }

    /**
     * Constructs an {@code BspvAuthenticationException} using the provided parameters.
     *
     * @param error
     *            the {@link BspvAuthError error}
     * @param cause
     *            the root cause
     */
    public BspvAuthException(final BspvAuthError error, final Throwable cause) {
        this(error, cause.getMessage(), cause);
    }

    /**
     * Constructs an {@code BspvAuthenticationException} using the provided parameters.
     *
     * @param message
     *            the message
     * @param cause
     *            the root cause
     */
    public BspvAuthException(final String message, final Throwable cause) {
        this(null, message, cause);
    }

    /**
     * Constructs an {@code BspvAuthenticationException} using the provided parameters.
     *
     * @param error
     *            the {@link BspvAuthError error}
     * @param message
     *            the detail message
     */
    public BspvAuthException(final BspvAuthError error, final String message) {
        super(message);
        this.error = error;
    }

    /**
     * Constructs an {@code BspvAuthenticationException} using the provided parameters.
     *
     * @param error
     *            the {@link BspvAuthError error}
     * @param message
     *            the detail message
     * @param cause
     *            the root cause
     */
    public BspvAuthException(final BspvAuthError error, final String message, final Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    /**
     * Get the error for this exception if any.
     *
     * @return The nullable {@link BspvAuthJWTError} as an {@link Optional}.
     */
    public Optional<BspvAuthError> getError() {
        return Optional.ofNullable(this.error);
    }

}
