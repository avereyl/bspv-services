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
/**
 *
 */
package org.bspv.lib.security.exception;

import org.bspv.lib.security.BspvSecurityConstant;

/**
 * @author BILLAUDG
 *
 */
public class BspvAuthJWTException extends BspvAuthException {

    /**
     *
     */
    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    /**
     * Constructor of the exception.
     *
     * @param error
     *            The {@link BspvAuthError} responsible for raising this exception.
     */
    public BspvAuthJWTException(final BspvAuthError error) {
        super(error);
    }

    /**
     * Constructor of the exception.
     *
     * @param error
     *            The {@link BspvAuthError} responsible for raising this exception.
     * @param cause
     *            The throwable root cause
     */
    public BspvAuthJWTException(final BspvAuthError error, final Throwable cause) {
        super(error, cause);
    }

    /**
     * Constructor of the exception.
     *
     * @param message
     *            A message for this exception.
     * @param cause
     *            The throwable root cause
     */
    public BspvAuthJWTException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor of the exception.
     *
     * @param error
     *            The {@link BspvAuthError} responsible for raising this exception.
     * @param message
     *            A message for this exception.
     */
    public BspvAuthJWTException(final BspvAuthError error, final String message) {
        super(error, message);
    }

    /**
     * Constructor of the exception.
     *
     * @param error
     *            The {@link BspvAuthError} responsible for raising this exception.
     * @param message
     *            A message for this exception.
     * @param cause
     *            The throwable root cause
     */
    public BspvAuthJWTException(final BspvAuthError error, final String message, final Throwable cause) {
        super(error, message, cause);
    }

}
