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

import java.io.Serializable;

import org.bspv.lib.security.BspvSecurityConstant;
import org.springframework.util.Assert;

import lombok.Getter;
import lombok.ToString;

@ToString
public class BspvAuthError implements Serializable {

    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    @Getter
    private final String errorCode;
    @Getter
    private final String description;

    /**
     * Constructs an {@code BspvAuthenticationError} using the provided parameters.
     *
     * @param errorCode
     *            the error code
     */
    public BspvAuthError(final String errorCode) {
        this(errorCode, null);
    }

    /**
     * Constructs an {@code BspvAuthenticationError} using the provided parameters.
     *
     * @param errorCode
     *            the error code
     * @param description
     *            the error description
     */
    public BspvAuthError(final String errorCode, final String description) {
        Assert.hasText(errorCode, "errorCode cannot be empty");
        this.errorCode = errorCode;
        this.description = description;
    }

}
