/*
 * Copyright 2021 Monotonic Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modifications copyright (C) 2024 - Vermiculus Financial Technology AB
 */
package uk.co.real_logic.artio.fixp;

import org.agrona.ErrorHandler;
import uk.co.real_logic.artio.messages.FixPProtocolType;

import java.lang.reflect.InvocationTargetException;

public final class FixPProtocolFactory
{
    public static final String EXTERNAL_FQCN_PROP = "fix.protocol.fixp.external_fqcn";

    public static boolean isAcceptorImplemented(final FixPProtocolType fixPProtocolType)
    {
        switch (fixPProtocolType)
        {
            case BINARY_ENTRYPOINT:
            case EXTERNAL:
                return true;
            case ILINK_3:
            default:
                return false;
        }
    }

    public static FixPProtocol make(
        final FixPProtocolType protocol, final ErrorHandler errorHandler)
    {
        switch (protocol)
        {
            case ILINK_3:
                return make("uk.co.real_logic.artio.ilink.Ilink3Protocol", errorHandler);

            case BINARY_ENTRYPOINT:
                return make("uk.co.real_logic.artio.binary_entrypoint.BinaryEntryPointProtocol", errorHandler);

            case EXTERNAL:
                return make(getEnvProp(EXTERNAL_FQCN_PROP, "Missing -D" + EXTERNAL_FQCN_PROP), errorHandler);

            default:
                throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
    }

    private static FixPProtocol make(final String className, final ErrorHandler errorHandler)
    {
        try
        {
            final Class<?> cls = Class.forName(className);
            return (FixPProtocol)cls.getConstructor().newInstance();
        }
        catch (final ClassNotFoundException | InstantiationException | IllegalAccessException |
            NoSuchMethodException | InvocationTargetException e)
        {
            if (errorHandler != null)
            {
                errorHandler.onError(e);
            }
            return null;
        }
    }

    /**
     * Return environment variable or system property or supplied default value
     *
     * @param propName that will be automatically converted to environment variable using propToEnv(...)
     * @param defaultValue to return if no env or prop found
     * @return value
     */
    public static String getEnvProp(final String propName, final String defaultValue)
    {
        final String env = propToEnv(propName);
        String val = System.getenv(env);
        if (null == val || val.isEmpty())
        {
            val = System.getProperty(propName, defaultValue);
        }
        return val;
    }

    /**
     * Convert a property to environment variable
     *
     * @param propName to convert
     * @return environment variable name
     */
    public static String propToEnv(final String propName)
    {
        return propName.replace('.', '_').toUpperCase();
    }
}
