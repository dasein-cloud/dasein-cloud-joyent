/**
 * Copyright (C) 2009-2015 Dell, Inc.
 * See annotations for authorship information
 *
 * ====================================================================
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
 * ====================================================================
 */

package org.dasein.cloud.joyent.storage;

import org.dasein.cloud.AbstractCapabilities;
import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;
import org.dasein.cloud.joyent.SmartDataCenter;
import org.dasein.cloud.storage.BlobStoreCapabilities;
import org.dasein.cloud.util.NamingConstraints;
import org.dasein.util.uom.storage.*;
import org.dasein.util.uom.storage.Byte;

import javax.annotation.Nonnull;
import java.util.Locale;

public class MantaCapabilities extends AbstractCapabilities<SmartDataCenter> implements BlobStoreCapabilities {
    static final  int                                       MAX_BUCKETS         = 100;
    static final  int                                       MAX_OBJECTS         = -1;
    static final Storage<org.dasein.util.uom.storage.Byte> MAX_OBJECT_SIZE     = new Storage<org.dasein.util.uom.storage.Byte>(5000000000L, Storage.BYTE);

    public MantaCapabilities(SmartDataCenter provider) {
        super(provider);
    }

    /**
     * Manta supports directories with sub-directories in /:login/stor or /:login/public.
     *
     *
     * @throws CloudException
     * @throws InternalException
     * @return
     */
    @Override
    public boolean allowsNestedBuckets() throws CloudException, InternalException {
        return true;
    }

    /**
     * Manta does not support objects on root level. However, user must specify one of two available storage folders:
     * /:login/stor or /:login/public which will be used as a root level.
     *
     * @throws CloudException
     * @throws InternalException
     * @return
     */
    @Override
    public boolean allowsRootObjects() throws CloudException, InternalException {
        return false;
    }

    /**
     * Manta allow public sharing using directory /:login/public
     *
     * @return
     * @throws CloudException
     * @throws InternalException
     */
    @Override
    public boolean allowsPublicSharing() throws CloudException, InternalException {
        return true;
    }

    @Override
    public int getMaxBuckets() throws CloudException, InternalException {
        return MAX_BUCKETS;
    }

    @Nonnull
    @Override
    public Storage<Byte> getMaxObjectSize() throws InternalException, CloudException {
        return MAX_OBJECT_SIZE;
    }

    /**
     * According to this <a href=http://apidocs.joyent.com/manta/#directories>doc</a> Manta limits objects per single
     * directory to 1,000,000.
     *
     * @return objects limit per single directory
     * @throws CloudException
     * @throws InternalException
     */
    @Override
    public int getMaxObjectsPerBucket() throws CloudException, InternalException {
        return 1000000;
    }

    @Nonnull
    @Override
    public NamingConstraints getBucketNamingConstraints() throws CloudException, InternalException {
        return NamingConstraints.getAlphaNumeric(1, 255).lowerCaseOnly().limitedToLatin1().constrainedBy(new char[]{'-', '.'});
    }

    @Nonnull
    @Override
    public NamingConstraints getObjectNamingConstraints() throws CloudException, InternalException {
        return NamingConstraints.getAlphaNumeric(1, 255).lowerCaseOnly().limitedToLatin1().constrainedBy(new char[]{'-', '.', ',', '#', '+'});
    }

    @Nonnull
    @Override
    public String getProviderTermForBucket(@Nonnull Locale locale) {
        return "directory";
    }

    @Nonnull
    @Override
    public String getProviderTermForObject(@Nonnull Locale locale) {
        return "object";
    }
}
