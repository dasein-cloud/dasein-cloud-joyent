/**
 * Copyright (C) 2009-2015 Dell, Inc
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

package org.dasein.cloud.joyent.compute;

import org.dasein.cloud.AsynchronousTask;
import org.dasein.cloud.CloudErrorType;
import org.dasein.cloud.CloudException;
import org.dasein.cloud.GeneralCloudException;
import org.dasein.cloud.InternalException;
import org.dasein.cloud.InvalidStateException;
import org.dasein.cloud.ResourceNotFoundException;
import org.dasein.cloud.compute.AbstractImageSupport;
import org.dasein.cloud.compute.Architecture;
import org.dasein.cloud.compute.ImageCapabilities;
import org.dasein.cloud.compute.ImageClass;
import org.dasein.cloud.compute.ImageCreateOptions;
import org.dasein.cloud.compute.ImageFilterOptions;
import org.dasein.cloud.compute.MachineImage;
import org.dasein.cloud.compute.MachineImageState;
import org.dasein.cloud.compute.Platform;
import org.dasein.cloud.compute.VirtualMachine;
import org.dasein.cloud.identity.ServiceAction;
import org.dasein.cloud.joyent.JoyentException;
import org.dasein.cloud.joyent.JoyentMethod;
import org.dasein.cloud.joyent.SmartDataCenter;
import org.dasein.cloud.util.APITrace;
import org.dasein.cloud.util.CacheLevel;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Dataset extends AbstractImageSupport<SmartDataCenter> {
    private static final String[] VALID_CAPTURE_OS = {
            "base",
            "base64",
            "centos-6",
            "debian-7",
            "ubuntu-certified-14.04",
            "ubuntu-certified-13.10",
            "ubuntu-certified-12.04"
    };
    private static final String OWNER_JOYENT = "--joyent--";
    private volatile transient DatasetCapabilities capabilities;

    Dataset( @Nonnull SmartDataCenter sdc ) {
        super(sdc);
    }

    @Override
    public ImageCapabilities getCapabilities() throws CloudException, InternalException {
        if( capabilities == null ) {
            capabilities = new DatasetCapabilities(getProvider());
        }
        return capabilities;
    }

    @Override
    protected MachineImage capture( @Nonnull ImageCreateOptions options, @Nullable AsynchronousTask<MachineImage> task ) throws CloudException, InternalException {
        APITrace.begin(getProvider(), "Image.capture");
        try {
            VirtualMachine vm = getProvider().getComputeServices().getVirtualMachineSupport().getVirtualMachine(options.getVirtualMachineId());
            if( vm == null ) {
                throw new ResourceNotFoundException("Virtual machine", options.getVirtualMachineId());
            }
            String originalImageId = vm.getProviderMachineImageId();
            if( originalImageId == null ) {
                throw new GeneralCloudException("Image capture is not supported for this VM, original image is unknown.", CloudErrorType.GENERAL);
            }
            MachineImage originalImage = getImage(originalImageId);
            if( !OWNER_JOYENT.equalsIgnoreCase(originalImage.getProviderOwnerId()) ) {
                throw new GeneralCloudException("Image capture is not supported for VMs launched from custom images.", CloudErrorType.GENERAL);
            }
            boolean validOs = false;
            for( String os : VALID_CAPTURE_OS ) {
                if( originalImage.getName().startsWith(os) ) {
                    validOs = true;
                    break;
                }
            }
            if( !validOs ) {
                throw new GeneralCloudException("Image capture is not supported for this VM, the OS of the original image is not supported.", CloudErrorType.GENERAL);
            }
            if( task != null ) {
                task.setStartTime(System.currentTimeMillis());
            }

            String vmID = options.getVirtualMachineId();
            String imageName = options.getName();
            String version = "1.0.0";

            if( !getCapabilities().canImage(vm.getCurrentState()) ) {
                throw new InvalidStateException("Server must be stopped before making an image - current state: " + vm.getCurrentState());
            }
            JoyentMethod method = new JoyentMethod(getProvider());
            Map<String, Object> post = new HashMap<String, Object>();

            post.put("machine", vmID);
            post.put("name", imageName);
            post.put("version", version);
            String json = method.doPostString(getProvider().getEndpoint(), "images", new JSONObject(post).toString());
            if( json == null ) {
                throw new GeneralCloudException("No image was created", CloudErrorType.GENERAL);
            }

            MachineImage img = null;
            try {
                JSONObject jsonObject = new JSONObject(json);
                if( jsonObject.has("id") ) {
                    img = getImage(jsonObject.getString("id"));
                }
            } catch( JSONException e ) {
                throw new InternalException(e);
            }
            if( img == null ) {
                throw new GeneralCloudException("No image was created", CloudErrorType.GENERAL);
            }

            if( task != null ) {
                task.completeWithResult(img);
            }
            return img;
        } finally {
            APITrace.end();
        }
    }

    @Override
    public MachineImage getImage( @Nonnull String providerImageId ) throws CloudException, InternalException {
        JoyentMethod method = new JoyentMethod(getProvider());

        try {
            String json = method.doGetJson(getProvider().getEndpoint(), "images/" + providerImageId);

            if( json == null ) {
                return null;
            }
            return toMachineImage(new JSONObject(json));
        } catch( JSONException e ) {
            throw new InternalException(e);
        }
    }

    @Override
    public boolean isImageSharedWithPublic( @Nonnull String machineImageId ) throws CloudException, InternalException {
        JoyentMethod method = new JoyentMethod(getProvider());

        try {
            String json = method.doGetJson(getProvider().getEndpoint(), "images/" + machineImageId);

            if( json != null ) {
                JSONObject jsonObject = new JSONObject(json);
                if( jsonObject.has("public") ) {
                    return jsonObject.getBoolean("public");
                }
            }

            return false;
        } catch( JSONException e ) {
            throw new InternalException(e);
        }
    }

    @Override
    public boolean isSubscribed() throws CloudException, InternalException {
        org.dasein.cloud.util.Cache<Boolean> cache = org.dasein.cloud.util.Cache.getInstance(getProvider(), "Image.isSubscribed", Boolean.class, CacheLevel.REGION_ACCOUNT);
        final Iterable<Boolean> cachedIsSubscribed = cache.get(getContext());
        if (cachedIsSubscribed != null && cachedIsSubscribed.iterator().hasNext()) {
            final Boolean isSubscribed = cachedIsSubscribed.iterator().next();
            if (isSubscribed != null) {
                return isSubscribed;
            }
        }

        JoyentMethod method = new JoyentMethod(getProvider());
        try {
            method.doGetJson(getProvider().getEndpoint(), "images");
        } catch (JoyentException e) {
            if (e.getErrorType().equals(CloudErrorType.AUTHENTICATION)) {
                cache.put(getContext(), Collections.singleton(false));
                return false;
            }
            throw e;
        }
        cache.put(getContext(), Collections.singleton(true));
        return true;
    }

    @Override
    public @Nonnull Iterable<MachineImage> listImages( @Nullable ImageFilterOptions options ) throws CloudException, InternalException {
        APITrace.begin(getProvider(), "Image.listImages");
        try {
            JoyentMethod method = new JoyentMethod(getProvider());

            try {
                JSONArray arr = new JSONArray(method.doGetJson(getProvider().getEndpoint(), "images?public=false"));
                List<MachineImage> images = new ArrayList<MachineImage>();

                for( int i = 0; i < arr.length(); i++ ) {
                    JSONObject ob = arr.getJSONObject(i);
                    MachineImage image = toMachineImage(ob);

                    if( image != null && options.matches(image) ) {
                        images.add(image);
                    }
                }
                return images;
            } catch( JSONException e ) {
                throw new InternalException(e);
            }
        } finally {
            APITrace.end();
        }
    }

    @Override
    public @Nonnull Iterable<String> listShares( @Nonnull String forMachineImageId ) throws CloudException, InternalException {
        // Joyent 7.1 doesn't support image sharing
        return Collections.emptyList();
    }

    @Override
    public @Nonnull String[] mapServiceAction( @Nonnull ServiceAction action ) {
        return new String[0];
    }

    @Override
    public void remove( @Nonnull String providerImageId, boolean checkState ) throws CloudException, InternalException {
        APITrace.begin(getProvider(), "Image.remove");
        try {
            JoyentMethod method = new JoyentMethod(getProvider());

            method.doDelete(getProvider().getEndpoint(), "images/" + providerImageId);
        } finally {
            APITrace.end();
        }
    }

    @Override
    public @Nonnull Iterable<MachineImage> searchPublicImages( @Nonnull ImageFilterOptions options ) throws CloudException, InternalException {
        JoyentMethod method = new JoyentMethod(getProvider());

        try {
            JSONArray arr = new JSONArray(method.doGetJson(getProvider().getEndpoint(), "images?public=true"));
            List<MachineImage> images = new ArrayList<MachineImage>();

            for( int i = 0; i < arr.length(); i++ ) {
                MachineImage image = toMachineImage(arr.getJSONObject(i));

                if( image != null && options.matches(image) ) {
                    image.sharedWithPublic();// mark it as public regardless, since it is
                    images.add(image);
                }
            }
            return images;
        } catch( JSONException e ) {
            throw new InternalException(e);
        }
    }

    private @Nullable MachineImage toMachineImage( @Nullable JSONObject json ) throws CloudException, InternalException {
        if( json == null ) {
            return null;
        }
        String regionId = getContext().getRegionId();

        if( regionId == null ) {
            throw new InternalException("No region ID was specified for this request");
        }
        String imageId, name, description, version, owner = OWNER_JOYENT;
        Architecture architecture = Architecture.I64;
        Platform platform = Platform.UNKNOWN;
        long created = 0L;
        Boolean isPublic = null;
        long minRamSize = 0L;
        MachineImageState state = MachineImageState.PENDING;
        try {
            if( json.has("id") ) {
                imageId = json.getString("id");
            }
            else {
                return null;
            }
            if( json.has("name") ) {
                name = json.getString("name");
            }
            else {
                name = imageId;
            }
            if( json.has("description") ) {
                description = json.getString("description");
            }
            else {
                description = name + " (" + platform + ") [#" + imageId + "]";
            }
            if( json.has("os") ) {
                String os = ( name == null ? json.getString("os") : name + " " + json.getString("os") );
                platform = Platform.guess(os);
                architecture = guessArch(os);
            }
            if( json.has("created") ) {
                created = getProvider().parseTimestamp(json.getString("created"));
            }
            if( json.has("version") ) {
                version = json.getString("version");
                name = name + ":" + version;
            }
            if( json.has("public") ) {
                isPublic = json.getBoolean("public");
                owner = isPublic ? OWNER_JOYENT : getContext().getAccountNumber();
            }
            if( json.has("requirements") ) {
                JSONObject requirements = json.getJSONObject("requirements");
                if( requirements.has("min_ram") ) {
                    minRamSize = requirements.getLong("min_ram");
                }
                else if( requirements.has("min_memory") ) {
                    minRamSize = requirements.getLong("min_memory");
                }
            }
            if( json.has("state") ) {
                if( "active".equalsIgnoreCase(json.getString("state")) ) {
                    state = MachineImageState.ACTIVE;
                }
            }
        } catch( JSONException e ) {
            throw new InternalException(e);
        }
        //old version only supported public images and did not return owner attribute
        final MachineImage machineImage = MachineImage.getInstance(
                owner, regionId, imageId, ImageClass.MACHINE, state, name, description, architecture, platform
        ).createdAt(created);

        if (isPublic != null) {
            machineImage.setTag("public", String.valueOf(isPublic));
            if( isPublic ) {
                machineImage.sharedWithPublic();
            }
        }
        if( minRamSize > 0L ) {
            machineImage.getProviderMetadata().put("min_ram", String.valueOf(minRamSize));
        }
        return machineImage;

    }

    private static boolean surroundedByDigits(String hay, String needle ) throws Exception {
        hay = " " + hay + " ";
        int index = hay.indexOf(needle);
        if( index > 0 ) {
            if( Character.isDigit(hay.charAt(index-1)) && Character.isDigit(hay.charAt(index+needle.length())) )
                return true;
            else {
                return false;
            }
        }
        throw new Exception(); // not found the needle
    }

    private static Architecture guessArch(String testString) {
        String[] needles = {"32", "386"};
        for( String needle : needles ) {
            try {
                if( !surroundedByDigits(testString, needle) ) {
                    return Architecture.I32;
                }
            } catch(Exception e) {}
        }
        return Architecture.I64;
    }
}
