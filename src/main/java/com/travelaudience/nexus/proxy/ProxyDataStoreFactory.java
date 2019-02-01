package com.travelaudience.nexus.proxy;

import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

import java.io.File;
import java.io.IOException;

/**
 * Provides a thread-safe way to get a singleton {@link DataStoreFactory} instance
 */
class ProxyDataStoreFactory {

    private static final String CREDENTIAL_STORE_PATH = System.getenv("CREDENTIAL_STORE_PATH");

    private static final Object mutex = new Object();
    private static volatile DataStoreFactory instance;


    static DataStoreFactory getDefaultInstance() throws IOException {
        DataStoreFactory result = instance;
        if (result == null) {
            synchronized (mutex) {
                result = instance;
                if (result == null)
                    instance = result = new FileDataStoreFactory(new File(CREDENTIAL_STORE_PATH));
            }
        }

        return result;
    }

}
