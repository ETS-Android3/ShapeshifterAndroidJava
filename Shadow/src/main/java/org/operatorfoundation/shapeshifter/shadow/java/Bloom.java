package org.operatorfoundation.shapeshifter.shadow.java;

import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Bloom {
    BloomFilter<byte[]> saltHistory = BloomFilter.create(Funnels.byteArrayFunnel(), 1000);

    public Boolean checkBloom(byte[] salt) {
        if (saltHistory.mightContain(salt)) {
            return true;
        } else {
            saltHistory.put(salt);
            return false;
        }
    }

    public void save(String fileName) throws IOException {
        OutputStream output = new FileOutputStream(fileName);
        saltHistory.writeTo(output);
    }

    public void load(String fileName) throws IOException {
        InputStream input = new FileInputStream(fileName);
        saltHistory = BloomFilter.readFrom(input, Funnels.byteArrayFunnel());
    }
}
