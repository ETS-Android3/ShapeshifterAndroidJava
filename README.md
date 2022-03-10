# ShapeshifterAndroidKotlin

Shadowsocks is a simple, but effective and popular network traffic obfuscation tool that uses basic encryption with a shared password. shadow is a wrapper for Shadowsocks that makes it available as a Pluggable Transport.

## Setting up dependencies
1) add the following at the end of repositories in your PROJECT's build.gradle:
```
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

2) add the dependency in your MODULE's build.gradle:
```
dependencies {
        // Be sure to replace TAG with the most recent version
        implementation 'com.github.OperatorFoundation:ShapeshifterAndroidJava:TAG'

        // Later releases of bouncycastle may not work with ShapeshifterAndroidJava
        implementation 'org.bouncycastle:bcpkix-jdk15on:1.58'
        
        // 
        implementation 'com.google.guava:guava:31.0.1-android'
        implementation 'com.google.code.gson:gson:2.8.2'
}
```

3) Make sure the min SDK in your build.gradle is 21 or higher in each project/app related build.gradle

## Using the Library
1) Create the Bloom Filter
```
Bloom bloomFilter = new Bloom();
```

2) Load the Bloom Filter from the path given (include the file name)
```
bloomFilter.load(fileName);
```   

3) Create a shadow config, putting the password and cipher name. The Server's Persistent Public Key is used in place of the password.
```
ShadowConfig config = new ShadowConfig(password, cipherName);
```

4) Make a Shadow Socket with the config, the host, and the port.
```
ShadowSocket shadowSocket = new ShadowSocket(config, host, port);
```

5) Get the output stream and write some bytes.
```
shadowSocket.getOutputStream().write(someBytes);
```

6) Flush the output stream.
```
shadowSocket.getOutputStream().flush();
```

7) Get the input stream and read some bytes into an empty buffer.
```
shadowSocket.getInputStream().read(emptyBuffer);
```

8) Save the Bloom Filter to the path given at the end of the session (include file name)
```
bloomFilter.save(fileName)
```