#!/bin/bash

chmod +x gradlew

echo "
org.gradle.jvmargs=-Xmx16g -Dfile.encoding=UTF-8 -XX:+HeapDumpOnOutOfMemoryError
org.gradle.daemon=false
org.gradle.caching=true
org.gradle.configureondemand=true
org.gradle.parallel=true
android.useAndroidX=true
android.enableJetifier=true

" >> gradle.properties