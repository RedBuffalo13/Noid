# Keep the JNI surface — R8 otherwise strips the native entry points and
# every Rust→Kotlin callback dies with UnsatisfiedLinkError.
-keep class com.bst.noid.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
