plugins {
    id("com.android.application")
}

android {
    namespace = "lab.cve28650"
    compileSdk = 36

    defaultConfig {
        applicationId = "lab.cve28650"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
