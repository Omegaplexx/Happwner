import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.happwner"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.happwner"
        minSdk = 21
        targetSdk = 36
        versionCode = 2
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    androidResources {
        localeFilters += listOf("ru", "en")
    }

    val keystorePropertiesFile = rootProject.file("local.properties")
    val keystoreProperties = Properties()
    if (keystorePropertiesFile.exists()) {
        keystoreProperties.load(keystorePropertiesFile.inputStream())
    }

    signingConfigs {
        create("release") {
            val storePath = keystoreProperties["RELEASE_STORE_FILE"]?.toString()
            if (storePath != null) {
                storeFile = file(storePath)
                storePassword = keystoreProperties["RELEASE_STORE_PASSWORD"]?.toString()
                keyAlias = keystoreProperties["RELEASE_KEY_ALIAS"]?.toString()
                keyPassword = keystoreProperties["RELEASE_KEY_PASSWORD"]?.toString()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            // Отключаем сжатие для быстрой разработки
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }
    
    buildFeatures {
        compose = false
        buildConfig = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    compileOnly("de.robv.android.xposed:api:82")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}