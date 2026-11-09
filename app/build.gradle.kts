import java.util.Properties

plugins {
	alias(libs.plugins.android.application)
}

android {
	namespace = "com.happwner"
	compileSdk {
		version = release(37) {
			minorApiLevel = 2
		}
	}

	defaultConfig {
		applicationId = "com.happwner"
		minSdk = 21
		targetSdk = 37
		versionCode = 6
		versionName = "1.4"
	}

	androidResources {
		localeFilters += listOf("ru", "en")
	}

	// The app switches its own language, so a bundle keeps every language in the base APK.
	bundle {
		language {
			enableSplit = false
		}
	}

	compileOptions {
		sourceCompatibility = JavaVersion.VERSION_17
		targetCompatibility = JavaVersion.VERSION_17
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
			if (signingConfigs.getByName("release").storeFile != null) {
				signingConfig = signingConfigs.getByName("release")
			}
		}
	}

	buildFeatures {
		buildConfig = true
	}

	// The screen tests run on Android's own classes under Robolectric, which reads the app's
	// resources and, on JDK 17 and later, needs the JDK modules its documentation lists opened.
	testOptions {
		unitTests {
			isIncludeAndroidResources = true
			all {
				it.jvmArgs(
					"--add-opens=java.base/java.lang=ALL-UNNAMED",
					"--add-opens=java.base/java.util=ALL-UNNAMED",
					"--add-opens=java.base/java.io=ALL-UNNAMED",
					"--add-opens=java.base/java.net=ALL-UNNAMED",
					"--add-opens=java.base/java.security=ALL-UNNAMED",
					"--add-opens=java.base/java.text=ALL-UNNAMED",
					"--add-opens=java.base/jdk.internal.access=ALL-UNNAMED",
					"--add-opens=java.desktop/java.awt.font=ALL-UNNAMED",
					"--add-opens=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED"
				)
			}
		}
	}
}

// Android's own org.json, from AOSP less its platform annotations, for the unit tests in place of
// android.jar's stubs of it; built apart, as javac refuses org.json sources beside them.
val androidJsonClasses = tasks.register<JavaCompile>("androidJsonClasses") {
	source = fileTree("src/test/aosp")
	classpath = files()
	destinationDirectory = layout.buildDirectory.dir("android-json/classes")
	options.release = 17
}
val androidJson = tasks.register<Jar>("androidJson") {
	from(androidJsonClasses)
	archiveFileName = "android-json.jar"
	destinationDirectory = layout.buildDirectory.dir("android-json")
}

dependencies {
	implementation(libs.androidx.core.ktx)
	implementation(libs.androidx.appcompat)
	implementation(libs.material)
	implementation(libs.androidx.activity)
	implementation(libs.androidx.constraintlayout)
	implementation(libs.androidx.splashscreen)
	implementation(libs.androidx.lifecycle.runtime.ktx)
	compileOnly(libs.xposed.api)
	testImplementation(libs.junit)
	testImplementation(libs.robolectric)
	testImplementation(files(androidJson))
}
